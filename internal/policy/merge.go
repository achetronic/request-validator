package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	yamlv3 "gopkg.in/yaml.v3"

	"request-validator/internal/celenv"
	"request-validator/internal/crdt"
	"request-validator/internal/facts"
)

// MergeError carries the offending CRDT key (when applicable) so the
// quarantine layer can route it back to the buffer.
type MergeError struct {
	Section string
	Key     string
	Err     error
}

func (e *MergeError) Error() string {
	if e.Key == "" {
		return fmt.Sprintf("%s: %v", e.Section, e.Err)
	}
	return fmt.Sprintf("%s/%s: %v", e.Section, e.Key, e.Err)
}

func (e *MergeError) Unwrap() error { return e.Err }

// MergeFromYAML parses the YAML once and overlays the CRDT state on
// top of it, returning a freshly compiled effective *Config.
func MergeFromYAML(yamlBytes []byte, state crdt.FullState) (*Config, error) {
	base := &Config{}
	if len(yamlBytes) > 0 {
		if err := yamlv3.Unmarshal(yamlBytes, base); err != nil {
			return nil, fmt.Errorf("yaml: %w", err)
		}
	}
	return Merge(base, state)
}

// Merge produces a compiled effective *Config by overlaying CRDT state
// on top of the parsed YAML. The YAML is the floor; CRDT entries
// (live or tombstoned) override per-key. Defaults and logging are
// merged per-field.
//
// `yamlCfg` must be a freshly parsed YAML view of the policy, with no
// compiled state attached. The function will run applyDefaults,
// sortGroups, validate and compile on the merged result. Use
// MergeFromYAML if you have only raw bytes.
func Merge(yamlCfg *Config, state crdt.FullState) (*Config, error) {
	if yamlCfg == nil {
		return nil, errors.New("policy: nil yaml config")
	}
	merged := &Config{
		Defaults: yamlCfg.Defaults,
		Logging:  yamlCfg.Logging,
		Facts:    append([]facts.Spec(nil), yamlCfg.Facts...),
		Groups:   append([]Group(nil), yamlCfg.Groups...),
	}

	if err := mergeGroups(merged, state.Groups); err != nil {
		return nil, err
	}
	if err := mergeFacts(merged, state.Facts); err != nil {
		return nil, err
	}
	if state.Defaults != nil && state.Defaults.Set && !state.Defaults.Entry.Cleared {
		if err := overlayDefaults(&merged.Defaults, state.Defaults.Entry.Payload); err != nil {
			return nil, &MergeError{Section: crdt.SectionDefaults, Err: err}
		}
	}
	if state.Logging != nil && state.Logging.Set && !state.Logging.Entry.Cleared {
		if err := overlayLogging(&merged.Logging, state.Logging.Entry.Payload); err != nil {
			return nil, &MergeError{Section: crdt.SectionLogging, Err: err}
		}
	}

	applyDefaults(merged)
	sortGroups(merged)
	if err := merged.validate(); err != nil {
		return nil, err
	}
	env, err := celenv.New()
	if err != nil {
		return nil, err
	}
	merged.env = env
	reg, err := facts.New(merged.Facts)
	if err != nil {
		return nil, fmt.Errorf("facts: %w", err)
	}
	merged.registry = reg
	if err := merged.compile(); err != nil {
		return nil, err
	}
	return merged, nil
}

// mergeGroups overlays CRDT-managed group entries on top of the YAML
// groups already copied into merged.Groups.
func mergeGroups(merged *Config, entries map[string]crdt.MapEntry) error {
	if len(entries) == 0 {
		return nil
	}
	yamlIdx := make(map[string]int, len(merged.Groups))
	for i, g := range merged.Groups {
		yamlIdx[g.Name] = i
	}

	// Decode every live API group, sorted by name for determinism among
	// equal-priority entries.
	keys := make([]string, 0, len(entries))
	for k := range entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	apiGroups := make([]Group, 0)
	apiIndex := 0
	for _, name := range keys {
		entry := entries[name]
		if entry.Tombstone {
			if idx, ok := yamlIdx[name]; ok {
				merged.Groups[idx] = Group{Name: "", Source: "__deleted"}
			}
			continue
		}
		var g Group
		if err := decodeYAMLViaJSON(entry.Payload, &g); err != nil {
			return &MergeError{Section: crdt.SectionGroups, Key: name, Err: err}
		}
		if g.Name == "" {
			g.Name = name
		}
		if g.Name != name {
			return &MergeError{
				Section: crdt.SectionGroups,
				Key:     name,
				Err:     fmt.Errorf("payload name %q does not match key", g.Name),
			}
		}
		g.Source = SourceAPI
		g.declarationIndex = apiIndex
		apiIndex++
		if idx, ok := yamlIdx[name]; ok {
			// Replace YAML occurrence inline so the YAML declarationIndex
			// is reused (preserves tie order even though Source differs).
			yamlAt := merged.Groups[idx]
			g.declarationIndex = yamlAt.declarationIndex
			merged.Groups[idx] = g
			continue
		}
		apiGroups = append(apiGroups, g)
	}

	// Compact tombstoned slots and append the new API-only groups.
	out := merged.Groups[:0]
	for _, g := range merged.Groups {
		if g.Source == "__deleted" {
			continue
		}
		out = append(out, g)
	}
	out = append(out, apiGroups...)
	merged.Groups = out
	return nil
}

// mergeFacts overlays CRDT-managed fact entries on top of the YAML facts.
func mergeFacts(merged *Config, entries map[string]crdt.MapEntry) error {
	if len(entries) == 0 {
		return nil
	}
	yamlIdx := make(map[string]int, len(merged.Facts))
	for i, f := range merged.Facts {
		yamlIdx[f.Name] = i
	}
	keys := make([]string, 0, len(entries))
	for k := range entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	apiFacts := make([]facts.Spec, 0)
	for _, name := range keys {
		entry := entries[name]
		if entry.Tombstone {
			if idx, ok := yamlIdx[name]; ok {
				merged.Facts[idx] = facts.Spec{Name: "__deleted"}
			}
			continue
		}
		var f facts.Spec
		if err := decodeYAMLViaJSON(entry.Payload, &f); err != nil {
			return &MergeError{Section: crdt.SectionFacts, Key: name, Err: err}
		}
		if f.Name == "" {
			f.Name = name
		}
		if f.Name != name {
			return &MergeError{
				Section: crdt.SectionFacts,
				Key:     name,
				Err:     fmt.Errorf("payload name %q does not match key", f.Name),
			}
		}
		if idx, ok := yamlIdx[name]; ok {
			merged.Facts[idx] = f
			continue
		}
		apiFacts = append(apiFacts, f)
	}

	out := merged.Facts[:0]
	for _, f := range merged.Facts {
		if f.Name == "__deleted" {
			continue
		}
		out = append(out, f)
	}
	out = append(out, apiFacts...)
	merged.Facts = out
	return nil
}

// overlayDefaults parses payload as a Defaults struct and overlays any
// non-zero fields onto target. Zero fields are treated as "not set"
// and inherit from the YAML value.
func overlayDefaults(target *Defaults, payload json.RawMessage) error {
	if len(payload) == 0 || bytes.Equal(payload, []byte("null")) {
		return nil
	}
	// Decode into a wire-shape struct keyed by the YAML tags so the
	// JSON sent by the admin API matches the YAML schema verbatim.
	var d Defaults
	if err := decodeYAMLViaJSON(payload, &d); err != nil {
		return err
	}
	// Per-field overlay: keep target zero values when the API didn't
	// provide that key. We detect "provided" by also decoding the
	// payload into a map and checking key presence.
	keys, err := jsonKeys(payload)
	if err != nil {
		return err
	}
	if _, ok := keys["action"]; ok {
		target.Action = d.Action
	}
	if _, ok := keys["denyStatus"]; ok {
		target.DenyStatus = d.DenyStatus
	}
	if _, ok := keys["denyBody"]; ok {
		target.DenyBody = d.DenyBody
	}
	if _, ok := keys["maxBodyBytes"]; ok {
		target.MaxBodyBytes = d.MaxBodyBytes
	}
	if _, ok := keys["allowOnError"]; ok {
		target.AllowOnError = d.AllowOnError
	}
	return nil
}

// overlayLogging applies the same shape of overlay as overlayDefaults
// for the Logging block.
func overlayLogging(target *Logging, payload json.RawMessage) error {
	if len(payload) == 0 || bytes.Equal(payload, []byte("null")) {
		return nil
	}
	var l Logging
	if err := decodeYAMLViaJSON(payload, &l); err != nil {
		return err
	}
	keys, err := jsonKeys(payload)
	if err != nil {
		return err
	}
	if _, ok := keys["level"]; ok {
		target.Level = l.Level
	}
	if _, ok := keys["format"]; ok {
		target.Format = l.Format
	}
	if _, ok := keys["logBody"]; ok {
		target.LogBody = l.LogBody
	}
	if _, ok := keys["excludeHeaders"]; ok {
		target.ExcludeHeaders = l.ExcludeHeaders
	}
	if _, ok := keys["redactHeaders"]; ok {
		target.RedactHeaders = l.RedactHeaders
	}
	if _, ok := keys["redactReveal"]; ok {
		target.RedactReveal = l.RedactReveal
	}
	if _, ok := keys["redactQueryParams"]; ok {
		target.RedactQueryParams = l.RedactQueryParams
	}
	return nil
}

func jsonKeys(payload json.RawMessage) (map[string]struct{}, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, fmt.Errorf("payload must be a JSON object: %w", err)
	}
	out := make(map[string]struct{}, len(raw))
	for k := range raw {
		out[k] = struct{}{}
	}
	return out, nil
}

// decodeYAMLViaJSON unmarshals a JSON payload into a struct whose
// YAML tags drive the field mapping. We route JSON through YAML so
// the API consumes the exact same shape an operator would write
// inside the policy file.
func decodeYAMLViaJSON(payload []byte, dst any) error {
	if len(payload) == 0 {
		return errors.New("empty payload")
	}
	// Convert JSON to a generic value, re-emit as YAML, then YAML
	// unmarshal into the destination. This keeps a single source of
	// truth (YAML tags on the structs).
	var anyVal any
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	if err := dec.Decode(&anyVal); err != nil {
		return fmt.Errorf("json: %w", err)
	}
	anyVal = jsonNumberToYAML(anyVal)
	yb, err := yamlv3.Marshal(anyVal)
	if err != nil {
		return fmt.Errorf("yaml re-emit: %w", err)
	}
	if err := yamlv3.Unmarshal(yb, dst); err != nil {
		return fmt.Errorf("yaml unmarshal: %w", err)
	}
	return nil
}

// jsonNumberToYAML rewrites json.Number leaves into int64/float64 so
// the subsequent YAML round-trip produces plain numeric scalars (and
// custom YAML unmarshalers like BytesSize see the original form).
func jsonNumberToYAML(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, vv := range x {
			x[k] = jsonNumberToYAML(vv)
		}
		return x
	case []any:
		for i, vv := range x {
			x[i] = jsonNumberToYAML(vv)
		}
		return x
	case json.Number:
		if i, err := x.Int64(); err == nil {
			return i
		}
		if f, err := x.Float64(); err == nil {
			return f
		}
		return x.String()
	}
	return v
}
