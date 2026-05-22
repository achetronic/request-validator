package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	yamlv3 "gopkg.in/yaml.v3"

	"request-validator/internal/celenv"
	"request-validator/internal/facts"
	"request-validator/internal/state"
)

// MergeError carries the offending overlay key (when applicable) so
// the admin API can route it back to the client as a 400 with a
// useful message.
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

// MergeFromYAML parses the YAML once and overlays the state snapshot
// on top of it, returning a freshly compiled effective *Config.
func MergeFromYAML(yamlBytes []byte, snap state.Snapshot) (*Config, error) {
	base := &Config{}
	if len(yamlBytes) > 0 {
		if err := yamlv3.Unmarshal(yamlBytes, base); err != nil {
			return nil, fmt.Errorf("yaml: %w", err)
		}
	}
	return Merge(base, snap)
}

// Merge produces a compiled effective *Config by overlaying a state
// snapshot on top of the parsed YAML. The YAML is the floor; state
// entries override per-key. Defaults and logging are merged per-field.
//
// `yamlCfg` must be a freshly parsed YAML view of the policy, with no
// compiled state attached. The function runs applyDefaults,
// sortGroups, validate and compile on the merged result. Use
// MergeFromYAML if you have only raw bytes.
func Merge(yamlCfg *Config, snap state.Snapshot) (*Config, error) {
	if yamlCfg == nil {
		return nil, errors.New("policy: nil yaml config")
	}
	merged := &Config{
		Defaults: yamlCfg.Defaults,
		Logging:  yamlCfg.Logging,
		Facts:    append([]facts.Spec(nil), yamlCfg.Facts...),
		Groups:   append([]Group(nil), yamlCfg.Groups...),
	}

	if err := mergeGroups(merged, snap.Groups); err != nil {
		return nil, err
	}
	if err := mergeFacts(merged, snap.Facts); err != nil {
		return nil, err
	}
	if len(snap.Defaults) > 0 {
		if err := overlayDefaults(&merged.Defaults, snap.Defaults); err != nil {
			return nil, &MergeError{Section: state.SectionDefaults, Err: err}
		}
	}
	if len(snap.Logging) > 0 {
		if err := overlayLogging(&merged.Logging, snap.Logging); err != nil {
			return nil, &MergeError{Section: state.SectionLogging, Err: err}
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

// mergeGroups overlays state-managed group entries on top of the YAML
// groups already copied into merged.Groups.
func mergeGroups(merged *Config, entries map[string]json.RawMessage) error {
	if len(entries) == 0 {
		return nil
	}
	yamlIdx := make(map[string]int, len(merged.Groups))
	for i, g := range merged.Groups {
		yamlIdx[g.Name] = i
	}

	keys := make([]string, 0, len(entries))
	for k := range entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	apiGroups := make([]Group, 0)
	apiIndex := 0
	for _, name := range keys {
		payload := entries[name]
		if len(payload) == 0 {
			continue
		}
		var g Group
		if err := decodeYAMLViaJSON(payload, &g); err != nil {
			return &MergeError{Section: state.SectionGroups, Key: name, Err: err}
		}
		if g.Name == "" {
			g.Name = name
		}
		if g.Name != name {
			return &MergeError{
				Section: state.SectionGroups,
				Key:     name,
				Err:     fmt.Errorf("payload name %q does not match key", g.Name),
			}
		}
		g.Source = SourceAPI
		g.declarationIndex = apiIndex
		apiIndex++
		if idx, ok := yamlIdx[name]; ok {
			yamlAt := merged.Groups[idx]
			g.declarationIndex = yamlAt.declarationIndex
			merged.Groups[idx] = g
			continue
		}
		apiGroups = append(apiGroups, g)
	}
	merged.Groups = append(merged.Groups, apiGroups...)
	return nil
}

// mergeFacts overlays state-managed fact entries on top of the YAML
// facts.
func mergeFacts(merged *Config, entries map[string]json.RawMessage) error {
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
		payload := entries[name]
		if len(payload) == 0 {
			continue
		}
		var f facts.Spec
		if err := decodeYAMLViaJSON(payload, &f); err != nil {
			return &MergeError{Section: state.SectionFacts, Key: name, Err: err}
		}
		if f.Name == "" {
			f.Name = name
		}
		if f.Name != name {
			return &MergeError{
				Section: state.SectionFacts,
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
	merged.Facts = append(merged.Facts, apiFacts...)
	return nil
}

// overlayDefaults parses payload and overlays the present fields onto
// target. Missing fields keep their YAML value.
func overlayDefaults(target *Defaults, payload json.RawMessage) error {
	if len(payload) == 0 || bytes.Equal(payload, []byte("null")) {
		return nil
	}
	var d Defaults
	if err := decodeYAMLViaJSON(payload, &d); err != nil {
		return err
	}
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
