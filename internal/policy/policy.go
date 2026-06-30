// SPDX-FileCopyrightText: 2026 Alby Hernández <hola@achetronic.com>
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/google/cel-go/cel"
	yamlv3 "gopkg.in/yaml.v3"

	"request-validator/internal/celenv"
	"request-validator/internal/facts"
)

// Config is the top-level configuration loaded from YAML.
type Config struct {
	Defaults Defaults     `yaml:"defaults"`
	Logging  Logging      `yaml:"logging"`
	Facts    []facts.Spec `yaml:"facts"`
	Groups   []Group      `yaml:"groups"`
	env      *celenv.Env
	registry *facts.Registry
}

// Defaults are server-wide knobs split per-engine.
type Defaults struct {
	ExtAuthz ExtAuthzDefaults `yaml:"extAuthz"`
	ExtProc  ExtProcDefaults  `yaml:"extProc"`
	DryRun   bool             `yaml:"dryRun"`
}

// ExtAuthzDefaults configures the HTTP ext-authz engine defaults.
type ExtAuthzDefaults struct {
	Action       string    `yaml:"action"`
	DenyStatus   int       `yaml:"denyStatus"`
	DenyBody     string    `yaml:"denyBody"`
	AllowOnError bool      `yaml:"allowOnError"`
	MaxBodyBytes BytesSize `yaml:"maxBodyBytes"`
}

// ExtProcDefaults configures the gRPC ext_proc engine defaults.
type ExtProcDefaults struct {
	MaxBodyBytes   BytesSize `yaml:"maxBodyBytes"`
	OnBodyOverflow string    `yaml:"onBodyOverflow"`
}

// Logging configures the access-log enrichment applied to every request.
type Logging struct {
	Level             string   `yaml:"level"`
	Format            string   `yaml:"format"`
	LogBody           bool     `yaml:"logBody"`
	ExcludeHeaders    []string `yaml:"excludeHeaders"`
	RedactHeaders     []string `yaml:"redactHeaders"`
	RedactReveal      int      `yaml:"redactReveal"`
	RedactQueryParams []string `yaml:"redactQueryParams"`
}

// Group is a named collection of rules bound to an engine with parameters.
type Group struct {
	Name        string     `yaml:"name"`
	Description string     `yaml:"description"`
	Parameters  Parameters `yaml:"parameters"`
	Match       string     `yaml:"match"`
	Rules       []Rule     `yaml:"rules"`
	matchProg   cel.Program
}

// Parameters defines engine-specific wiring and modes.
type Parameters struct {
	Engine string `yaml:"engine"`
	Mode   string `yaml:"mode"`
	Phase  string `yaml:"phase"`
}

// Rule is one conditional entry in a group.
type Rule struct {
	Name        string      `yaml:"name"`
	Description string      `yaml:"description"`
	Match       string      `yaml:"match"`
	Validation  *Validation `yaml:"validation"`
	Mutations   []Mutation  `yaml:"mutations"`
	DryRun      bool        `yaml:"dryRun"`
	matchProg   cel.Program
}

// Validation defines the verdict action on a successful rule match.
type Validation struct {
	Action string `yaml:"action"`
}

// Mutation defines header, body or status transformations for ext_proc.
type Mutation struct {
	Op          string `yaml:"op"`
	Name        string `yaml:"name"`
	Value       string `yaml:"value"`
	Code        string `yaml:"code"`
	Status      int    `yaml:"status"`  // directResponse: status literal
	Headers     string `yaml:"headers"` // directResponse: CEL expression -> map<string,string>
	Body        string `yaml:"body"`    // directResponse: CEL expression -> string
	valueProg   cel.Program
	codeProg    cel.Program
	headersProg cel.Program
	bodyProg    cel.Program
}

// Decision is the HTTP ext-authz evaluator output.
type Decision struct {
	Allowed bool
	Rule    string
	Reason  string
	DryRun  bool
}

// Request is the normalised view of the incoming HTTP request.
type Request struct {
	Method   string
	Scheme   string
	Host     string
	Path     string
	RawQuery string
	RemoteIP string
	Headers  http.Header
	Body     []byte
}

// Response is the normalised view of the upstream HTTP response.
type Response struct {
	Status  int
	Headers http.Header
	Body    []byte
}

// LoadFile reads, parses, validates and compiles a policy file.
func LoadFile(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw = []byte(os.ExpandEnv(string(raw)))
	return LoadBytes(raw)
}

// LoadBytes is LoadFile from already-read bytes.
func LoadBytes(b []byte) (*Config, error) {
	c := &Config{}
	if err := yamlv3.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("yaml: %w", err)
	}
	applyDefaults(c)
	if err := c.validate(); err != nil {
		return nil, err
	}
	env, err := celenv.New()
	if err != nil {
		return nil, err
	}
	c.env = env
	reg, err := facts.New(c.Facts)
	if err != nil {
		return nil, fmt.Errorf("facts: %w", err)
	}
	c.registry = reg
	if err := c.compile(); err != nil {
		return nil, err
	}
	return c, nil
}

// Start activates the facts registry.
func (c *Config) Start(ctx context.Context) error {
	if c.registry == nil {
		return nil
	}
	return c.registry.Start(ctx)
}

// Stop cancels the facts registry background tasks.
func (c *Config) Stop() {
	if c.registry == nil {
		return
	}
	c.registry.Stop()
}

// applyDefaults populates missing config fields with default values.
func applyDefaults(c *Config) {
	if c.Defaults.ExtAuthz.Action == "" {
		c.Defaults.ExtAuthz.Action = "deny"
	}
	if c.Defaults.ExtAuthz.DenyStatus == 0 {
		c.Defaults.ExtAuthz.DenyStatus = 403
	}
	if c.Defaults.ExtAuthz.DenyBody == "" {
		c.Defaults.ExtAuthz.DenyBody = "Forbidden"
	}
	if c.Defaults.ExtAuthz.MaxBodyBytes == 0 {
		c.Defaults.ExtAuthz.MaxBodyBytes = 1 << 20
	}
	if c.Defaults.ExtProc.MaxBodyBytes == 0 {
		c.Defaults.ExtProc.MaxBodyBytes = 1 << 20
	}
	if c.Defaults.ExtProc.OnBodyOverflow == "" {
		c.Defaults.ExtProc.OnBodyOverflow = "fail"
	}
	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	if c.Logging.Format == "" {
		c.Logging.Format = "json"
	}
	if c.Logging.ExcludeHeaders == nil {
		c.Logging.ExcludeHeaders = []string{"cookie", "set-cookie"}
	}
	if c.Logging.RedactHeaders == nil {
		c.Logging.RedactHeaders = []string{
			"authorization",
			"proxy-authorization",
			"x-api-key",
			"x-auth-token",
		}
	}
	if c.Logging.RedactReveal == 0 {
		c.Logging.RedactReveal = 6
	}
	if c.Logging.RedactQueryParams == nil {
		c.Logging.RedactQueryParams = []string{"access_token", "id_token", "code"}
	}
}

// validate ensures structural correctness of groups and mutations.
func (c *Config) validate() error {
	if c.Defaults.ExtAuthz.Action != "allow" && c.Defaults.ExtAuthz.Action != "deny" {
		return fmt.Errorf("defaults.extAuthz.action must be allow|deny, got %q", c.Defaults.ExtAuthz.Action)
	}
	if c.Defaults.ExtProc.OnBodyOverflow != "skip" && c.Defaults.ExtProc.OnBodyOverflow != "fail" {
		return fmt.Errorf("defaults.extProc.onBodyOverflow must be skip|fail, got %q", c.Defaults.ExtProc.OnBodyOverflow)
	}

	if len(c.Groups) == 0 {
		return fmt.Errorf("policy must contain at least one group")
	}

	seenGroups := make(map[string]bool)

	for gi, g := range c.Groups {
		if g.Name == "" {
			return fmt.Errorf("group at index %d is missing 'name'", gi)
		}
		if seenGroups[g.Name] {
			return fmt.Errorf("duplicate group name %q", g.Name)
		}
		seenGroups[g.Name] = true

		if g.Parameters.Engine != "extAuthz" && g.Parameters.Engine != "extProc" {
			return fmt.Errorf("group %q: parameters.engine must be extAuthz|extProc, got %q", g.Name, g.Parameters.Engine)
		}

		if g.Parameters.Engine == "extAuthz" {
			if g.Parameters.Mode != "firstMatch" && g.Parameters.Mode != "matchAll" {
				return fmt.Errorf("group %q (extAuthz): parameters.mode must be firstMatch|matchAll, got %q", g.Name, g.Parameters.Mode)
			}
		} else {
			if g.Parameters.Mode != "firstMatch" && g.Parameters.Mode != "applyAll" {
				return fmt.Errorf("group %q (extProc): parameters.mode must be firstMatch|applyAll, got %q", g.Name, g.Parameters.Mode)
			}
		}

		if g.Parameters.Engine == "extProc" {
			phase := g.Parameters.Phase
			if phase != "requestHeaders" && phase != "requestBody" && phase != "responseHeaders" && phase != "responseBody" {
				return fmt.Errorf("group %q (extProc): parameters.phase must be requestHeaders|requestBody|responseHeaders|responseBody, got %q", g.Name, phase)
			}
		} else {
			if g.Parameters.Phase != "" {
				return fmt.Errorf("group %q (extAuthz): parameters.phase is forbidden, got %q", g.Name, g.Parameters.Phase)
			}
		}

		if len(g.Rules) == 0 {
			return fmt.Errorf("group %q: must contain at least one rule", g.Name)
		}

		seenRules := make(map[string]bool)
		for ri, r := range g.Rules {
			if r.Name == "" {
				return fmt.Errorf("group %q rule at index %d is missing 'name'", g.Name, ri)
			}
			if seenRules[r.Name] {
				return fmt.Errorf("group %q: duplicate rule name %q", g.Name, r.Name)
			}
			seenRules[r.Name] = true

			if strings.TrimSpace(r.Match) == "" {
				return fmt.Errorf("rule %q/%q: match expression is mandatory and cannot be empty", g.Name, r.Name)
			}

			if g.Parameters.Engine == "extAuthz" {
				if r.Validation == nil {
					return fmt.Errorf("rule %q/%q (extAuthz): validation block is mandatory", g.Name, r.Name)
				}
				if len(r.Mutations) > 0 {
					return fmt.Errorf("rule %q/%q (extAuthz): mutations are forbidden", g.Name, r.Name)
				}
				action := r.Validation.Action
				if action != "allow" && action != "deny" {
					return fmt.Errorf("rule %q/%q (extAuthz): validation.action must be allow|deny, got %q", g.Name, r.Name, action)
				}
				if g.Parameters.Mode == "matchAll" && action != "allow" {
					return fmt.Errorf("rule %q/%q (extAuthz under matchAll): validation.action must be allow, got %q", g.Name, r.Name, action)
				}

			} else {
				if r.Validation != nil {
					return fmt.Errorf("rule %q/%q (extProc): validation block is forbidden", g.Name, r.Name)
				}
				hasDirect := false
				for _, m := range r.Mutations {
					if m.Op == "directResponse" {
						hasDirect = true
					}
				}
				if hasDirect && len(r.Mutations) > 1 {
					return fmt.Errorf("rule %q/%q: directResponse must be the only mutation in the rule", g.Name, r.Name)
				}
				for mi, m := range r.Mutations {
					switch m.Op {
					case "directResponse":
						if m.Status <= 0 || m.Status > 599 {
							return fmt.Errorf("rule %q/%q mutation[%d] (%s): status is required, must be a valid HTTP code (got %d)", g.Name, r.Name, mi, m.Op, m.Status)
						}
						if strings.TrimSpace(m.Headers) == "" {
							return fmt.Errorf("rule %q/%q mutation[%d] (%s): headers is required and cannot be empty", g.Name, r.Name, mi, m.Op)
						}
						if strings.TrimSpace(m.Body) == "" {
							return fmt.Errorf("rule %q/%q mutation[%d] (%s): body is required and cannot be empty", g.Name, r.Name, mi, m.Op)
						}
						if m.Name != "" {
							return fmt.Errorf("rule %q/%q mutation[%d] (%s): name must be empty", g.Name, r.Name, mi, m.Op)
						}
						if m.Value != "" {
							return fmt.Errorf("rule %q/%q mutation[%d] (%s): value must be empty", g.Name, r.Name, mi, m.Op)
						}
						if m.Code != "" {
							return fmt.Errorf("rule %q/%q mutation[%d] (%s): code must be empty", g.Name, r.Name, mi, m.Op)
						}
						phase := g.Parameters.Phase
						if phase != "responseHeaders" && phase != "responseBody" {
							return fmt.Errorf("rule %q/%q mutation[%d] (%s): directResponse is only legal in responseHeaders|responseBody phases, got %q", g.Name, r.Name, mi, m.Op, phase)
						}
					case "setHeader", "appendHeader":
						if strings.TrimSpace(m.Name) == "" {
							return fmt.Errorf("rule %q/%q mutation[%d] (%s): name is required and cannot be empty", g.Name, r.Name, mi, m.Op)
						}
						if strings.TrimSpace(m.Value) == "" {
							return fmt.Errorf("rule %q/%q mutation[%d] (%s): value is required and cannot be empty", g.Name, r.Name, mi, m.Op)
						}
						if m.Code != "" {
							return fmt.Errorf("rule %q/%q mutation[%d] (%s): code must be empty", g.Name, r.Name, mi, m.Op)
						}
					case "removeHeader":
						if strings.TrimSpace(m.Name) == "" {
							return fmt.Errorf("rule %q/%q mutation[%d] (%s): name is required and cannot be empty", g.Name, r.Name, mi, m.Op)
						}
						if m.Value != "" {
							return fmt.Errorf("rule %q/%q mutation[%d] (%s): value must be empty", g.Name, r.Name, mi, m.Op)
						}
						if m.Code != "" {
							return fmt.Errorf("rule %q/%q mutation[%d] (%s): code must be empty", g.Name, r.Name, mi, m.Op)
						}
					case "setBody":
						if strings.TrimSpace(m.Value) == "" {
							return fmt.Errorf("rule %q/%q mutation[%d] (%s): value is required and cannot be empty", g.Name, r.Name, mi, m.Op)
						}
						if m.Name != "" {
							return fmt.Errorf("rule %q/%q mutation[%d] (%s): name must be empty", g.Name, r.Name, mi, m.Op)
						}
						if m.Code != "" {
							return fmt.Errorf("rule %q/%q mutation[%d] (%s): code must be empty", g.Name, r.Name, mi, m.Op)
						}
						phase := g.Parameters.Phase
						if phase != "requestBody" && phase != "responseBody" {
							return fmt.Errorf("rule %q/%q mutation[%d] (%s): setBody is only legal in requestBody|responseBody phases, got %q", g.Name, r.Name, mi, m.Op, phase)
						}
					case "setStatus":
						if strings.TrimSpace(m.Code) == "" {
							return fmt.Errorf("rule %q/%q mutation[%d] (%s): code is required and cannot be empty", g.Name, r.Name, mi, m.Op)
						}
						if m.Name != "" {
							return fmt.Errorf("rule %q/%q mutation[%d] (%s): name must be empty", g.Name, r.Name, mi, m.Op)
						}
						if m.Value != "" {
							return fmt.Errorf("rule %q/%q mutation[%d] (%s): value must be empty", g.Name, r.Name, mi, m.Op)
						}
						phase := g.Parameters.Phase
						if phase != "responseHeaders" && phase != "responseBody" {
							return fmt.Errorf("rule %q/%q mutation[%d] (%s): setStatus is only legal in responseHeaders|responseBody phases, got %q", g.Name, r.Name, mi, m.Op, phase)
						}
					default:
						return fmt.Errorf("rule %q/%q mutation[%d]: unknown op %q", g.Name, r.Name, mi, m.Op)
					}
				}
			}
		}
	}
	return nil
}

// compile compiles all CEL expressions inside groups with proper scopes.
func (c *Config) compile() error {
	for gi := range c.Groups {
		g := &c.Groups[gi]

		var scope celenv.Scope
		if g.Parameters.Engine == "extAuthz" {
			scope = celenv.ScopeRequest
		} else {
			switch g.Parameters.Phase {
			case "requestHeaders", "requestBody":
				scope = celenv.ScopeRequest
			case "responseHeaders", "responseBody":
				scope = celenv.ScopeResponse
			}
		}

		if strings.TrimSpace(g.Match) != "" {
			p, err := c.env.Compile(g.Match, scope)
			if err != nil {
				return fmt.Errorf("group %q match: %w", g.Name, err)
			}
			g.matchProg = p
		}

		for ri := range g.Rules {
			r := &g.Rules[ri]
			p, err := c.env.Compile(r.Match, scope)
			if err != nil {
				return fmt.Errorf("rule %q/%q match: %w", g.Name, r.Name, err)
			}
			r.matchProg = p

			for mi := range r.Mutations {
				m := &r.Mutations[mi]
				switch m.Op {
				case "directResponse":
					hp, err := c.env.CompileStringMap(m.Headers, scope)
					if err != nil {
						return fmt.Errorf("rule %q/%q mutation %d headers (%s): %w", g.Name, r.Name, mi, m.Op, err)
					}
					m.headersProg = hp
					bp, err := c.env.CompileString(m.Body, scope)
					if err != nil {
						return fmt.Errorf("rule %q/%q mutation %d body (%s): %w", g.Name, r.Name, mi, m.Op, err)
					}
					m.bodyProg = bp
				case "setHeader", "appendHeader", "setBody":
					vp, err := c.env.CompileString(m.Value, scope)
					if err != nil {
						return fmt.Errorf("rule %q/%q mutation %d value (%s): %w", g.Name, r.Name, mi, m.Op, err)
					}
					m.valueProg = vp
				case "setStatus":
					cp, err := c.env.CompileInt(m.Code, scope)
					if err != nil {
						return fmt.Errorf("rule %q/%q mutation %d code (%s): %w", g.Name, r.Name, mi, m.Op, err)
					}
					m.codeProg = cp
				}
			}
		}
	}
	return nil
}

// Evaluate runs the ext-authz policy against a request.
func (c *Config) Evaluate(ctx context.Context, r *Request) Decision {
	requestVar := buildRequestVar(r)
	factsVar := c.snapshot()
	for gi := range c.Groups {
		g := &c.Groups[gi]
		if g.Parameters.Engine != "extAuthz" {
			continue
		}
		if d, decided := c.evalGroup(ctx, g, requestVar, factsVar); decided {
			return d
		}
	}
	return Decision{
		Allowed: c.Defaults.ExtAuthz.Action == "allow",
		Rule:    "<defaults>",
		Reason:  "no group matched",
	}
}

// snapshot returns the current facts values map for one evaluation.
func (c *Config) snapshot() map[string]any {
	if c.registry == nil {
		return map[string]any{}
	}
	return c.registry.Snapshot()
}

// evalGroup runs match and rules inside a single ext-authz group.
func (c *Config) evalGroup(ctx context.Context, g *Group, requestVar, factsVar map[string]any) (Decision, bool) {
	if g.matchProg != nil {
		ok, err := celenv.Eval(ctx, g.matchProg, map[string]any{
			"request": requestVar,
			"facts":   factsVar,
		})
		if err != nil {
			return c.errorDecision(g.Name, "group match error: "+err.Error(), false), true
		}
		if !ok {
			return Decision{}, false
		}
	}

	switch g.Parameters.Mode {
	case "matchAll":
		for ri := range g.Rules {
			r := &g.Rules[ri]
			ok, err := celenv.Eval(ctx, r.matchProg, map[string]any{
				"request": requestVar,
				"facts":   factsVar,
			})
			if err != nil {
				return c.errorDecision(g.Name+"/"+r.Name, "match error: "+err.Error(), r.DryRun), true
			}
			if !ok {
				return Decision{
					Allowed: false,
					Rule:    g.Name + "/" + r.Name,
					Reason:  fmt.Sprintf("matchAll: rule %s failed", r.Name),
					DryRun:  r.DryRun,
				}, true
			}
		}
		return Decision{
			Allowed: true,
			Rule:    g.Name,
			Reason:  "matchAll: all rules held",
			DryRun:  false,
		}, true

	default:
		for ri := range g.Rules {
			r := &g.Rules[ri]
			ok, err := celenv.Eval(ctx, r.matchProg, map[string]any{
				"request": requestVar,
				"facts":   factsVar,
			})
			if err != nil {
				return c.errorDecision(g.Name+"/"+r.Name, "match error: "+err.Error(), r.DryRun), true
			}
			if ok {
				return Decision{
					Allowed: r.Validation.Action == "allow",
					Rule:    g.Name + "/" + r.Name,
					Reason:  "matched",
					DryRun:  r.DryRun,
				}, true
			}
		}
		return Decision{}, false
	}
}

// errorDecision converts a CEL runtime evaluation error into a Decision.
func (c *Config) errorDecision(rule, reason string, dry bool) Decision {
	if c.Defaults.ExtAuthz.AllowOnError {
		return Decision{Allowed: true, Rule: rule, Reason: reason + " (allowOnError)", DryRun: dry}
	}
	return Decision{Allowed: false, Rule: rule, Reason: reason, DryRun: dry}
}

// buildRequestVar projects a Request into the dict-shaped value for CEL request variable.
func buildRequestVar(r *Request) map[string]any {
	headersAll := map[string][]string{}
	headersFirst := map[string]string{}
	for k, vs := range r.Headers {
		lk := strings.ToLower(k)
		headersAll[lk] = vs
		if len(vs) > 0 {
			headersFirst[lk] = vs[0]
		}
	}

	queryAll := map[string][]string{}
	queryFirst := map[string]string{}
	if r.RawQuery != "" {
		if qs, err := url.ParseQuery(r.RawQuery); err == nil {
			for k, vs := range qs {
				queryAll[k] = vs
				if len(vs) > 0 {
					queryFirst[k] = vs[0]
				}
			}
		}
	}

	body := map[string]any{
		"raw":         string(r.Body),
		"size":        int64(len(r.Body)),
		"contentType": headersFirst["content-type"],
	}
	if jv, ok := tryJSON(r.Body); ok {
		body["json"] = jv
		body["jsonOk"] = true
	} else {
		body["json"] = map[string]any{}
		body["jsonOk"] = false
	}
	if yv, ok := tryYAML(r.Body); ok {
		body["yaml"] = yv
		body["yamlOk"] = true
	} else {
		body["yaml"] = map[string]any{}
		body["yamlOk"] = false
	}

	return map[string]any{
		"method":   r.Method,
		"scheme":   r.Scheme,
		"host":     r.Host,
		"path":     r.Path,
		"remoteIp": r.RemoteIP,
		"headers":  headersAll,
		"header":   headersFirst,
		"queries":  queryAll,
		"query":    queryFirst,
		"body":     body,
	}
}

// buildResponseVar projects a Response into the dict-shaped value for CEL response variable.
func buildResponseVar(resp *Response) map[string]any {
	if resp == nil {
		return map[string]any{}
	}
	headersAll := map[string][]string{}
	headersFirst := map[string]string{}
	for k, vs := range resp.Headers {
		lk := strings.ToLower(k)
		headersAll[lk] = vs
		if len(vs) > 0 {
			headersFirst[lk] = vs[0]
		}
	}

	body := map[string]any{
		"raw":         string(resp.Body),
		"size":        int64(len(resp.Body)),
		"contentType": headersFirst["content-type"],
	}
	if jv, ok := tryJSON(resp.Body); ok {
		body["json"] = jv
		body["jsonOk"] = true
	} else {
		body["json"] = map[string]any{}
		body["jsonOk"] = false
	}
	if yv, ok := tryYAML(resp.Body); ok {
		body["yaml"] = yv
		body["yamlOk"] = true
	} else {
		body["yaml"] = map[string]any{}
		body["yamlOk"] = false
	}

	return map[string]any{
		"status":  int64(resp.Status),
		"headers": headersAll,
		"header":  headersFirst,
		"body":    body,
	}
}

// tryJSON tries to decode json, normalising decoded nested structures.
func tryJSON(b []byte) (any, bool) {
	if len(b) == 0 {
		return nil, false
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, false
	}
	return normaliseDecoded(v), true
}

// tryYAML tries to decode yaml, normalising decoded nested structures.
func tryYAML(b []byte) (any, bool) {
	if len(b) == 0 {
		return nil, false
	}
	var v any
	if err := yamlv3.Unmarshal(b, &v); err != nil {
		return nil, false
	}
	return normaliseDecoded(v), true
}

// normaliseDecoded converts map[any]any and []any leaves to types CEL can handle.
func normaliseDecoded(v any) any {
	switch x := v.(type) {
	case map[any]any:
		out := make(map[string]any, len(x))
		for k, vv := range x {
			out[fmt.Sprint(k)] = normaliseDecoded(vv)
		}
		return out
	case map[string]any:
		for k, vv := range x {
			x[k] = normaliseDecoded(vv)
		}
		return x
	case []any:
		for i, vv := range x {
			x[i] = normaliseDecoded(vv)
		}
		return x
	}
	return v
}

// BytesSize is a YAML-friendly byte count with suffix support.
type BytesSize int64

// UnmarshalYAML implements Custom Unmarshal for BytesSize.
func (b *BytesSize) UnmarshalYAML(n *yamlv3.Node) error {
	if n.Kind != yamlv3.ScalarNode {
		return fmt.Errorf("maxBodyBytes: expected scalar")
	}
	s := strings.TrimSpace(n.Value)
	if v, err := strconv.ParseInt(s, 10, 64); err == nil {
		*b = BytesSize(v)
		return nil
	}
	lower := strings.ToLower(s)
	mul := int64(1)
	switch {
	case strings.HasSuffix(lower, "kib"):
		mul = 1 << 10
		s = s[:len(s)-3]
	case strings.HasSuffix(lower, "mib"):
		mul = 1 << 20
		s = s[:len(s)-3]
	case strings.HasSuffix(lower, "gib"):
		mul = 1 << 30
		s = s[:len(s)-3]
	case strings.HasSuffix(lower, "kb"):
		mul = 1000
		s = s[:len(s)-2]
	case strings.HasSuffix(lower, "mb"):
		mul = 1000 * 1000
		s = s[:len(s)-2]
	case strings.HasSuffix(lower, "b"):
		s = s[:len(s)-1]
	}
	v, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return fmt.Errorf("invalid byte size %q: %w", n.Value, err)
	}
	*b = BytesSize(v * mul)
	return nil
}

// Int64 returns the value as int64.
func (b BytesSize) Int64() int64 { return int64(b) }
