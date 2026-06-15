// Package policy contains the configuration model, parser and evaluator that
// drive the request-validator authorisation engine.
//
// The policy is a list of named groups. Each rule has one CEL expression
// (`match`) that decides whether the rule applies; if it does, the rule's
// effective `action` (allow|deny) becomes the verdict. The group's `mode`
// composes the rules:
//
//   - `firstMatch` (default): the first rule whose `match` is true wins.
//   - `all`:                  every rule must hold; the first failure
//                              produces a deny.
//
// A rule inherits its `action` from the group when it does not declare one,
// which lets a "deny-by-default" group be expressed concisely.
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
	Defaults Defaults      `yaml:"defaults"`
	Logging  Logging       `yaml:"logging"`
	Facts    []facts.Spec  `yaml:"facts"`
	Groups   []Group       `yaml:"groups"`

	// compiled state (set during Load)
	env      *celenv.Env
	registry *facts.Registry
}

// Defaults are server-wide knobs.
type Defaults struct {
	// Action returned when no group decides. "allow" or "deny" (default deny).
	Action string `yaml:"action"`

	// DenyStatus is the HTTP status code returned on deny. Default 403.
	DenyStatus int `yaml:"denyStatus"`

	// DenyBody is the body returned on deny. Default "Forbidden".
	DenyBody string `yaml:"denyBody"`

	// MaxBodyBytes is the maximum number of bytes buffered from the request
	// body. Accepts unit suffixes ("1MiB", "512KiB", "1MB"). Default 1 MiB.
	MaxBodyBytes BytesSize `yaml:"maxBodyBytes"`

	// AllowOnError: if true, evaluation errors produce allow; else deny.
	AllowOnError bool `yaml:"allowOnError"`

	// DryRun is the global shadow switch: the service evaluates every request
	// normally but never enforces a deny. All requests pass through to Envoy
	// with HTTP 200, while the access log and metrics record the real verdict
	// so an operator can observe what would be denied before enabling
	// enforcement. Default false.
	DryRun bool `yaml:"dryRun"`
}

// Logging configures the access-log enrichment applied to every request.
//
// The whole struct is optional; defaults are biased towards "log everything
// safely" - every request produces a line, body and short header values
// are kept, and a small allow-list of obvious secrets is redacted or
// excluded.
type Logging struct {
	// Level is the global threshold (debug|info|warn|error). Default info.
	// Overridden by the --log-level flag if it is non-empty.
	Level string `yaml:"level"`

	// Format selects the slog handler: "json" (default) or "console".
	// Overridden by the --log-format flag if it is non-empty.
	Format string `yaml:"format"`

	// LogBody, when true, includes the request body (truncated to
	// defaults.maxBodyBytes already) as a string under request.body in the
	// log record. Default false because DCR payloads carry client_secrets.
	LogBody bool `yaml:"logBody"`

	// ExcludeHeaders lists header names that must never appear in the log.
	// Case-insensitive. Default: ["cookie", "set-cookie"].
	ExcludeHeaders []string `yaml:"excludeHeaders"`

	// RedactHeaders lists header names whose values must be masked. Each
	// value is shown as a short prefix followed by '*' characters; values
	// shorter than RedactReveal are fully masked.
	// Case-insensitive. Default:
	//   ["authorization","proxy-authorization","x-api-key","x-auth-token"].
	RedactHeaders []string `yaml:"redactHeaders"`

	// RedactReveal is the number of leading characters to keep when
	// redacting. Default 6. Set to 0 to always fully mask.
	RedactReveal int `yaml:"redactReveal"`

	// RedactQueryParams behaves like RedactHeaders for URL query parameters.
	// Default: ["access_token","id_token","code"].
	RedactQueryParams []string `yaml:"redactQueryParams"`
}

// Group is a named collection of rules with a common scope and a mode.
type Group struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`

	// Mode controls how the group composes its rules:
	//   "firstMatch" (default): the first rule whose `match` is true decides.
	//   "all":                  every rule must match; one failure denies.
	Mode string `yaml:"mode"`

	// Action is the verdict declared at the group level. Each rule inherits
	// it unless overridden. Allowed values: "allow" | "deny". Default "allow".
	Action string `yaml:"action"`

	// Match is an optional CEL boolean expression. If present and false the
	// whole group is skipped silently.
	Match string `yaml:"match"`

	// Rules in declaration order.
	Rules []Rule `yaml:"rules"`

	// compiled state
	matchProg cel.Program
}

// Rule is one entry in `rules:`.
type Rule struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`

	// Action overrides the group's action for this specific rule.
	// Allowed values: "allow" | "deny" | "" (inherit from group).
	Action string `yaml:"action"`

	// Match is the CEL boolean expression that decides whether the rule
	// applies. If omitted, the default is `true` (rule always applies, useful
	// as a fallback inside a firstMatch group).
	Match string `yaml:"match"`

	// Fallthrough controls what happens when `match` is false in a
	// firstMatch group:
	//   "next"  (default in firstMatch): try the next rule.
	//   "allow" or "deny":                emit that verdict immediately.
	// Ignored in `all` mode (a failure there is a group-level verdict).
	Fallthrough string `yaml:"fallthrough"`

	// DryRun: the rule still logs and emits metrics, but the verdict is
	// suppressed (request is allowed). Useful for shadow-testing future
	// tightenings.
	DryRun bool `yaml:"dryRun"`

	// resolved/compiled state
	effectiveAction string
	matchProg       cel.Program
}

// Decision is the evaluator output.
type Decision struct {
	Allowed bool
	Rule    string // "<defaults>" if nothing matched, "group/rule" otherwise
	Reason  string
	DryRun  bool
}

// Request is the normalised view of the incoming HTTP request that the
// httpserver layer hands over to the evaluator. The evaluator turns it into
// a CEL activation map shaped like the README documents.
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

// LoadFile reads, parses, validates and compiles a policy file.
func LoadFile(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw = []byte(os.ExpandEnv(string(raw)))
	return LoadBytes(raw)
}

// LoadBytes is LoadFile from already-read bytes (useful in tests).
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

// Start activates the facts registry: file sources are read, URL fetchers
// perform their first fetch and start refreshing in the background. It is
// safe to call multiple times only after Stop().
func (c *Config) Start(ctx context.Context) error {
	if c.registry == nil {
		return nil
	}
	return c.registry.Start(ctx)
}

// Stop cancels the facts registry goroutines and waits for them.
func (c *Config) Stop() {
	if c.registry == nil {
		return
	}
	c.registry.Stop()
}

func applyDefaults(c *Config) {
	if c.Defaults.Action == "" {
		c.Defaults.Action = "deny"
	}
	if c.Defaults.DenyStatus == 0 {
		c.Defaults.DenyStatus = 403
	}
	if c.Defaults.DenyBody == "" {
		c.Defaults.DenyBody = "Forbidden"
	}
	if c.Defaults.MaxBodyBytes == 0 {
		c.Defaults.MaxBodyBytes = 1 << 20
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
	for gi := range c.Groups {
		g := &c.Groups[gi]
		if g.Mode == "" {
			g.Mode = "firstMatch"
		}
		if g.Action == "" {
			g.Action = "allow"
		}
		for ri := range g.Rules {
			r := &g.Rules[ri]
			r.effectiveAction = r.Action
			if r.effectiveAction == "" {
				r.effectiveAction = g.Action
			}
			if r.Fallthrough == "" {
				// In firstMatch groups the natural default is "next" so the
				// next rule can try. In `all` groups fallthrough is ignored.
				r.Fallthrough = "next"
			}
		}
	}
}

func (c *Config) validate() error {
	if c.Defaults.Action != "allow" && c.Defaults.Action != "deny" {
		return fmt.Errorf("defaults.action must be allow|deny")
	}
	seen := map[string]bool{}
	for gi, g := range c.Groups {
		if g.Name == "" {
			return fmt.Errorf("groups[%d]: missing name", gi)
		}
		if seen[g.Name] {
			return fmt.Errorf("duplicate group name %q", g.Name)
		}
		seen[g.Name] = true
		if g.Mode != "firstMatch" && g.Mode != "all" {
			return fmt.Errorf("group %q: mode must be firstMatch|all", g.Name)
		}
		if g.Action != "allow" && g.Action != "deny" {
			return fmt.Errorf("group %q: action must be allow|deny", g.Name)
		}
		if len(g.Rules) == 0 {
			return fmt.Errorf("group %q: must contain at least one rule", g.Name)
		}
		for ri, r := range g.Rules {
			if r.Name == "" {
				return fmt.Errorf("group %q rules[%d]: missing name", g.Name, ri)
			}
			if seen[g.Name+"/"+r.Name] {
				return fmt.Errorf("duplicate rule name %q in group %q", r.Name, g.Name)
			}
			seen[g.Name+"/"+r.Name] = true
			ea := r.effectiveAction
			if ea != "allow" && ea != "deny" {
				return fmt.Errorf("rule %q/%q: action must be allow|deny (got %q)", g.Name, r.Name, ea)
			}
			if r.Fallthrough != "next" && r.Fallthrough != "allow" && r.Fallthrough != "deny" {
				return fmt.Errorf("rule %q/%q: fallthrough must be next|allow|deny", g.Name, r.Name)
			}
		}
	}
	return nil
}

func (c *Config) compile() error {
	for gi := range c.Groups {
		g := &c.Groups[gi]
		if strings.TrimSpace(g.Match) != "" {
			p, err := c.env.Compile(g.Match)
			if err != nil {
				return fmt.Errorf("group %q match: %w", g.Name, err)
			}
			g.matchProg = p
		}
		for ri := range g.Rules {
			r := &g.Rules[ri]
			src := strings.TrimSpace(r.Match)
			if src == "" {
				src = "true"
			}
			p, err := c.env.Compile(src)
			if err != nil {
				return fmt.Errorf("rule %q/%q match: %w", g.Name, r.Name, err)
			}
			r.matchProg = p
		}
	}
	return nil
}

// Evaluate runs the policy against a request.
func (c *Config) Evaluate(ctx context.Context, r *Request) Decision {
	requestVar := buildRequestVar(r)
	factsVar := c.snapshot()
	for gi := range c.Groups {
		if d, decided := c.evalGroup(ctx, &c.Groups[gi], requestVar, factsVar); decided {
			return d
		}
	}
	return Decision{
		Allowed: c.Defaults.Action == "allow",
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

func (c *Config) evalGroup(ctx context.Context, g *Group, requestVar, factsVar map[string]any) (Decision, bool) {
	if g.matchProg != nil {
		ok, err := celenv.Eval(ctx, g.matchProg, requestVar, factsVar)
		if err != nil {
			return c.errorDecision(g.Name, "group match error: "+err.Error(), false), true
		}
		if !ok {
			return Decision{}, false
		}
	}

	switch g.Mode {
	case "all":
		for ri := range g.Rules {
			r := &g.Rules[ri]
			ok, err := celenv.Eval(ctx, r.matchProg, requestVar, factsVar)
			if err != nil {
				return c.errorDecision(g.Name+"/"+r.Name, "match error: "+err.Error(), r.DryRun), true
			}
			// In `all` mode, every rule must produce its declared verdict;
			// if it doesn't match, the group denies (or allows when the
			// rule's action is deny - interpreting "all of these denies must
			// hold" naturally).
			ruleAllow := r.effectiveAction == "allow"
			if ok != ruleAllow {
				// Group fails. Emit the opposite of the group action.
				groupAllow := g.Action == "allow"
				return Decision{
					Allowed: !groupAllow,
					Rule:    g.Name + "/" + r.Name,
					Reason:  fmt.Sprintf("group mode=all: rule %q failed", r.Name),
					DryRun:  r.DryRun,
				}, true
			}
		}
		// All rules held.
		return Decision{
			Allowed: g.Action == "allow",
			Rule:    g.Name,
			Reason:  "group mode=all: every rule held",
		}, true

	default: // firstMatch
		for ri := range g.Rules {
			r := &g.Rules[ri]
			ok, err := celenv.Eval(ctx, r.matchProg, requestVar, factsVar)
			if err != nil {
				return c.errorDecision(g.Name+"/"+r.Name, "match error: "+err.Error(), r.DryRun), true
			}
			if ok {
				return Decision{
					Allowed: r.effectiveAction == "allow",
					Rule:    g.Name + "/" + r.Name,
					Reason:  "matched",
					DryRun:  r.DryRun,
				}, true
			}
			// match=false; apply fallthrough.
			switch r.Fallthrough {
			case "next":
				continue
			case "allow":
				return Decision{Allowed: true, Rule: g.Name + "/" + r.Name, Reason: "no match -> fallthrough allow", DryRun: r.DryRun}, true
			case "deny":
				return Decision{Allowed: false, Rule: g.Name + "/" + r.Name, Reason: "no match -> fallthrough deny", DryRun: r.DryRun}, true
			}
		}
		return Decision{}, false
	}
}

func (c *Config) errorDecision(rule, reason string, dry bool) Decision {
	if c.Defaults.AllowOnError {
		return Decision{Allowed: true, Rule: rule, Reason: reason + " (allowOnError)", DryRun: dry}
	}
	return Decision{Allowed: false, Rule: rule, Reason: reason, DryRun: dry}
}

// buildRequestVar projects a Request into the dict-shaped value that policies
// see as the `request` CEL variable.
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

func tryYAML(b []byte) (any, bool) {
	if len(b) == 0 {
		return nil, false
	}
	var v any
	if err := yamlv3.Unmarshal(b, &v); err != nil {
		return nil, false
	}
	// yaml.v3 may decode maps as map[string]any already, but sometimes as
	// map[any]any. Normalise so CEL sees consistent types.
	return normaliseDecoded(v), true
}

// normaliseDecoded converts map[any]any and []any leaves to types CEL can
// handle uniformly. JSON output is already compatible; YAML is the troubled
// case.
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

// BytesSize is a YAML-friendly byte count that accepts numbers or
// human-readable strings ("1MiB", "512KiB", "1MB", "1024b").
type BytesSize int64

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
