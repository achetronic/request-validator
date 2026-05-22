package adminapi

import (
	"encoding/json"

	"request-validator/internal/facts"
	"request-validator/internal/policy"
	"request-validator/internal/state"
)

// dto.go declares every request / response type the admin API exposes
// so the OpenAPI generator (swaggo/swag v2) can introspect them.
//
// These types are deliberately separate from the internal runtime
// types: those carry compiled CEL programs, mutexes and informers
// that don't survive JSON marshalling cleanly. The DTOs are a stable
// wire contract.

// ErrorResponse is the JSON shape returned for any non-2xx outcome.
type ErrorResponse struct {
	// Error is a short, human-readable explanation.
	Error string `json:"error" example:"validation failed: group \"x\": rules must not be empty"`
}

// ItemResponse is the JSON shape returned for a single overlay entry
// in a collection (`groups`, `facts`).
type ItemResponse struct {
	// Name is the entry key (e.g. group name, fact name).
	Name string `json:"name" example:"api-block-residential"`
	// Section is the parent collection ("groups" or "facts").
	Section string `json:"section" example:"groups"`
	// Revision is the opaque concurrency token; pass it back as
	// `If-Match` to perform a conditional update.
	Revision state.Revision `json:"revision" example:"42"`
	// Payload is the JSON payload exactly as it would appear inside
	// the YAML policy (decoded into a generic object).
	Payload json.RawMessage `json:"payload" swaggertype:"object"`
}

// ItemListResponse wraps an array of ItemResponse for collection GETs.
type ItemListResponse struct {
	Items []ItemResponse `json:"items"`
}

// RegisterResponse is the JSON shape returned by GET/PUT on the
// singleton sections (`defaults`, `logging`).
type RegisterResponse struct {
	Section  string          `json:"section" example:"defaults"`
	Revision state.Revision  `json:"revision" example:"42"`
	Payload  json.RawMessage `json:"payload" swaggertype:"object"`
}

// GroupRequest is the body shape accepted by PUT /api/v1/groups/{name}.
// It mirrors the YAML grammar exactly; see POLICY_DSL.md.
type GroupRequest struct {
	Name        string        `json:"name,omitempty" example:"api-block-residential"`
	Description string        `json:"description,omitempty" example:"Block a residential ASN at request time"`
	Priority    int           `json:"priority,omitempty" example:"-100"`
	Mode        string        `json:"mode,omitempty" example:"firstMatch" enums:"firstMatch,all"`
	Action      string        `json:"action,omitempty" example:"deny" enums:"allow,deny"`
	Match       string        `json:"match,omitempty"`
	Rules       []RuleRequest `json:"rules"`
}

// RuleRequest is a rule entry as accepted by the admin API.
type RuleRequest struct {
	Name        string `json:"name" example:"block-bad-ip"`
	Description string `json:"description,omitempty"`
	Action      string `json:"action,omitempty" example:"deny" enums:"allow,deny"`
	Match       string `json:"match,omitempty" example:"request.remoteIp == \"203.0.113.5\""`
	Fallthrough string `json:"fallthrough,omitempty" example:"next" enums:"next,allow,deny"`
	DryRun      bool   `json:"dryRun,omitempty"`
}

// FactRequest is the body shape accepted by PUT /api/v1/facts/{name}.
type FactRequest struct {
	Name   string        `json:"name,omitempty" example:"chatgptFeed"`
	Method string        `json:"method" example:"url" enums:"value,file,url"`
	Value  any           `json:"value,omitempty" swaggertype:"object"`
	File   *FactFileSpec `json:"file,omitempty"`
	URL    *FactURLSpec  `json:"url,omitempty"`
}

// FactFileSpec is the `file:` block of a fact spec.
type FactFileSpec struct {
	Path string `json:"path" example:"/etc/policy/lists/cidrs.json"`
}

// FactURLSpec is the `url:` block of a fact spec.
type FactURLSpec struct {
	Address  string            `json:"address" example:"https://openai.com/chatgpt-actions.json"`
	Interval string            `json:"interval,omitempty" example:"10m"`
	Timeout  string            `json:"timeout,omitempty" example:"15s"`
	Headers  map[string]string `json:"headers,omitempty"`
}

// DefaultsRequest is the body shape accepted by PUT /api/v1/defaults.
// Only the fields the caller wants to override need to be present;
// absent fields inherit from the YAML.
type DefaultsRequest struct {
	Action       string `json:"action,omitempty" example:"deny" enums:"allow,deny"`
	DenyStatus   int    `json:"denyStatus,omitempty" example:"403"`
	DenyBody     string `json:"denyBody,omitempty" example:"Forbidden"`
	MaxBodyBytes string `json:"maxBodyBytes,omitempty" example:"1MiB"`
	AllowOnError bool   `json:"allowOnError,omitempty"`
}

// LoggingRequest is the body shape accepted by PUT /api/v1/logging.
type LoggingRequest struct {
	Level             string   `json:"level,omitempty" example:"info" enums:"debug,info,warn,error"`
	Format            string   `json:"format,omitempty" example:"json" enums:"json,console"`
	LogBody           bool     `json:"logBody,omitempty"`
	ExcludeHeaders    []string `json:"excludeHeaders,omitempty"`
	RedactHeaders     []string `json:"redactHeaders,omitempty"`
	RedactReveal      int      `json:"redactReveal,omitempty" example:"6"`
	RedactQueryParams []string `json:"redactQueryParams,omitempty"`
}

// ConfigResponse is the body returned by GET /api/v1/config (the
// effective compiled config currently serving traffic).
type ConfigResponse struct {
	Defaults policy.Defaults    `json:"defaults"`
	Logging  policy.Logging     `json:"logging"`
	Facts    []facts.Spec       `json:"facts"`
	Groups   []GroupViewElement `json:"groups"`
}

// GroupViewElement is one entry of ConfigResponse.Groups: the YAML
// group enriched with the resolved `source` ("yaml" | "api").
type GroupViewElement struct {
	Name        string        `json:"name"`
	Description string        `json:"description,omitempty"`
	Priority    int           `json:"priority"`
	Mode        string        `json:"mode"`
	Action      string        `json:"action"`
	Match       string        `json:"match,omitempty"`
	Source      string        `json:"source" example:"yaml" enums:"yaml,api"`
	Rules       []RuleRequest `json:"rules"`
}

// ClusterResponse is the body returned by GET /api/v1/cluster.
type ClusterResponse struct {
	Standalone bool       `json:"standalone"`
	IAmLeader  bool       `json:"iAmLeader"`
	Leader     LeaderView `json:"leader"`
}

// LeaderView is the nested leader info in ClusterResponse.
type LeaderView struct {
	PodName    string `json:"podName"`
	AdminURL   string `json:"adminURL"`
	Identity   string `json:"identity"`
	LeaseUntil string `json:"leaseUntil"`
}
