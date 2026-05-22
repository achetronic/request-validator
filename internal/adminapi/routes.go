package adminapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/swaggo/swag/v2"

	_ "request-validator/internal/adminapi/docs" // self-register the generated OpenAPI 3.1 spec
	"request-validator/internal/cluster"
	"request-validator/internal/policy"
	"request-validator/internal/state"
)

const adminMaxBodyBytes = 1 << 20

func readBody(r *http.Request) ([]byte, error) {
	if r.ContentLength > adminMaxBodyBytes {
		return nil, fmt.Errorf("body too large")
	}
	buf, err := io.ReadAll(io.LimitReader(r.Body, adminMaxBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(buf)) > adminMaxBodyBytes {
		return nil, fmt.Errorf("body too large")
	}
	return buf, nil
}

// registerRoutes wires every path on the admin API.
func (s *Server) registerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/groups", s.handleCollection(state.SectionGroups))
	mux.HandleFunc("/api/v1/groups/", s.handleItem(state.SectionGroups))

	mux.HandleFunc("/api/v1/facts", s.handleCollection(state.SectionFacts))
	mux.HandleFunc("/api/v1/facts/", s.handleItem(state.SectionFacts))

	mux.HandleFunc("/api/v1/defaults", s.handleRegister(state.SectionDefaults))
	mux.HandleFunc("/api/v1/logging", s.handleRegister(state.SectionLogging))

	mux.HandleFunc("/api/v1/config", s.handleConfig)
	mux.HandleFunc("/api/v1/cluster", s.handleCluster)
	mux.HandleFunc("/api/v1/openapi.json", s.handleOpenAPI)
}

// itemView is the JSON shape returned for a single overlay entry.
type itemView struct {
	Name     string          `json:"name"`
	Section  string          `json:"section"`
	Revision state.Revision  `json:"revision"`
	Payload  json.RawMessage `json:"payload"`
}

// handleCollection implements GET /api/v1/{groups,facts}.
func (s *Server) handleCollection(section string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		snap, err := s.opts.Store.Snapshot(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		entries := map[string]json.RawMessage{}
		switch section {
		case state.SectionGroups:
			entries = snap.Groups
		case state.SectionFacts:
			entries = snap.Facts
		}
		items := make([]itemView, 0, len(entries))
		for k, v := range entries {
			items = append(items, itemView{
				Name:     k,
				Section:  section,
				Revision: snap.Revision,
				Payload:  v,
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items})
	}
}

// handleItem implements GET/PUT/DELETE /api/v1/{groups,facts}/{name}.
func (s *Server) handleItem(section string) http.HandlerFunc {
	prefix := "/api/v1/" + section + "/"
	return func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, prefix)
		if name == "" || strings.Contains(name, "/") {
			writeError(w, http.StatusBadRequest, "missing or invalid name")
			return
		}
		switch r.Method {
		case http.MethodGet:
			s.itemGet(w, r, section, name)
		case http.MethodPut:
			if !s.ensureLeaderOrRedirect(w, r) {
				return
			}
			s.itemPut(w, r, section, name)
		case http.MethodDelete:
			if !s.ensureLeaderOrRedirect(w, r) {
				return
			}
			s.itemDelete(w, r, section, name)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	}
}

func (s *Server) itemGet(w http.ResponseWriter, r *http.Request, section, name string) {
	entry, err := s.opts.Store.Get(r.Context(), section, name)
	if err != nil {
		if errors.Is(err, state.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Etag", etagFor(entry.Revision))
	writeJSON(w, http.StatusOK, itemView{
		Name: name, Section: section, Revision: entry.Revision, Payload: entry.Payload,
	})
}

func (s *Server) itemPut(w http.ResponseWriter, r *http.Request, section, name string) {
	body, err := readBody(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var asMap map[string]any
	if err := json.Unmarshal(body, &asMap); err != nil {
		writeError(w, http.StatusBadRequest, "body must be a JSON object")
		return
	}
	if asMap == nil {
		asMap = map[string]any{}
	}
	if got, ok := asMap["name"]; ok {
		if gs, _ := got.(string); gs != "" && gs != name {
			writeError(w, http.StatusBadRequest,
				fmt.Sprintf("body name %q does not match path %q", gs, name))
			return
		}
	}
	asMap["name"] = name
	normalised, err := json.Marshal(asMap)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	// Build a hypothetical snapshot with the new entry applied; if
	// the merge fails we never touch the store.
	snap, err := s.opts.Store.Snapshot(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	hypothetical := withEntry(snap, section, name, normalised)
	if err := s.previewMerge(hypothetical); err != nil {
		writeError(w, http.StatusBadRequest, "validation failed: "+err.Error())
		return
	}

	ifMatch := parseIfMatch(r)
	rev, err := s.opts.Store.Put(r.Context(), section, name, normalised, ifMatch)
	if err != nil {
		switch {
		case errors.Is(err, state.ErrConflict):
			writeError(w, http.StatusPreconditionFailed, "If-Match did not match the current revision")
		default:
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	// The store watcher will trigger a rebuild on every replica; but
	// to give the caller read-your-writes locally, we rebuild
	// synchronously here too.
	freshSnap, _ := s.opts.Store.Snapshot(r.Context())
	if err := s.rebuildAndApply(freshSnap, "admin "+section+" PUT "+name); err != nil {
		writeError(w, http.StatusInternalServerError, "applied to store but rebuild failed: "+err.Error())
		return
	}

	w.Header().Set("Etag", etagFor(rev))
	writeJSON(w, http.StatusOK, itemView{
		Name: name, Section: section, Revision: rev, Payload: normalised,
	})
}

func (s *Server) itemDelete(w http.ResponseWriter, r *http.Request, section, name string) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	ifMatch := parseIfMatch(r)
	if err := s.opts.Store.Delete(r.Context(), section, name, ifMatch); err != nil {
		switch {
		case errors.Is(err, state.ErrConflict):
			writeError(w, http.StatusPreconditionFailed, "If-Match did not match the current revision")
		case errors.Is(err, state.ErrNotFound):
			writeError(w, http.StatusNotFound, "not found")
		default:
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	freshSnap, _ := s.opts.Store.Snapshot(r.Context())
	if err := s.rebuildAndApply(freshSnap, "admin "+section+" DELETE "+name); err != nil {
		writeError(w, http.StatusInternalServerError, "applied to store but rebuild failed: "+err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleRegister implements GET/PUT/DELETE /api/v1/{defaults,logging}.
func (s *Server) handleRegister(section string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			entry, err := s.opts.Store.Get(r.Context(), section, "")
			if err != nil {
				if errors.Is(err, state.ErrNotFound) {
					writeError(w, http.StatusNotFound, "not set via admin api")
					return
				}
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			w.Header().Set("Etag", etagFor(entry.Revision))
			writeJSON(w, http.StatusOK, map[string]any{
				"section":  section,
				"revision": entry.Revision,
				"payload":  json.RawMessage(entry.Payload),
			})
		case http.MethodPut:
			if !s.ensureLeaderOrRedirect(w, r) {
				return
			}
			s.registerPut(w, r, section)
		case http.MethodDelete:
			if !s.ensureLeaderOrRedirect(w, r) {
				return
			}
			s.registerDelete(w, r, section)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	}
}

func (s *Server) registerPut(w http.ResponseWriter, r *http.Request, section string) {
	body, err := readBody(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var asMap map[string]any
	if err := json.Unmarshal(body, &asMap); err != nil {
		writeError(w, http.StatusBadRequest, "body must be a JSON object")
		return
	}
	payload, _ := json.Marshal(asMap)

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	snap, err := s.opts.Store.Snapshot(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	hypothetical := withEntry(snap, section, "", payload)
	if err := s.previewMerge(hypothetical); err != nil {
		writeError(w, http.StatusBadRequest, "validation failed: "+err.Error())
		return
	}

	ifMatch := parseIfMatch(r)
	rev, err := s.opts.Store.Put(r.Context(), section, "", payload, ifMatch)
	if err != nil {
		switch {
		case errors.Is(err, state.ErrConflict):
			writeError(w, http.StatusPreconditionFailed, "If-Match did not match the current revision")
		default:
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	freshSnap, _ := s.opts.Store.Snapshot(r.Context())
	if err := s.rebuildAndApply(freshSnap, "admin "+section+" PUT"); err != nil {
		writeError(w, http.StatusInternalServerError, "applied to store but rebuild failed: "+err.Error())
		return
	}
	w.Header().Set("Etag", etagFor(rev))
	writeJSON(w, http.StatusOK, map[string]any{
		"section":  section,
		"revision": rev,
		"payload":  asMap,
	})
}

func (s *Server) registerDelete(w http.ResponseWriter, r *http.Request, section string) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	ifMatch := parseIfMatch(r)
	if err := s.opts.Store.Delete(r.Context(), section, "", ifMatch); err != nil {
		switch {
		case errors.Is(err, state.ErrConflict):
			writeError(w, http.StatusPreconditionFailed, "If-Match did not match the current revision")
		case errors.Is(err, state.ErrNotFound):
			writeError(w, http.StatusNotFound, "not set via admin api")
		default:
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	freshSnap, _ := s.opts.Store.Snapshot(r.Context())
	if err := s.rebuildAndApply(freshSnap, "admin "+section+" DELETE"); err != nil {
		writeError(w, http.StatusInternalServerError, "applied to store but rebuild failed: "+err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleConfig returns the effective compiled config currently
// serving traffic, in a JSON-safe form.
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	snap, err := s.opts.Store.Snapshot(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	cfg, err := policy.MergeFromYAML(s.opts.YAMLProvider(), snap)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, configView(cfg))
}

func configView(cfg *policy.Config) map[string]any {
	groups := make([]map[string]any, 0, len(cfg.Groups))
	for _, g := range cfg.Groups {
		rules := make([]map[string]any, 0, len(g.Rules))
		for _, rl := range g.Rules {
			rules = append(rules, map[string]any{
				"name":        rl.Name,
				"description": rl.Description,
				"action":      rl.Action,
				"match":       rl.Match,
				"fallthrough": rl.Fallthrough,
				"dryRun":      rl.DryRun,
			})
		}
		groups = append(groups, map[string]any{
			"name":        g.Name,
			"description": g.Description,
			"priority":    g.Priority,
			"mode":        g.Mode,
			"action":      g.Action,
			"match":       g.Match,
			"source":      g.Source,
			"rules":       rules,
		})
	}
	return map[string]any{
		"defaults": cfg.Defaults,
		"logging":  cfg.Logging,
		"facts":    cfg.Facts,
		"groups":   groups,
	}
}

// handleCluster returns who is leader, who am I, and other members.
func (s *Server) handleCluster(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var l cluster.Leader
	standalone := true
	if s.opts.Cluster != nil {
		l = s.opts.Cluster.Leader()
		standalone = s.opts.Cluster.Standalone()
	} else {
		// No cluster wired at all (test setup or pre-Bootstrap):
		// behave as if we were the single replica.
		l.Self = true
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"standalone": standalone,
		"iAmLeader":  l.Self,
		"leader": map[string]any{
			"podName":    l.PodName,
			"adminURL":   l.AdminURL,
			"identity":   l.Identity,
			"leaseUntil": l.LeaseUntil,
		},
	})
}

// handleOpenAPI returns the generated OpenAPI 3.1 specification.
func (s *Server) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	doc, err := swag.ReadDoc("swagger")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(doc))
}

// withEntry returns a copy of snap with the given section/key set to
// payload. Used to build hypothetical snapshots for preview-merge.
func withEntry(snap state.Snapshot, section, key string, payload json.RawMessage) state.Snapshot {
	out := state.Snapshot{
		Groups:   cloneMap(snap.Groups),
		Facts:    cloneMap(snap.Facts),
		Defaults: clone(snap.Defaults),
		Logging:  clone(snap.Logging),
		Revision: snap.Revision,
	}
	switch section {
	case state.SectionGroups:
		if out.Groups == nil {
			out.Groups = map[string]json.RawMessage{}
		}
		out.Groups[key] = payload
	case state.SectionFacts:
		if out.Facts == nil {
			out.Facts = map[string]json.RawMessage{}
		}
		out.Facts[key] = payload
	case state.SectionDefaults:
		out.Defaults = payload
	case state.SectionLogging:
		out.Logging = payload
	}
	return out
}

func cloneMap(m map[string]json.RawMessage) map[string]json.RawMessage {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]json.RawMessage, len(m))
	for k, v := range m {
		out[k] = clone(v)
	}
	return out
}

func clone(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
