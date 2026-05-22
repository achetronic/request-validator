package adminapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/swaggo/swag/v2"

	_ "request-validator/internal/adminapi/docs" // self-register the generated OpenAPI 3.1 spec
	"request-validator/internal/crdt"
	"request-validator/internal/policy"
)

// registerRoutes wires every path on the admin API. Method matching is
// done inside each handler so we can return a useful 405 on the wrong
// verb without depending on a router.
func (s *Server) registerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/groups", s.handleCollection(crdt.SectionGroups))
	mux.HandleFunc("/api/v1/groups/", s.handleItem(crdt.SectionGroups))

	mux.HandleFunc("/api/v1/facts", s.handleCollection(crdt.SectionFacts))
	mux.HandleFunc("/api/v1/facts/", s.handleItem(crdt.SectionFacts))

	mux.HandleFunc("/api/v1/defaults", s.handleRegister(crdt.SectionDefaults))
	mux.HandleFunc("/api/v1/logging", s.handleRegister(crdt.SectionLogging))

	mux.HandleFunc("/api/v1/config", s.handleConfig)
	mux.HandleFunc("/api/v1/quarantine", s.handleQuarantineList)
	mux.HandleFunc("/api/v1/quarantine/", s.handleQuarantineItem)

	mux.HandleFunc("/api/v1/openapi.json", s.handleOpenAPI)
}

// handleOpenAPI returns the generated OpenAPI 3.1 specification of
// this admin API. The document is rendered by swaggo/swag v2 at build
// time and embedded into internal/adminapi/docs via `make swagger`.
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

// itemView is the JSON shape returned for a CRDT-managed entry.
type itemView struct {
	Name      string           `json:"name"`
	Section   string           `json:"section"`
	Stamp     crdt.Stamp       `json:"stamp"`
	Payload   json.RawMessage  `json:"payload"`
	Tombstone bool             `json:"tombstone,omitempty"`
}

func (s *Server) collectionMap(section string) *crdt.LWWMap {
	switch section {
	case crdt.SectionGroups:
		return s.opts.Store.Groups
	case crdt.SectionFacts:
		return s.opts.Store.Facts
	}
	return nil
}

// handleCollection implements GET /api/v1/{groups,facts}.
func (s *Server) handleCollection(section string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		m := s.collectionMap(section)
		items := make([]itemView, 0)
		m.Range(func(key string, e crdt.MapEntry) bool {
			items = append(items, itemView{
				Name:    key,
				Section: section,
				Stamp:   e.Stamp,
				Payload: e.Payload,
			})
			return true
		})
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
			s.itemGet(w, section, name)
		case http.MethodPut:
			s.itemPut(w, r, section, name)
		case http.MethodDelete:
			s.itemDelete(w, r, section, name)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	}
}

func (s *Server) itemGet(w http.ResponseWriter, section, name string) {
	m := s.collectionMap(section)
	var entry crdt.MapEntry
	var found bool
	m.Range(func(key string, e crdt.MapEntry) bool {
		if key == name {
			entry = e
			found = true
			return false
		}
		return true
	})
	if !found {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	w.Header().Set("Etag", etagFor(entry.Stamp))
	writeJSON(w, http.StatusOK, itemView{
		Name: name, Section: section, Stamp: entry.Stamp, Payload: entry.Payload,
	})
}

func (s *Server) itemPut(w http.ResponseWriter, r *http.Request, section, name string) {
	body, err := readBody(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Body must be a JSON object; we copy the "name" key from the path
	// onto the payload so clients can omit it without ambiguity.
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

	if want := parseIfMatch(r); want != nil {
		_, ok, _ := s.collectionMap(section).Get(name, nil)
		if ok {
			// Compare against current stamp.
			var current crdt.MapEntry
			s.collectionMap(section).Range(func(key string, e crdt.MapEntry) bool {
				if key == name {
					current = e
					return false
				}
				return true
			})
			if current.Stamp.TS != want.TS || current.Stamp.Node != want.Node {
				writeError(w, http.StatusPreconditionFailed, "If-Match mismatch")
				return
			}
		}
	}

	// Build a tentative snapshot with the new entry applied to a clone
	// of the live map's data. We don't have a clone-store API, so we
	// instead optimistically apply, validate, and on failure roll back
	// by overwriting with the previous entry (or tombstoning if it
	// didn't exist).
	prevEntry, hadPrev := snapshotEntry(s.collectionMap(section), name)
	stamp, err := putSectionRaw(s.opts.Store, section, name, normalised)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	snap := s.opts.Store.Snapshot()
	if err := s.rebuildAndApply(snap, "admin "+section+" PUT "+name); err != nil {
		// Quarantine and roll back.
		s.opts.Quarantine.Push(section, name, err.Error())
		rollbackSectionRaw(s.opts.Store, section, name, hadPrev, prevEntry)
		writeError(w, http.StatusBadRequest, "rebuild failed: "+err.Error())
		return
	}
	s.broadcast(crdt.Delta{
		Section: section,
		Key:     name,
		Map: &crdt.MapEntry{
			Stamp:   stamp,
			Payload: normalised,
		},
	})

	w.Header().Set("Etag", etagFor(stamp))
	writeJSON(w, http.StatusOK, itemView{
		Name: name, Section: section, Stamp: stamp, Payload: normalised,
	})
}

func (s *Server) itemDelete(w http.ResponseWriter, r *http.Request, section, name string) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if want := parseIfMatch(r); want != nil {
		var current crdt.MapEntry
		s.collectionMap(section).Range(func(key string, e crdt.MapEntry) bool {
			if key == name {
				current = e
				return false
			}
			return true
		})
		if current.Stamp.TS != want.TS || current.Stamp.Node != want.Node {
			writeError(w, http.StatusPreconditionFailed, "If-Match mismatch")
			return
		}
	}

	prevEntry, hadPrev := snapshotEntry(s.collectionMap(section), name)
	stamp := deleteSection(s.opts.Store, section, name)

	snap := s.opts.Store.Snapshot()
	if err := s.rebuildAndApply(snap, "admin "+section+" DELETE "+name); err != nil {
		s.opts.Quarantine.Push(section, name, err.Error())
		rollbackSectionRaw(s.opts.Store, section, name, hadPrev, prevEntry)
		writeError(w, http.StatusBadRequest, "rebuild failed: "+err.Error())
		return
	}
	s.broadcast(crdt.Delta{
		Section: section,
		Key:     name,
		Map: &crdt.MapEntry{
			Stamp:     stamp,
			Tombstone: true,
		},
	})
	w.WriteHeader(http.StatusNoContent)
}

// handleRegister implements GET/PUT/DELETE /api/v1/{defaults,logging}.
func (s *Server) handleRegister(section string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			reg := s.registerOf(section)
			entry, ok := reg.Snapshot()
			if !ok || entry.Cleared {
				writeError(w, http.StatusNotFound, "not set via admin api")
				return
			}
			w.Header().Set("Etag", etagFor(entry.Stamp))
			writeJSON(w, http.StatusOK, map[string]any{
				"section": section,
				"stamp":   entry.Stamp,
				"payload": json.RawMessage(entry.Payload),
			})
		case http.MethodPut:
			s.registerPut(w, r, section)
		case http.MethodDelete:
			s.registerDelete(w, section)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	}
}

func (s *Server) registerOf(section string) *crdt.LWWRegister {
	switch section {
	case crdt.SectionDefaults:
		return s.opts.Store.Defaults
	case crdt.SectionLogging:
		return s.opts.Store.Logging
	}
	return nil
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

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	reg := s.registerOf(section)
	prevEntry, hadPrev := reg.Snapshot()

	stamp, err := setRegister(s.opts.Store, section, asMap)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	snap := s.opts.Store.Snapshot()
	if err := s.rebuildAndApply(snap, "admin "+section+" PUT"); err != nil {
		s.opts.Quarantine.Push(section, "", err.Error())
		rollbackRegister(reg, hadPrev, prevEntry)
		writeError(w, http.StatusBadRequest, "rebuild failed: "+err.Error())
		return
	}

	payload, _ := json.Marshal(asMap)
	s.broadcast(crdt.Delta{
		Section: section,
		Register: &crdt.RegisterEntry{
			Stamp:   stamp,
			Payload: payload,
		},
	})
	w.Header().Set("Etag", etagFor(stamp))
	writeJSON(w, http.StatusOK, map[string]any{
		"section": section,
		"stamp":   stamp,
		"payload": asMap,
	})
}

func (s *Server) registerDelete(w http.ResponseWriter, section string) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	reg := s.registerOf(section)
	prevEntry, hadPrev := reg.Snapshot()
	stamp := clearRegister(s.opts.Store, section)

	snap := s.opts.Store.Snapshot()
	if err := s.rebuildAndApply(snap, "admin "+section+" DELETE"); err != nil {
		s.opts.Quarantine.Push(section, "", err.Error())
		rollbackRegister(reg, hadPrev, prevEntry)
		writeError(w, http.StatusBadRequest, "rebuild failed: "+err.Error())
		return
	}
	s.broadcast(crdt.Delta{
		Section: section,
		Register: &crdt.RegisterEntry{
			Stamp:   stamp,
			Cleared: true,
		},
	})
	w.WriteHeader(http.StatusNoContent)
}

// handleConfig returns the effective compiled config currently
// serving traffic, in a JSON-safe form.
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	// We rebuild from the current YAML + CRDT instead of asking the
	// engine for its installed Config, so the response always
	// reflects what *would* serve right now (useful for debugging
	// concurrent reloads).
	cfg, err := policy.MergeFromYAML(s.opts.YAMLProvider(), s.opts.Store.Snapshot())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, configView(cfg))
}

// configView projects *policy.Config into JSON-friendly maps, dropping
// the compiled CEL programs and the facts registry.
func configView(cfg *policy.Config) map[string]any {
	groups := make([]map[string]any, 0, len(cfg.Groups))
	for _, g := range cfg.Groups {
		rules := make([]map[string]any, 0, len(g.Rules))
		for _, r := range g.Rules {
			rules = append(rules, map[string]any{
				"name":        r.Name,
				"description": r.Description,
				"action":      r.Action,
				"match":       r.Match,
				"fallthrough": r.Fallthrough,
				"dryRun":      r.DryRun,
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

func (s *Server) handleQuarantineList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": s.opts.Quarantine.List(),
	})
}

func (s *Server) handleQuarantineItem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/quarantine/")
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		writeError(w, http.StatusBadRequest, "missing section")
		return
	}
	section := parts[0]
	key := ""
	if len(parts) == 2 {
		key = parts[1]
	}
	if !s.opts.Quarantine.Remove(section, key) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- helpers ---

// readBody reads at most adminMaxBodyBytes from the request body and
// surfaces an explicit "body too large" error past that threshold so
// callers see a deterministic 400 instead of a partial JSON.
const adminMaxBodyBytes = 1 << 20

func readBody(r *http.Request) ([]byte, error) {
	if r.ContentLength > adminMaxBodyBytes {
		return nil, fmt.Errorf("body too large")
	}
	// LimitReader returns one extra byte if the source produced more
	// than the cap; we use that signal to convert overflow into a
	// 400-friendly error rather than silently truncating.
	buf, err := io.ReadAll(io.LimitReader(r.Body, adminMaxBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(buf)) > adminMaxBodyBytes {
		return nil, fmt.Errorf("body too large")
	}
	return buf, nil
}

func snapshotEntry(m *crdt.LWWMap, key string) (crdt.MapEntry, bool) {
	var out crdt.MapEntry
	var found bool
	m.Range(func(k string, e crdt.MapEntry) bool {
		if k == key {
			out = e
			found = true
			return false
		}
		return true
	})
	return out, found
}

func putSectionRaw(store *crdt.Store, section, name string, payload []byte) (crdt.Stamp, error) {
	switch section {
	case crdt.SectionGroups:
		var v any
		if err := json.Unmarshal(payload, &v); err != nil {
			return crdt.Stamp{}, err
		}
		return store.PutGroup(name, v)
	case crdt.SectionFacts:
		var v any
		if err := json.Unmarshal(payload, &v); err != nil {
			return crdt.Stamp{}, err
		}
		return store.PutFact(name, v)
	}
	return crdt.Stamp{}, fmt.Errorf("unknown section %q", section)
}

func deleteSection(store *crdt.Store, section, name string) crdt.Stamp {
	switch section {
	case crdt.SectionGroups:
		return store.DeleteGroup(name)
	case crdt.SectionFacts:
		return store.DeleteFact(name)
	}
	return crdt.Stamp{}
}

func rollbackSectionRaw(store *crdt.Store, section, name string, hadPrev bool, prev crdt.MapEntry) {
	m := selectMap(store, section)
	if m == nil {
		return
	}
	if hadPrev {
		m.PutRaw(name, prev)
	} else {
		// Insert a tombstone with the *current* (newer) stamp so the
		// transient Put we made before failing is overwritten.
		m.Delete(name, crdt.Stamp{TS: 1<<62, Node: store.Node()})
	}
}

func selectMap(store *crdt.Store, section string) *crdt.LWWMap {
	switch section {
	case crdt.SectionGroups:
		return store.Groups
	case crdt.SectionFacts:
		return store.Facts
	}
	return nil
}

func setRegister(store *crdt.Store, section string, value any) (crdt.Stamp, error) {
	switch section {
	case crdt.SectionDefaults:
		return store.SetDefaults(value)
	case crdt.SectionLogging:
		return store.SetLogging(value)
	}
	return crdt.Stamp{}, fmt.Errorf("unknown section %q", section)
}

func clearRegister(store *crdt.Store, section string) crdt.Stamp {
	switch section {
	case crdt.SectionDefaults:
		return store.ClearDefaults()
	case crdt.SectionLogging:
		return store.ClearLogging()
	}
	return crdt.Stamp{}
}

func rollbackRegister(reg *crdt.LWWRegister, hadPrev bool, prev crdt.RegisterEntry) {
	if hadPrev {
		reg.SetRaw(prev)
		return
	}
	reg.SetRaw(crdt.RegisterEntry{Stamp: crdt.Stamp{TS: 1<<62, Node: "_rollback"}, Cleared: true})
}

func (s *Server) broadcast(d crdt.Delta) {
	if s.opts.Broadcaster == nil {
		return
	}
	s.opts.Broadcaster.BroadcastDelta(d)
}
