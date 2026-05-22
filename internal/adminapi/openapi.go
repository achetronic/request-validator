// Package adminapi - OpenAPI 3.1 documentation.
//
// The handler functions below are NEVER invoked at runtime. They
// exist solely as a target for swaggo/swag v2 annotations so the
// generated openapi.json is kept next to the code it describes.
//
// The real handlers live in routes.go and dispatch through closures
// returned by handleCollection / handleItem / handleRegister; swag
// would have a hard time discovering rules vs collections via that
// shape, so we keep the documentation as small, explicit stubs.
//
// Regenerate the spec after any change with:
//
//   make swagger
//
//go:build !nodocs

package adminapi

import "net/http"

// docDelete is a no-op signature reused by the DELETE doc stubs.
func docDelete(_ http.ResponseWriter, _ *http.Request) {}

// docGet is a no-op signature reused by the GET doc stubs.
func docGet(_ http.ResponseWriter, _ *http.Request) {}

// docPut is a no-op signature reused by the PUT doc stubs.
func docPut(_ http.ResponseWriter, _ *http.Request) {}

// listGroupsDoc documents GET /api/v1/groups.
//
//	@Summary		List CRDT-managed groups
//	@Description	Returns every group currently held in the CRDT store on this node. YAML-only groups are NOT included; use GET /api/v1/config for the merged effective view.
//	@Tags			groups
//	@Produce		json
//	@Security		BearerAuth
//	@Success		200	{object}	ItemListResponse
//	@Failure		401	{object}	ErrorResponse	"missing or invalid bearer token"
//	@Router			/api/v1/groups [get]
func listGroupsDoc(w http.ResponseWriter, r *http.Request) { docGet(w, r) }

// getGroupDoc documents GET /api/v1/groups/{name}.
//
//	@Summary		Get a single CRDT-managed group
//	@Tags			groups
//	@Produce		json
//	@Security		BearerAuth
//	@Param			name	path		string	true	"group name"
//	@Success		200		{object}	ItemResponse
//	@Header			200		{string}	Etag	"opaque concurrency token (\"<ts>-<node>\")"
//	@Failure		401		{object}	ErrorResponse
//	@Failure		404		{object}	ErrorResponse
//	@Router			/api/v1/groups/{name} [get]
func getGroupDoc(w http.ResponseWriter, r *http.Request) { docGet(w, r) }

// putGroupDoc documents PUT /api/v1/groups/{name}.
//
//	@Summary		Upsert a group
//	@Description	Replaces the group with the given name. The whole effective config is recompiled; if validation fails the live policy is untouched and the offending entry is pushed to the local quarantine.
//	@Tags			groups
//	@Accept			json
//	@Produce		json
//	@Security		BearerAuth
//	@Param			name		path		string			true	"group name (must match body.name when present)"
//	@Param			If-Match	header		string			false	"opaque concurrency token from a previous response"
//	@Param			body		body		GroupRequest	true	"group payload, same shape as a YAML group entry"
//	@Success		200			{object}	ItemResponse
//	@Header			200			{string}	Etag			"new concurrency token"
//	@Failure		400			{object}	ErrorResponse	"validation/compile failed; entry quarantined"
//	@Failure		401			{object}	ErrorResponse
//	@Failure		412			{object}	ErrorResponse	"If-Match did not match the live stamp"
//	@Router			/api/v1/groups/{name} [put]
func putGroupDoc(w http.ResponseWriter, r *http.Request) { docPut(w, r) }

// deleteGroupDoc documents DELETE /api/v1/groups/{name}.
//
//	@Summary		Delete a group
//	@Description	Writes a tombstone. If a YAML group with the same name exists, it is hidden by the tombstone until the YAML entry is also removed.
//	@Tags			groups
//	@Security		BearerAuth
//	@Param			name		path	string	true	"group name"
//	@Param			If-Match	header	string	false	"opaque concurrency token"
//	@Success		204			"deleted"
//	@Failure		401			{object}	ErrorResponse
//	@Failure		412			{object}	ErrorResponse	"If-Match did not match the live stamp"
//	@Router			/api/v1/groups/{name} [delete]
func deleteGroupDoc(w http.ResponseWriter, r *http.Request) { docDelete(w, r) }

// listFactsDoc documents GET /api/v1/facts.
//
//	@Summary		List CRDT-managed facts
//	@Tags			facts
//	@Produce		json
//	@Security		BearerAuth
//	@Success		200	{object}	ItemListResponse
//	@Failure		401	{object}	ErrorResponse
//	@Router			/api/v1/facts [get]
func listFactsDoc(w http.ResponseWriter, r *http.Request) { docGet(w, r) }

// getFactDoc documents GET /api/v1/facts/{name}.
//
//	@Summary		Get a single fact
//	@Tags			facts
//	@Produce		json
//	@Security		BearerAuth
//	@Param			name	path		string	true	"fact name"
//	@Success		200		{object}	ItemResponse
//	@Failure		401		{object}	ErrorResponse
//	@Failure		404		{object}	ErrorResponse
//	@Router			/api/v1/facts/{name} [get]
func getFactDoc(w http.ResponseWriter, r *http.Request) { docGet(w, r) }

// putFactDoc documents PUT /api/v1/facts/{name}.
//
//	@Summary		Upsert a fact
//	@Description	Same semantics as a YAML facts entry. URL facts spin up a fetcher on the next rebuild; the previous fetcher (if any) is stopped first.
//	@Tags			facts
//	@Accept			json
//	@Produce		json
//	@Security		BearerAuth
//	@Param			name		path		string			true	"fact name"
//	@Param			If-Match	header		string			false	"opaque concurrency token"
//	@Param			body		body		FactRequest		true	"fact payload"
//	@Success		200			{object}	ItemResponse
//	@Failure		400			{object}	ErrorResponse
//	@Failure		401			{object}	ErrorResponse
//	@Failure		412			{object}	ErrorResponse
//	@Router			/api/v1/facts/{name} [put]
func putFactDoc(w http.ResponseWriter, r *http.Request) { docPut(w, r) }

// deleteFactDoc documents DELETE /api/v1/facts/{name}.
//
//	@Summary		Delete a fact
//	@Tags			facts
//	@Security		BearerAuth
//	@Param			name		path	string	true	"fact name"
//	@Param			If-Match	header	string	false	"opaque concurrency token"
//	@Success		204			"deleted"
//	@Failure		401			{object}	ErrorResponse
//	@Failure		412			{object}	ErrorResponse
//	@Router			/api/v1/facts/{name} [delete]
func deleteFactDoc(w http.ResponseWriter, r *http.Request) { docDelete(w, r) }

// getDefaultsDoc documents GET /api/v1/defaults.
//
//	@Summary		Get the API-managed defaults overlay
//	@Description	Returns 404 when no admin override is set; in that case the YAML defaults are in effect.
//	@Tags			defaults
//	@Produce		json
//	@Security		BearerAuth
//	@Success		200	{object}	RegisterResponse
//	@Failure		401	{object}	ErrorResponse
//	@Failure		404	{object}	ErrorResponse	"not set via admin api"
//	@Router			/api/v1/defaults [get]
func getDefaultsDoc(w http.ResponseWriter, r *http.Request) { docGet(w, r) }

// putDefaultsDoc documents PUT /api/v1/defaults.
//
//	@Summary		Override the defaults block
//	@Description	Per-field overlay over the YAML defaults. Any field omitted from the body keeps its YAML value.
//	@Tags			defaults
//	@Accept			json
//	@Produce		json
//	@Security		BearerAuth
//	@Param			body	body		DefaultsRequest	true	"fields to override"
//	@Success		200		{object}	RegisterResponse
//	@Failure		400		{object}	ErrorResponse
//	@Failure		401		{object}	ErrorResponse
//	@Router			/api/v1/defaults [put]
func putDefaultsDoc(w http.ResponseWriter, r *http.Request) { docPut(w, r) }

// deleteDefaultsDoc documents DELETE /api/v1/defaults.
//
//	@Summary		Clear the defaults overlay
//	@Description	After this call the YAML defaults are the effective ones again.
//	@Tags			defaults
//	@Security		BearerAuth
//	@Success		204
//	@Failure		401	{object}	ErrorResponse
//	@Router			/api/v1/defaults [delete]
func deleteDefaultsDoc(w http.ResponseWriter, r *http.Request) { docDelete(w, r) }

// getLoggingDoc documents GET /api/v1/logging.
//
//	@Summary		Get the API-managed logging overlay
//	@Tags			logging
//	@Produce		json
//	@Security		BearerAuth
//	@Success		200	{object}	RegisterResponse
//	@Failure		401	{object}	ErrorResponse
//	@Failure		404	{object}	ErrorResponse	"not set via admin api"
//	@Router			/api/v1/logging [get]
func getLoggingDoc(w http.ResponseWriter, r *http.Request) { docGet(w, r) }

// putLoggingDoc documents PUT /api/v1/logging.
//
//	@Summary		Override the logging block
//	@Tags			logging
//	@Accept			json
//	@Produce		json
//	@Security		BearerAuth
//	@Param			body	body		LoggingRequest	true	"fields to override"
//	@Success		200		{object}	RegisterResponse
//	@Failure		400		{object}	ErrorResponse
//	@Failure		401		{object}	ErrorResponse
//	@Router			/api/v1/logging [put]
func putLoggingDoc(w http.ResponseWriter, r *http.Request) { docPut(w, r) }

// deleteLoggingDoc documents DELETE /api/v1/logging.
//
//	@Summary		Clear the logging overlay
//	@Tags			logging
//	@Security		BearerAuth
//	@Success		204
//	@Failure		401	{object}	ErrorResponse
//	@Router			/api/v1/logging [delete]
func deleteLoggingDoc(w http.ResponseWriter, r *http.Request) { docDelete(w, r) }

// getConfigDoc documents GET /api/v1/config.
//
//	@Summary		Effective compiled policy
//	@Description	Returns the policy the engine would evaluate right now (YAML floor + CRDT overrides), with sources annotated per group.
//	@Tags			config
//	@Produce		json
//	@Security		BearerAuth
//	@Success		200	{object}	ConfigResponse
//	@Failure		401	{object}	ErrorResponse
//	@Failure		500	{object}	ErrorResponse	"merge or compile failed"
//	@Router			/api/v1/config [get]
func getConfigDoc(w http.ResponseWriter, r *http.Request) { docGet(w, r) }

// listQuarantineDoc documents GET /api/v1/quarantine.
//
//	@Summary		List quarantined CRDT entries
//	@Description	Per-node view: each replica may legitimately quarantine different items depending on its current state. Items are re-evaluated on every rebuild.
//	@Tags			quarantine
//	@Produce		json
//	@Security		BearerAuth
//	@Success		200	{object}	QuarantineListResponse
//	@Failure		401	{object}	ErrorResponse
//	@Router			/api/v1/quarantine [get]
func listQuarantineDoc(w http.ResponseWriter, r *http.Request) { docGet(w, r) }

// deleteQuarantineDoc documents DELETE /api/v1/quarantine/{section}/{name}.
//
//	@Summary		Drop a quarantined entry without retry
//	@Description	The CRDT entry itself is NOT removed (it remains the source of truth); only the local quarantine buffer is cleared for this key.
//	@Tags			quarantine
//	@Security		BearerAuth
//	@Param			section	path	string	true	"groups|facts|defaults|logging"
//	@Param			name	path	string	false	"key name (empty for singleton sections)"
//	@Success		204
//	@Failure		401	{object}	ErrorResponse
//	@Failure		404	{object}	ErrorResponse
//	@Router			/api/v1/quarantine/{section}/{name} [delete]
func deleteQuarantineDoc(w http.ResponseWriter, r *http.Request) { docDelete(w, r) }

// openAPIDoc documents GET /api/v1/openapi.json.
//
//	@Summary		OpenAPI 3.1 specification of this admin API
//	@Description	Returns the generated openapi.json. Useful for client codegen.
//	@Tags			meta
//	@Produce		json
//	@Security		BearerAuth
//	@Success		200	{object}	map[string]any
//	@Failure		401	{object}	ErrorResponse
//	@Router			/api/v1/openapi.json [get]
func openAPIDoc(w http.ResponseWriter, r *http.Request) { docGet(w, r) }
