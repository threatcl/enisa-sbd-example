// Package dashboard is the Dashboard API process: the read side of the
// product, reachable by operators and admins from the internet trust zone over
// the "fleet dashboard" flow (https).
//
// Every handler here is one line of scoping followed by a repository call.
// That is the point: the tenant-tenant boundary from threat
// "cross_tenant_telemetry_read" is held in internal/store, so a handler cannot
// forget it - see store.Scope.
package dashboard

import (
	"log/slog"
	"net/http"
	"strconv"

	"github.com/threatcl/enisa-sbd-example/internal/authn"
	"github.com/threatcl/enisa-sbd-example/internal/authz"
	"github.com/threatcl/enisa-sbd-example/internal/store"
)

const defaultReadingLimit = 100

// Fleet views are readable by both roles. Admins are not implicitly operators
// anywhere in this service: every grant lists the roles it allows, so
// widening one is a diff rather than an inherited side effect.
var fleetReaders = []authn.Role{authn.RoleOperator, authn.RoleAdmin}

// Handler builds the Dashboard API's routes.
func Handler(st *store.Store, tokens *authn.Store, log *slog.Logger) *authz.Router {
	if log == nil {
		log = slog.Default()
	}
	s := &service{store: st, log: log}
	r := authz.New(tokens, log)

	r.HandleFunc("GET /api/fleet", fleetReaders, s.fleet)
	r.HandleFunc("GET /api/devices/{id}/telemetry", fleetReaders, s.telemetry)
	r.HandlePublic("GET /healthz", http.HandlerFunc(health))

	return r
}

type service struct {
	store *store.Store
	log   *slog.Logger
}

func (s *service) fleet(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.scope(w, r)
	if !ok {
		return
	}
	devices, err := s.store.Fleet(scope)
	if err != nil {
		s.fail(w, r, "listing fleet", err)
		return
	}
	authz.WriteJSON(w, http.StatusOK, map[string]any{"devices": devices})
}

func (s *service) telemetry(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.scope(w, r)
	if !ok {
		return
	}
	limit := defaultReadingLimit
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			authz.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "limit must be a positive integer"})
			return
		}
		limit = n
	}
	// A device belonging to another organisation yields no readings and no
	// error, so this response cannot be used to probe for device ids in other
	// tenants.
	readings, err := s.store.Readings(scope, r.PathValue("id"), limit)
	if err != nil {
		s.fail(w, r, "reading telemetry", err)
		return
	}
	if readings == nil {
		readings = []store.Reading{}
	}
	authz.WriteJSON(w, http.StatusOK, map[string]any{"readings": readings})
}

func health(w http.ResponseWriter, _ *http.Request) {
	authz.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// scope derives the caller's tenant scope, which is the only way to reach data
// in this service.
func (s *service) scope(w http.ResponseWriter, r *http.Request) (store.Scope, bool) {
	id, ok := authz.Caller(r.Context())
	if !ok {
		// Unreachable through the router, which authenticates before any
		// handler runs. Kept as a fail-closed backstop in case a handler is
		// ever mounted somewhere else.
		s.log.Error("handler reached with no caller identity", "path", r.URL.Path)
		authz.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
		return nil, false
	}
	scope, err := store.ScopeFor(id)
	if err != nil {
		s.log.Error("caller has no organisation", "subject", id.Subject)
		authz.WriteJSON(w, http.StatusForbidden, map[string]string{"error": "Forbidden"})
		return nil, false
	}
	return scope, true
}

func (s *service) fail(w http.ResponseWriter, r *http.Request, what string, err error) {
	s.log.Error("dashboard request failed", "what", what, "path", r.URL.Path, "err", err)
	authz.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "Internal Server Error"})
}
