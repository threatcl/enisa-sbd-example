// Package authz enforces SensorHub's server-side authorisation.
//
// It implements the control named in threat "operator_escalates_to_admin"
// (threatmodel/sensorhub.tm.hcl): "Authorisation middleware denies by default:
// a route with no explicit role grant is unreachable."
//
// Default-deny here is structural rather than conventional. Handle takes the
// grant as a required argument, so a route cannot be registered without one -
// the omission is a compile error. Passing an empty grant panics at
// registration, which means startup, which means CI. There is no code path
// that reaches a handler without first resolving an identity and checking it
// against that route's grant.
package authz

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"slices"

	"github.com/threatcl/enisa-sbd-example/internal/authn"
)

// Route is a registered endpoint and the grant guarding it. Routes is the
// basis of the conformance test asserting every route carries a grant.
type Route struct {
	Pattern string
	Allow   []authn.Role
	Public  bool
}

// Router is an http.Handler that authenticates every request and authorises it
// against the grant declared when the route was registered.
type Router struct {
	mux    *http.ServeMux
	tokens *authn.Store
	log    *slog.Logger
	routes []Route
}

type contextKey struct{}

// New returns an empty router. Patterns use net/http's method-aware syntax,
// e.g. "GET /api/fleet", so a grant covers one method rather than a path.
func New(tokens *authn.Store, log *slog.Logger) *Router {
	if log == nil {
		log = slog.Default()
	}
	return &Router{mux: http.NewServeMux(), tokens: tokens, log: log}
}

// Handle registers a route behind an explicit role grant.
//
// It panics if allow is empty. A route with no grant is a route that is open
// to every authenticated caller, which is exactly the failure this package
// exists to prevent, so it fails at startup rather than shipping.
func (rt *Router) Handle(pattern string, allow []authn.Role, h http.Handler) {
	if len(allow) == 0 {
		panic("authz: route " + pattern + " registered with no role grant; name the roles allowed to reach it, or use HandlePublic and add it to the public allowlist")
	}
	for _, role := range allow {
		if !role.Valid() {
			panic("authz: route " + pattern + " grants unknown role " + string(role))
		}
	}
	rt.routes = append(rt.routes, Route{Pattern: pattern, Allow: slices.Clone(allow)})
	rt.mux.Handle(pattern, rt.guard(pattern, allow, h))
}

// HandleFunc is Handle for a plain function.
func (rt *Router) HandleFunc(pattern string, allow []authn.Role, h http.HandlerFunc) {
	rt.Handle(pattern, allow, h)
}

// HandlePublic registers a route reachable without a credential.
//
// Deliberately a separate method rather than a magic "anyone" role: an
// unauthenticated route is an exception, and exceptions should be greppable.
// Routes reports these with Public set, and tests/api_rbac_test.go asserts the
// set of public routes matches a fixed allowlist - so adding a second one
// fails CI until someone amends the list on purpose.
func (rt *Router) HandlePublic(pattern string, h http.Handler) {
	rt.routes = append(rt.routes, Route{Pattern: pattern, Public: true})
	rt.mux.Handle(pattern, h)
}

// Routes returns the registered routes in registration order.
func (rt *Router) Routes() []Route {
	return slices.Clone(rt.routes)
}

func (rt *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rt.mux.ServeHTTP(w, r)
}

func (rt *Router) guard(pattern string, allow []authn.Role, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := authn.BearerToken(r)
		if !ok {
			rt.deny(w, r, pattern, "", http.StatusUnauthorized, "no bearer credential")
			return
		}
		id, ok := rt.tokens.Lookup(token)
		if !ok {
			rt.deny(w, r, pattern, "", http.StatusUnauthorized, "unrecognised credential")
			return
		}
		if !slices.Contains(allow, id.Role) {
			rt.deny(w, r, pattern, id.Subject, http.StatusForbidden, "role "+string(id.Role)+" not granted")
			return
		}
		h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), contextKey{}, id)))
	})
}

// deny writes a terse refusal and records it. The response body never explains
// which check failed - an unauthorised caller should not learn whether a route
// exists, only that they cannot have it.
func (rt *Router) deny(w http.ResponseWriter, r *http.Request, pattern, subject string, status int, reason string) {
	rt.log.Warn("request denied",
		"route", pattern,
		"subject", subject,
		"status", status,
		"reason", reason,
		"remote", r.RemoteAddr,
	)
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer realm="sensorhub"`)
	}
	WriteJSON(w, status, map[string]string{"error": http.StatusText(status)})
}

// Caller returns the authenticated identity attached to a request context by
// the router. The second result is false on public routes.
func Caller(ctx context.Context) (authn.Identity, bool) {
	id, ok := ctx.Value(contextKey{}).(authn.Identity)
	return id, ok
}

// WriteJSON writes a JSON response with no-store caching, shared by the two
// API services so their error shapes cannot drift apart.
func WriteJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
