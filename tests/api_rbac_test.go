package tests

// Verification for the control "Server-side RBAC enforced per route" on threat
// "operator_escalates_to_admin" in threatmodel/sensorhub.tm.hcl.
//
// The model claims two things. First, that admin routes refuse operator tokens
// server-side "regardless of what the UI offers" - TestOperatorTokenOnAdminRouteIs403.
// Second, that "the default-deny behaviour is itself tested, so a newly added
// route without a grant fails CI rather than shipping open" - the two
// conformance tests at the bottom of this file. The second claim is the one
// that keeps holding after everyone who wrote this has moved on.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"testing"

	"github.com/threatcl/enisa-sbd-example/internal/authn"
	"github.com/threatcl/enisa-sbd-example/internal/authz"
	"github.com/threatcl/enisa-sbd-example/internal/dashboard"
	"github.com/threatcl/enisa-sbd-example/internal/rollout"
	"github.com/threatcl/enisa-sbd-example/internal/store"
)

const (
	operatorToken = "test-operator-token-northwind"
	adminToken    = "test-admin-token-northwind"
)

// publicRoutes is the complete list of endpoints reachable without a
// credential, across every service. Adding an unauthenticated route means
// amending this list in a diff someone reviews.
var publicRoutes = map[string]bool{
	"GET /healthz": true,
}

// recordingPublisher stands in for the firmware CDN.
type recordingPublisher struct {
	mu        sync.Mutex
	published []rollout.Manifest
	err       error
}

func (p *recordingPublisher) Publish(_ context.Context, m rollout.Manifest) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return p.err
	}
	p.published = append(p.published, m)
	return nil
}

func (p *recordingPublisher) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.published)
}

func northwindTokens(t *testing.T) *authn.Store {
	t.Helper()
	return tokenStore(t,
		credential(operatorToken, "olive@northwind.example", northwind, authn.RoleOperator),
		credential(adminToken, "adam@northwind.example", northwind, authn.RoleAdmin),
	)
}

// signedRelease builds a manifest signed by a freshly generated release key,
// alongside the public key the service should pin.
func signedRelease(t *testing.T, version string) (ed25519.PublicKey, rollout.Manifest) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating release key: %v", err)
	}
	digest := sha256.Sum256([]byte("sensorhub firmware " + version))
	return pub, rollout.Sign(priv, rollout.Manifest{
		Version: version,
		Digest:  fmt.Sprintf("sha256:%x", digest),
	})
}

func manifestBody(t *testing.T, m rollout.Manifest) *bytes.Reader {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("encoding manifest: %v", err)
	}
	return bytes.NewReader(raw)
}

// TestOperatorTokenOnAdminRouteIs403 is the negative test named by the model.
func TestOperatorTokenOnAdminRouteIs403(t *testing.T) {
	key, manifest := signedRelease(t, "1.4.1")
	cdn := &recordingPublisher{}
	srv := serve(t, rollout.Handler(store.New(), northwindTokens(t), key, cdn, discardLogger()))

	// An operator holds a valid credential. It is simply not one that reaches
	// the firmware rollout path.
	resp, body := call(t, srv, http.MethodPost, "/api/rollouts", operatorToken, manifestBody(t, manifest))
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("POST /api/rollouts as operator = %d, want 403 - an operator can reach admin firmware rollout", resp.StatusCode)
	}
	t.Logf("refused, as required: operator token on POST /api/rollouts -> 403 %s", bytes.TrimSpace(body))

	if resp, _ := call(t, srv, http.MethodGet, "/api/rollouts", operatorToken, nil); resp.StatusCode != http.StatusForbidden {
		t.Errorf("GET /api/rollouts as operator = %d, want 403", resp.StatusCode)
	}
	if n := cdn.count(); n != 0 {
		t.Fatalf("a refused operator still published %d releases to the CDN", n)
	}

	// The same request as an admin must succeed, otherwise the 403 above would
	// prove nothing more than a broken route.
	resp, body = call(t, srv, http.MethodPost, "/api/rollouts", adminToken, manifestBody(t, manifest))
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("POST /api/rollouts as admin = %d (%s), want 202", resp.StatusCode, bytes.TrimSpace(body))
	}
	if n := cdn.count(); n != 1 {
		t.Fatalf("admin rollout published %d releases, want 1", n)
	}
}

// TestUnauthenticatedRequestIsRefused covers the deny-by-default case that
// precedes any role check.
func TestUnauthenticatedRequestIsRefused(t *testing.T) {
	key, _ := signedRelease(t, "1.4.1")
	tokens := northwindTokens(t)
	services := map[string]http.Handler{
		"dashboard": dashboard.Handler(store.New(), tokens, discardLogger()),
		"rollout":   rollout.Handler(store.New(), tokens, key, &recordingPublisher{}, discardLogger()),
	}
	paths := map[string]string{"dashboard": "/api/fleet", "rollout": "/api/rollouts"}

	for name, h := range services {
		srv := serve(t, h)
		for _, token := range []string{"", "not-a-real-token"} {
			resp, _ := call(t, srv, http.MethodGet, paths[name], token, nil)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("%s %s with token %q = %d, want 401", name, paths[name], token, resp.StatusCode)
			}
			if got := resp.Header.Get("WWW-Authenticate"); got == "" {
				t.Errorf("%s 401 response omits WWW-Authenticate", name)
			}
		}
		// The public route stays public, or the health check is a false alarm.
		if resp, _ := call(t, srv, http.MethodGet, "/healthz", "", nil); resp.StatusCode != http.StatusOK {
			t.Errorf("%s GET /healthz unauthenticated = %d, want 200", name, resp.StatusCode)
		}
	}
}

// TestEveryRegisteredRouteCarriesARoleGrant is the conformance check behind the
// model's claim that a new route cannot ship open. It walks what the services
// actually registered rather than a list maintained by hand.
func TestEveryRegisteredRouteCarriesARoleGrant(t *testing.T) {
	key, _ := signedRelease(t, "1.4.1")
	tokens := northwindTokens(t)
	routers := map[string]*authz.Router{
		"dashboard": dashboard.Handler(store.New(), tokens, discardLogger()),
		"rollout":   rollout.Handler(store.New(), tokens, key, &recordingPublisher{}, discardLogger()),
	}

	total := 0
	for service, r := range routers {
		routes := r.Routes()
		if len(routes) == 0 {
			t.Fatalf("%s registered no routes; this test would pass vacuously", service)
		}
		for _, route := range routes {
			total++
			switch {
			case route.Public && !publicRoutes[route.Pattern]:
				t.Errorf("%s exposes %q with no credential required, and it is not on the public allowlist in this file", service, route.Pattern)
			case !route.Public && len(route.Allow) == 0:
				t.Errorf("%s route %q has no role grant", service, route.Pattern)
			default:
				t.Logf("%-9s %-35s %v", service, route.Pattern, grantOf(route))
			}
		}
	}
	if total < len(routers)*2 {
		t.Errorf("only %d routes registered across %d services; expected more", total, len(routers))
	}
}

func grantOf(r authz.Route) any {
	if r.Public {
		return "public (allowlisted)"
	}
	return r.Allow
}

// TestRegisteringARouteWithoutAGrantPanics pins the mechanism the test above
// relies on. A grant is a required argument, so omitting one does not compile;
// this covers the remaining case of passing an empty one.
func TestRegisteringARouteWithoutAGrantPanics(t *testing.T) {
	r := authz.New(northwindTokens(t), discardLogger())

	defer func() {
		recovered := recover()
		if recovered == nil {
			t.Fatal("registering a route with an empty grant was allowed; a route with no grant must fail at startup")
		}
		t.Logf("refused, as required: %v", recovered)
	}()

	r.Handle("GET /api/whatever", nil, http.NotFoundHandler())
}
