package tests

// Verification for the control "Tenant scoping enforced in the data layer" on
// threat "cross_tenant_telemetry_read" in threatmodel/sensorhub.tm.hcl.
//
// The model's claim is structural: "Every fleet query is scoped by
// organisation id at the repository layer, not per-handler. A query built
// without a tenant scope fails to compile rather than returning unscoped
// rows." So there are two tests here - one across the HTTP boundary, one
// against the repository itself, because that is where the control lives.

import (
	"net/http"
	"testing"
	"time"

	"github.com/threatcl/enisa-sbd-example/internal/authn"
	"github.com/threatcl/enisa-sbd-example/internal/dashboard"
	"github.com/threatcl/enisa-sbd-example/internal/store"
)

const (
	contoso        = "contoso"
	contosoDevice  = "dev-contoso-001"
	contosoToken   = "test-operator-token-contoso"
	contosoSubject = "carla@contoso.example"
)

type fleetResponse struct {
	Devices []struct {
		ID string `json:"id"`
	} `json:"devices"`
}

type telemetryResponse struct {
	Readings []store.Reading `json:"readings"`
}

// twoTenants seeds one device per organisation, each with a reading.
func twoTenants(t *testing.T) *store.Store {
	t.Helper()
	st := enrolledFleet(t)
	if err := st.Enrol(store.Device{ID: contosoDevice, OrgID: contoso, Model: "SH-2"}); err != nil {
		t.Fatalf("enrolling contoso device: %v", err)
	}
	for _, id := range []string{enrolledDevice, contosoDevice} {
		if err := st.RecordReading(id, store.Reading{Metric: "site_lat", Value: 51.5, At: time.Now()}); err != nil {
			t.Fatalf("recording reading for %s: %v", id, err)
		}
	}
	return st
}

// TestFleetQueryAcrossOrgsReturnsEmpty is the negative test named by the model.
func TestFleetQueryAcrossOrgsReturnsEmpty(t *testing.T) {
	st := twoTenants(t)
	tokens := tokenStore(t,
		credential(operatorToken, "olive@northwind.example", northwind, authn.RoleOperator),
		credential(contosoToken, contosoSubject, contoso, authn.RoleOperator),
	)
	srv := serve(t, dashboard.Handler(st, tokens, discardLogger()))

	// A northwind operator sees northwind's fleet and nothing else, even
	// though contoso's devices are rows in the same store.
	resp, body := call(t, srv, http.MethodGet, "/api/fleet", operatorToken, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/fleet = %d, want 200", resp.StatusCode)
	}
	fleet := decode[fleetResponse](t, body)
	if len(fleet.Devices) != 1 || fleet.Devices[0].ID != enrolledDevice {
		t.Fatalf("northwind operator sees %v, want only [%s]", fleet.Devices, enrolledDevice)
	}
	t.Logf("northwind fleet query returned only northwind devices: %v", fleet.Devices)

	// Naming another tenant's device id directly is the same query with the
	// predicate supplied by the attacker. It returns nothing - and returns
	// nothing in the same shape as an unknown device, so the response cannot
	// be used to discover which device ids exist in other tenants.
	resp, body = call(t, srv, http.MethodGet, "/api/devices/"+contosoDevice+"/telemetry", operatorToken, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET another tenant's telemetry = %d, want 200 with no rows", resp.StatusCode)
	}
	if got := decode[telemetryResponse](t, body); len(got.Readings) != 0 {
		t.Fatalf("northwind operator read %d of contoso's readings across the tenant boundary", len(got.Readings))
	}
	t.Logf("refused, as required: northwind operator reading %s -> 0 readings", contosoDevice)

	_, unknown := call(t, srv, http.MethodGet, "/api/devices/dev-does-not-exist/telemetry", operatorToken, nil)
	if string(unknown) != string(body) {
		t.Errorf("another tenant's device answers differently from an unknown one:\n cross-tenant: %s\n unknown:      %s", body, unknown)
	}

	// And contoso's own operator still sees contoso's reading, so the isolation
	// above is scoping rather than an empty store.
	resp, body = call(t, srv, http.MethodGet, "/api/devices/"+contosoDevice+"/telemetry", contosoToken, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("contoso operator reading their own device = %d, want 200", resp.StatusCode)
	}
	if got := decode[telemetryResponse](t, body); len(got.Readings) != 1 {
		t.Fatalf("contoso operator sees %d of their own readings, want 1", len(got.Readings))
	}
}

// TestRepositoryRefusesAnUnscopedQuery exercises the control where it is
// implemented. store.Scope is an interface with an unexported method, so no
// caller outside the store package can construct one; the only remaining way
// to reach a query without a tenant is to pass nil, and that is refused.
func TestRepositoryRefusesAnUnscopedQuery(t *testing.T) {
	st := twoTenants(t)

	if _, err := st.Fleet(nil); err != store.ErrNoScope {
		t.Errorf("Fleet(nil) error = %v, want ErrNoScope", err)
	}
	if _, err := st.Readings(nil, enrolledDevice, 10); err != store.ErrNoScope {
		t.Errorf("Readings(nil, ...) error = %v, want ErrNoScope", err)
	}
	if _, err := st.Audit(nil, ""); err != store.ErrNoScope {
		t.Errorf("Audit(nil, ...) error = %v, want ErrNoScope", err)
	}

	// A credential with no organisation cannot be turned into a scope either,
	// so an identity that slips through with an empty tenant reads nothing
	// rather than everything.
	if _, err := store.ScopeFor(authn.Identity{Subject: "nobody", Role: authn.RoleAdmin}); err != store.ErrNoScope {
		t.Errorf("ScopeFor(identity with no org) error = %v, want ErrNoScope", err)
	}
	t.Log("refused, as required: every read path rejects a query with no tenant scope")
}
