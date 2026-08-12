package tests

// End-to-end cover for the flows the data flow diagram draws: a field device
// publishes over mqtts to the Ingest API, the reading lands in the Telemetry
// DB, and an operator reads it back from the Dashboard API over https.
//
// The diagram in the README is generated from the model, so it always matches
// the model. This is what makes it match the product.

import (
	"net/http"
	"testing"
	"time"

	"github.com/threatcl/enisa-sbd-example/internal/authn"
	"github.com/threatcl/enisa-sbd-example/internal/dashboard"
	"github.com/threatcl/enisa-sbd-example/internal/ingest"
)

func TestDeviceTelemetryReachesTheDashboard(t *testing.T) {
	st := enrolledFleet(t)
	h := startIngest(t, st)
	tokens := tokenStore(t, credential(operatorToken, "olive@northwind.example", northwind, authn.RoleOperator))
	api := serve(t, dashboard.Handler(st, tokens, discardLogger()))

	cert := h.deviceCA.issue(t, certOpts{commonName: enrolledDevice})
	d, err := h.dial(t, &cert)
	if err != nil {
		t.Fatalf("device could not connect to ingest: %v", err)
	}
	if err := d.publish(ingest.TopicFor(enrolledDevice), map[string]any{
		"metric": "battery_pct",
		"value":  87.25,
		"at":     time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		t.Fatalf("device could not publish telemetry: %v", err)
	}

	resp, body := call(t, api, http.MethodGet, "/api/devices/"+enrolledDevice+"/telemetry", operatorToken, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET telemetry = %d, want 200", resp.StatusCode)
	}
	readings := decode[telemetryResponse](t, body).Readings
	if len(readings) != 1 {
		t.Fatalf("dashboard returned %d readings, want the 1 the device published", len(readings))
	}
	if readings[0].Value != 87.25 || readings[0].Metric != "battery_pct" {
		t.Fatalf("dashboard returned %+v, want the published sample", readings[0])
	}

	// The fleet view should show the device as having been seen just now.
	resp, body = call(t, api, http.MethodGet, "/api/fleet", operatorToken, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/fleet = %d, want 200", resp.StatusCode)
	}
	if devices := decode[fleetResponse](t, body).Devices; len(devices) != 1 {
		t.Fatalf("fleet view shows %d devices, want 1", len(devices))
	}
}
