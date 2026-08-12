package tests

// Cover for the fleet CSV export on the Dashboard API.

import (
	"bytes"
	"encoding/csv"
	"net/http"
	"strings"
	"testing"

	"github.com/threatcl/enisa-sbd-example/internal/authn"
	"github.com/threatcl/enisa-sbd-example/internal/dashboard"
	"github.com/threatcl/enisa-sbd-example/internal/store"
)

func TestFleetExportIsTenantScopedAndInjectionSafe(t *testing.T) {
	st := twoTenants(t)

	// Metric names come off the wire from devices, so a device can put a
	// spreadsheet formula in one.
	if err := st.RecordReading(enrolledDevice, store.Reading{Metric: "=1+1", Value: -2.5}); err != nil {
		t.Fatalf("recording reading: %v", err)
	}

	tokens := tokenStore(t, credential(operatorToken, "olive@northwind.example", northwind, authn.RoleOperator))
	srv := serve(t, dashboard.Handler(st, tokens, discardLogger()))

	resp, body := call(t, srv, http.MethodGet, "/api/fleet/export", operatorToken, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/fleet/export = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/csv") {
		t.Errorf("Content-Type = %q, want text/csv", got)
	}

	records, err := csv.NewReader(bytes.NewReader(body)).ReadAll()
	if err != nil {
		t.Fatalf("export is not valid CSV: %v\n%s", err, body)
	}
	if len(records) != 3 { // header + two northwind readings
		t.Fatalf("export has %d rows, want 3:\n%s", len(records), body)
	}
	if strings.Contains(string(body), contosoDevice) {
		t.Fatalf("export leaked another tenant's device:\n%s", body)
	}

	// The formula is neutralised, and the negative value beside it is not.
	var found bool
	for _, row := range records[1:] {
		if row[2] == "'=1+1" {
			found = true
			if row[3] != "-2.5" {
				t.Errorf("value column = %q, want -2.5 — numbers must not be prefixed", row[3])
			}
		}
		if strings.HasPrefix(row[2], "=") {
			t.Errorf("metric %q reached the file as a live formula", row[2])
		}
	}
	if !found {
		t.Errorf("device-supplied metric is missing from the export:\n%s", body)
	}

	if resp, _ := call(t, srv, http.MethodGet, "/api/fleet/export", "", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauthenticated export = %d, want 401", resp.StatusCode)
	}
}
