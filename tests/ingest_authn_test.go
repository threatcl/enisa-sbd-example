package tests

// Verification for the control "Mutual TLS with per-device certificates" on
// threat "spoofed_device_telemetry" in threatmodel/sensorhub.tm.hcl.
//
// The model's implementation notes say: "Negative tests assert that a no-cert
// connect, an expired-cert connect, and a cert signed by a foreign CA are all
// refused." Those are the three subtests below, plus a fourth the model does
// not demand but the boundary does - a certificate that is perfectly valid for
// a device nobody enrolled.

import (
	"crypto/tls"
	"testing"
	"time"

	"github.com/threatcl/enisa-sbd-example/internal/authn"
	"github.com/threatcl/enisa-sbd-example/internal/ingest"
	"github.com/threatcl/enisa-sbd-example/internal/store"
)

const (
	enrolledDevice = "dev-northwind-001"
	northwind      = "northwind"
)

func enrolledFleet(t *testing.T) *store.Store {
	t.Helper()
	st := store.New()
	if err := st.Enrol(store.Device{
		ID: enrolledDevice, OrgID: northwind, Model: "SH-2", FirmwareVersion: "1.4.0",
	}); err != nil {
		t.Fatalf("enrolling device: %v", err)
	}
	return st
}

func northwindScope(t *testing.T) store.Scope {
	t.Helper()
	sc, err := store.ScopeFor(authn.Identity{Subject: "test", OrgID: northwind, Role: authn.RoleOperator})
	if err != nil {
		t.Fatalf("building scope: %v", err)
	}
	return sc
}

// TestIngestRejectsUntrustedCert is the negative test named by the model.
func TestIngestRejectsUntrustedCert(t *testing.T) {
	st := enrolledFleet(t)
	h := startIngest(t, st)

	cases := []struct {
		name string
		cert func() *tls.Certificate
	}{
		{
			name: "no client certificate at all",
			cert: func() *tls.Certificate { return nil },
		},
		{
			name: "certificate issued by the fleet CA but expired yesterday",
			cert: func() *tls.Certificate {
				c := h.deviceCA.issue(t, certOpts{
					commonName: enrolledDevice,
					notBefore:  time.Now().Add(-48 * time.Hour),
					notAfter:   time.Now().Add(-24 * time.Hour),
				})
				return &c
			},
		},
		{
			name: "well-formed certificate signed by a foreign CA",
			cert: func() *tls.Certificate {
				c := h.foreignCA.issue(t, certOpts{commonName: enrolledDevice})
				return &c
			},
		},
		{
			name: "valid fleet certificate for a device that is not enrolled",
			cert: func() *tls.Certificate {
				c := h.deviceCA.issue(t, certOpts{commonName: "dev-never-provisioned"})
				return &c
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := h.dial(t, tc.cert())
			if err == nil {
				_ = d
				t.Fatalf("ingest ACCEPTED a device presenting %s - unauthorised access to the device-cloud boundary is not denied", tc.name)
			}
			t.Logf("refused, as required: %s -> %v", tc.name, err)
		})
	}

	// Nothing above should have left a trace in the Telemetry DB.
	readings, err := st.Readings(northwindScope(t), enrolledDevice, 10)
	if err != nil {
		t.Fatalf("reading telemetry: %v", err)
	}
	if len(readings) != 0 {
		t.Fatalf("refused connections still wrote %d readings", len(readings))
	}
}

// TestIngestAcceptsAnEnrolledDevice is the positive half. Without it, a server
// that refused everything would pass the negative tests.
func TestIngestAcceptsAnEnrolledDevice(t *testing.T) {
	st := enrolledFleet(t)
	h := startIngest(t, st)

	cert := h.deviceCA.issue(t, certOpts{commonName: enrolledDevice})
	d, err := h.dial(t, &cert)
	if err != nil {
		t.Fatalf("ingest refused a validly enrolled device: %v", err)
	}
	if err := d.publish(ingest.TopicFor(enrolledDevice), map[string]any{
		"metric": "battery_pct",
		"value":  91.5,
		"at":     time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		t.Fatalf("publishing telemetry: %v", err)
	}

	readings, err := st.Readings(northwindScope(t), enrolledDevice, 10)
	if err != nil {
		t.Fatalf("reading telemetry: %v", err)
	}
	if len(readings) != 1 {
		t.Fatalf("got %d readings, want 1", len(readings))
	}
	if got := readings[0].Metric; got != "battery_pct" {
		t.Errorf("metric = %q, want battery_pct", got)
	}
	if readings[0].ReceivedAt.IsZero() {
		t.Error("reading has no server-side ReceivedAt; a device's own clock is not evidence")
	}
}

// TestIngestRefusesAnotherDevicesTopic covers authentication without
// authorisation: the certificate is genuine, but it does not entitle this
// device to publish as a different one.
func TestIngestRefusesAnotherDevicesTopic(t *testing.T) {
	st := enrolledFleet(t)
	if err := st.Enrol(store.Device{ID: "dev-northwind-002", OrgID: northwind}); err != nil {
		t.Fatalf("enrolling second device: %v", err)
	}
	h := startIngest(t, st)

	cert := h.deviceCA.issue(t, certOpts{commonName: enrolledDevice})
	d, err := h.dial(t, &cert)
	if err != nil {
		t.Fatalf("ingest refused a validly enrolled device: %v", err)
	}

	// Publishing to a peer's topic must not be acknowledged, and must not land.
	_ = d.publish(ingest.TopicFor("dev-northwind-002"), map[string]any{
		"metric": "battery_pct",
		"value":  1,
	})
	readings, err := st.Readings(northwindScope(t), "dev-northwind-002", 10)
	if err != nil {
		t.Fatalf("reading telemetry: %v", err)
	}
	if len(readings) != 0 {
		t.Fatalf("device %s wrote %d readings against a peer's topic", enrolledDevice, len(readings))
	}
	t.Logf("refused, as required: %s may not publish as dev-northwind-002", enrolledDevice)
}
