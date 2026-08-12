// Package store is SensorHub's data layer: the Telemetry DB and Audit Log
// drawn inside the cloud_backend trust zone of the model's data flow diagram.
//
// The backing store is in-memory so the example runs with no infrastructure.
// What matters for the threat model is not where the rows live but that tenant
// scoping is enforced here rather than in each handler - see scope.go.
package store

import (
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
)

// maxReadingsPerDevice bounds retention per device. A device that publishes in
// a tight loop should cost memory proportional to the fleet, not to uptime.
const maxReadingsPerDevice = 1024

// Device is an enrolled unit. OrgID is set at enrolment and is the only source
// of a reading's tenant: an ingesting device cannot claim another operator's
// organisation, because it never states one.
type Device struct {
	ID              string    `json:"id"`
	OrgID           string    `json:"-"`
	Model           string    `json:"model"`
	FirmwareVersion string    `json:"firmware_version"`
	LastSeen        time.Time `json:"last_seen,omitzero"`
}

// Reading is one telemetry sample.
//
// At is what the device claimed; ReceivedAt is what the ingest process
// observed. They are kept apart because a device's clock is attacker-reachable
// and the server's is not - anything that needs to be trustworthy uses
// ReceivedAt.
type Reading struct {
	DeviceID   string    `json:"device_id"`
	Metric     string    `json:"metric"`
	Value      float64   `json:"value"`
	At         time.Time `json:"at,omitzero"`
	ReceivedAt time.Time `json:"received_at"`
}

// Audit actions recorded by the rollout service.
const (
	ActionRolloutAccepted = "rollout.accepted"
	ActionRolloutRejected = "rollout.rejected"
)

// AuditEntry is one line of the Audit Log: evidence for CRA incident
// reporting, per information_asset "audit_log" in the model. Rejections are
// recorded as well as acceptances - a log that only holds successes cannot
// answer "who tried".
type AuditEntry struct {
	At      time.Time `json:"at"`
	Actor   string    `json:"actor"`
	OrgID   string    `json:"-"`
	Action  string    `json:"action"`
	Target  string    `json:"target"`
	Outcome string    `json:"outcome"`
	Reason  string    `json:"reason,omitempty"`
}

// Errors returned by the write paths.
var (
	ErrUnknownDevice = errors.New("store: device is not enrolled")
	ErrInvalidDevice = errors.New("store: device is missing an id or organisation")
)

// Store holds the Telemetry DB and the Audit Log.
type Store struct {
	mu       sync.RWMutex
	devices  map[string]Device
	readings map[string][]Reading
	audit    []AuditEntry
	now      func() time.Time
}

// New returns an empty store.
func New() *Store {
	return &Store{
		devices:  make(map[string]Device),
		readings: make(map[string][]Reading),
		now:      time.Now,
	}
}

// Enrol registers a device against an organisation. In production this is the
// provisioning system's write; here it is also how tests seed a fleet.
func (s *Store) Enrol(d Device) error {
	if d.ID == "" || d.OrgID == "" {
		return ErrInvalidDevice
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.devices[d.ID] = d
	return nil
}

// Device looks up an enrolled device by id.
//
// Unscoped on purpose: the ingest process calls this with the common name from
// a verified client certificate, which is the authenticated principal on that
// path. The tenant is the answer here, not an input to be checked.
func (s *Store) Device(id string) (Device, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.devices[id]
	return d, ok
}

// RecordReading stores a sample from an enrolled device, stamping it with the
// device's organisation and the server's clock.
func (s *Store) RecordReading(deviceID string, r Reading) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[deviceID]
	if !ok {
		return ErrUnknownDevice
	}
	now := s.now()
	r.DeviceID = deviceID
	r.ReceivedAt = now
	d.LastSeen = now
	s.devices[deviceID] = d

	rs := append(s.readings[deviceID], r)
	if len(rs) > maxReadingsPerDevice {
		rs = rs[len(rs)-maxReadingsPerDevice:]
	}
	s.readings[deviceID] = rs
	return nil
}

// Fleet returns the devices belonging to the scope's organisation, by id.
func (s *Store) Fleet(sc Scope) ([]Device, error) {
	org, err := orgOf(sc)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	var out []Device
	for _, d := range s.devices {
		if d.OrgID == org {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// Readings returns up to limit samples for one device, newest first.
//
// A device belonging to another organisation returns no rows rather than an
// error, so the response cannot be used to test whether a device id exists in
// some other tenant.
func (s *Store) Readings(sc Scope, deviceID string, limit int) ([]Reading, error) {
	org, err := orgOf(sc)
	if err != nil {
		return nil, err
	}
	if limit <= 0 || limit > maxReadingsPerDevice {
		limit = maxReadingsPerDevice
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	d, ok := s.devices[deviceID]
	if !ok || d.OrgID != org {
		return nil, nil
	}
	rs := s.readings[deviceID]
	out := make([]Reading, 0, min(limit, len(rs)))
	for i := len(rs) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, rs[i])
	}
	return out, nil
}

// AppendAudit records one action against the caller's organisation.
func (s *Store) AppendAudit(sc Scope, e AuditEntry) error {
	org, err := orgOf(sc)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e.OrgID = org
	if e.At.IsZero() {
		e.At = s.now()
	}
	s.audit = append(s.audit, e)
	return nil
}

// Audit returns the scope's audit entries, newest first, optionally filtered
// to actions sharing a prefix ("rollout." for the rollout service's view).
func (s *Store) Audit(sc Scope, actionPrefix string) ([]AuditEntry, error) {
	org, err := orgOf(sc)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	var out []AuditEntry
	for i := len(s.audit) - 1; i >= 0; i-- {
		e := s.audit[i]
		if e.OrgID == org && strings.HasPrefix(e.Action, actionPrefix) {
			out = append(out, e)
		}
	}
	return out, nil
}
