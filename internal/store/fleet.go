package store

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
)

// deviceFile is the on-disk shape of the enrolled fleet. Device itself hides
// OrgID from JSON so an API response can never leak one tenant's organisation
// to another, which means the file format needs its own type.
type deviceFile struct {
	ID              string `json:"id"`
	OrgID           string `json:"org"`
	Model           string `json:"model"`
	FirmwareVersion string `json:"firmware_version"`
}

type fleetFile struct {
	Devices []deviceFile `json:"devices"`
}

// LoadFleet reads an enrolled-device file of the form
//
//	{"devices": [{"id": "dev-001", "org": "northwind", "model": "SH-2", "firmware_version": "1.4.0"}]}
//
// In production, enrolment is a write from the provisioning system. The file
// stands in for that here so the example runs with no infrastructure.
func LoadFleet(path string) ([]Device, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("store: reading fleet file: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var f fleetFile
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("store: parsing fleet file %s: %w", path, err)
	}
	if len(f.Devices) == 0 {
		return nil, fmt.Errorf("store: fleet file %s enrols no devices", path)
	}
	out := make([]Device, 0, len(f.Devices))
	seen := make(map[string]bool, len(f.Devices))
	for i, d := range f.Devices {
		if d.ID == "" || d.OrgID == "" {
			return nil, fmt.Errorf("store: fleet file %s: device %d needs both an id and an org", path, i)
		}
		if seen[d.ID] {
			return nil, fmt.Errorf("store: fleet file %s: device %q is enrolled twice", path, d.ID)
		}
		seen[d.ID] = true
		out = append(out, Device{
			ID:              d.ID,
			OrgID:           d.OrgID,
			Model:           d.Model,
			FirmwareVersion: d.FirmwareVersion,
		})
	}
	return out, nil
}

// EnrolAll registers every device or returns the first error.
func (s *Store) EnrolAll(devices []Device) error {
	for _, d := range devices {
		if err := s.Enrol(d); err != nil {
			return fmt.Errorf("store: enrolling %q: %w", d.ID, err)
		}
	}
	return nil
}
