package rollout

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Manifest describes one firmware image. The image itself is never handled by
// this service - only its digest and a detached signature over that digest, so
// the signing key stays offline and CI never holds anything that can mint a
// release. See threat "malicious_firmware_via_cdn".
type Manifest struct {
	Version   string `json:"version"`
	Digest    string `json:"digest"`
	Signature string `json:"signature"`
}

// signingContext is a domain separator. It means a signature produced for some
// other SensorHub artefact cannot be replayed as a firmware release.
const signingContext = "sensorhub-firmware-release/v1"

const digestPrefix = "sha256:"

// Errors surfaced to the API layer, which maps them to status codes.
var (
	ErrBadManifest  = errors.New("rollout: malformed release manifest")
	ErrBadSignature = errors.New("rollout: release signature does not verify against the pinned key")
	ErrDowngrade    = errors.New("rollout: release version is not newer than the last accepted rollout")
)

// Validate checks the shape of a manifest before any cryptography runs.
func (m Manifest) Validate() error {
	if _, err := ParseVersion(m.Version); err != nil {
		return fmt.Errorf("%w: %s", ErrBadManifest, err)
	}
	hex, ok := strings.CutPrefix(m.Digest, digestPrefix)
	if !ok || len(hex) != 64 || !isLowerHex(hex) {
		return fmt.Errorf("%w: digest must be %s followed by 64 lowercase hex characters", ErrBadManifest, digestPrefix)
	}
	sig, err := base64.StdEncoding.DecodeString(m.Signature)
	if err != nil {
		return fmt.Errorf("%w: signature is not valid base64", ErrBadManifest)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: signature must be %d bytes", ErrBadManifest, ed25519.SignatureSize)
	}
	return nil
}

// SignedBytes is the exact byte string covered by the signature.
func (m Manifest) SignedBytes() []byte {
	return []byte(signingContext + "\n" + m.Version + "\n" + m.Digest + "\n")
}

// Verify checks the detached signature against the pinned release key.
func (m Manifest) Verify(key ed25519.PublicKey) error {
	if err := m.Validate(); err != nil {
		return err
	}
	if len(key) != ed25519.PublicKeySize {
		return errors.New("rollout: no release verification key configured")
	}
	sig, err := base64.StdEncoding.DecodeString(m.Signature)
	if err != nil {
		return fmt.Errorf("%w: signature is not valid base64", ErrBadManifest)
	}
	if !ed25519.Verify(key, m.SignedBytes(), sig) {
		return ErrBadSignature
	}
	return nil
}

// Sign returns m with a detached signature. It exists for tests and for the
// offline signing tool; the service itself only ever verifies.
func Sign(key ed25519.PrivateKey, m Manifest) Manifest {
	m.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, m.SignedBytes()))
	return m
}

// LoadReleaseKey reads a PEM-encoded PKIX Ed25519 public key.
func LoadReleaseKey(path string) (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("rollout: reading release key: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("rollout: %s is not a PEM PUBLIC KEY block", path)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("rollout: parsing release key: %w", err)
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("rollout: release key is %T, want ed25519", parsed)
	}
	return key, nil
}

// ParseVersion accepts strictly dotted decimals: 2, 2.1, 1.4.2, 1.4.2.9.
// Anything looser would make the downgrade comparison a guess, and a
// downgrade that compares wrongly is a downgrade that succeeds.
func ParseVersion(v string) ([]int, error) {
	if v == "" {
		return nil, errors.New("version is empty")
	}
	parts := strings.Split(v, ".")
	if len(parts) > 4 {
		return nil, fmt.Errorf("version %q has more than four components", v)
	}
	out := make([]int, len(parts))
	for i, p := range parts {
		if p == "" || len(p) > 6 || (len(p) > 1 && p[0] == '0') {
			return nil, fmt.Errorf("version %q has a malformed component %q", v, p)
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("version %q has a non-numeric component %q", v, p)
		}
		out[i] = n
	}
	return out, nil
}

// CompareVersions returns -1, 0 or 1. Missing trailing components are zero, so
// 1.4 and 1.4.0 are equal.
func CompareVersions(a, b string) (int, error) {
	av, err := ParseVersion(a)
	if err != nil {
		return 0, err
	}
	bv, err := ParseVersion(b)
	if err != nil {
		return 0, err
	}
	for i := range max(len(av), len(bv)) {
		x, y := at(av, i), at(bv, i)
		switch {
		case x < y:
			return -1, nil
		case x > y:
			return 1, nil
		}
	}
	return 0, nil
}

func at(v []int, i int) int {
	if i < len(v) {
		return v[i]
	}
	return 0
}

func isLowerHex(s string) bool {
	for _, c := range s {
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f') {
			return false
		}
	}
	return true
}
