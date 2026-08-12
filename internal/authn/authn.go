// Package authn resolves an HTTP caller to an identity.
//
// SensorHub's threat model puts operators and admins on opposite sides of a
// user-admin trust boundary (threatmodel/sensorhub.tm.hcl, threat
// "operator_escalates_to_admin"). This package answers only "who is calling".
// What that caller may reach is decided in internal/authz, so a handler cannot
// authenticate a request without also authorising it.
package authn

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
)

// Role is the coarse permission band a credential carries. SensorHub has
// exactly two, on either side of the user-admin boundary.
type Role string

const (
	RoleOperator Role = "operator"
	RoleAdmin    Role = "admin"
)

// Valid reports whether r is a role this service knows about.
//
// Unknown roles are refused when the token store loads, rather than being
// treated as "no permissions". A typo in a role name should stop the service
// starting, not quietly mint an account whose failures look like a bug.
func (r Role) Valid() bool {
	switch r {
	case RoleOperator, RoleAdmin:
		return true
	}
	return false
}

// Identity is an authenticated caller. Both fields that matter for
// authorisation - the organisation and the role - come from the credential.
// Neither is ever read from a request body, path or query parameter.
type Identity struct {
	Subject string
	OrgID   string
	Role    Role
}

// Entry is one credential in the token store. Only the SHA-256 digest of the
// token is held, so a leaked credentials file does not hand over live tokens.
type Entry struct {
	TokenSHA256 string `json:"token_sha256"`
	Subject     string `json:"subject"`
	OrgID       string `json:"org"`
	Role        Role   `json:"role"`
}

// Store maps bearer tokens to identities.
//
// A real deployment would resolve an OIDC token against an identity provider.
// The shape the threat model depends on is the same either way: the caller's
// organisation and role are properties of the credential.
type Store struct {
	byHash map[string]Identity
}

type storeFile struct {
	Tokens []Entry `json:"tokens"`
}

// ErrEmptyStore is returned when a token store contains no credentials. An
// empty store fails closed, but silently: erroring at load time turns a
// misconfigured deployment into a startup failure instead of a support ticket.
var ErrEmptyStore = errors.New("authn: token store contains no credentials")

// NewStore validates entries and builds a store. Every entry must carry a
// well-formed digest, a subject, an organisation and a known role; anything
// else is a configuration error rather than a credential to be ignored.
func NewStore(entries []Entry) (*Store, error) {
	if len(entries) == 0 {
		return nil, ErrEmptyStore
	}
	byHash := make(map[string]Identity, len(entries))
	for i, e := range entries {
		switch {
		case len(e.TokenSHA256) != sha256.Size*2:
			return nil, fmt.Errorf("authn: entry %d: token_sha256 must be a %d-character hex digest", i, sha256.Size*2)
		case !isLowerHex(e.TokenSHA256):
			return nil, fmt.Errorf("authn: entry %d: token_sha256 must be lowercase hex", i)
		case e.Subject == "":
			return nil, fmt.Errorf("authn: entry %d: subject is required", i)
		case e.OrgID == "":
			return nil, fmt.Errorf("authn: entry %d (%s): org is required, a credential with no tenant can reach no data", i, e.Subject)
		case !e.Role.Valid():
			return nil, fmt.Errorf("authn: entry %d (%s): unknown role %q", i, e.Subject, e.Role)
		}
		if _, dup := byHash[e.TokenSHA256]; dup {
			return nil, fmt.Errorf("authn: entry %d (%s): duplicate token digest", i, e.Subject)
		}
		byHash[e.TokenSHA256] = Identity{Subject: e.Subject, OrgID: e.OrgID, Role: e.Role}
	}
	return &Store{byHash: byHash}, nil
}

// LoadStore reads a JSON credentials file of the form
//
//	{"tokens": [{"token_sha256": "...", "subject": "...", "org": "...", "role": "operator"}]}
func LoadStore(path string) (*Store, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("authn: reading token store: %w", err)
	}
	var f storeFile
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("authn: parsing token store %s: %w", path, err)
	}
	return NewStore(f.Tokens)
}

// HashToken returns the digest stored for a token. Used to build credentials
// files and by tests; the plaintext never leaves the caller.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Lookup resolves a bearer token to an identity.
func (s *Store) Lookup(token string) (Identity, bool) {
	if s == nil || token == "" {
		return Identity{}, false
	}
	// Keyed by digest rather than by the token itself, so the plaintext is
	// never held in memory by this package. A map lookup on a SHA-256 digest
	// leaks nothing that would help an attacker guess the preimage.
	id, ok := s.byHash[HashToken(token)]
	return id, ok
}

// BearerToken extracts a bearer credential from an Authorization header.
func BearerToken(r *http.Request) (string, bool) {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	return token, token != ""
}

func isLowerHex(s string) bool {
	for _, c := range s {
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f') {
			return false
		}
	}
	return true
}
