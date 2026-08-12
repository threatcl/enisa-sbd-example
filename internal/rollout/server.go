// Package rollout is the Rollout Service process: the privileged path.
//
// It is the only component an admin reaches (the "firmware rollout" flow,
// https), the only writer of the Audit Log, and the only publisher to the
// firmware CDN. Two boundaries meet here - user-admin and back-end-third-party
// - which is why every route is admin-only and every attempt, allowed or
// denied, lands in the audit log.
package rollout

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/threatcl/enisa-sbd-example/internal/authn"
	"github.com/threatcl/enisa-sbd-example/internal/authz"
	"github.com/threatcl/enisa-sbd-example/internal/store"
)

// maxManifestBytes bounds the request body. A manifest is three short strings.
const maxManifestBytes = 8 << 10

// adminOnly is the grant on every rollout route. Operators are absent by
// construction, not by a check inside the handler - see threat
// "operator_escalates_to_admin".
var adminOnly = []authn.Role{authn.RoleAdmin}

// Handler builds the Rollout Service's routes.
func Handler(st *store.Store, tokens *authn.Store, key ed25519.PublicKey, cdn Publisher, log *slog.Logger) *authz.Router {
	if log == nil {
		log = slog.Default()
	}
	s := &service{store: st, key: key, cdn: cdn, log: log}
	r := authz.New(tokens, log)

	r.HandleFunc("POST /api/rollouts", adminOnly, s.create)
	r.HandleFunc("GET /api/rollouts", adminOnly, s.list)
	r.HandlePublic("GET /healthz", http.HandlerFunc(health))

	return r
}

type service struct {
	store *store.Store
	key   ed25519.PublicKey
	cdn   Publisher
	log   *slog.Logger
}

func (s *service) create(w http.ResponseWriter, r *http.Request) {
	id, scope, ok := s.caller(w, r)
	if !ok {
		return
	}

	var m Manifest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxManifestBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		s.reject(w, r, id, scope, m.Version, http.StatusBadRequest, "undecodable manifest", err)
		return
	}

	// Verify before anything else has a chance to act on the manifest: an
	// unsigned or wrongly-signed release must never reach the CDN, even
	// though devices would refuse it on arrival. Defence in depth, and it
	// keeps a bad image out of the fleet's cache.
	if err := m.Verify(s.key); err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, ErrBadSignature) {
			status = http.StatusForbidden
		}
		s.reject(w, r, id, scope, m.Version, status, "signature verification failed", err)
		return
	}

	current, err := s.currentVersion(scope)
	if err != nil {
		s.fail(w, r, "reading rollout history", err)
		return
	}
	if current != "" {
		cmp, err := CompareVersions(m.Version, current)
		if err != nil {
			s.fail(w, r, "comparing versions", err)
			return
		}
		if cmp <= 0 {
			s.reject(w, r, id, scope, m.Version, http.StatusConflict, "downgrade refused",
				errors.Join(ErrDowngrade, errors.New("last accepted rollout was "+current)))
			return
		}
	}

	if err := s.cdn.Publish(r.Context(), m); err != nil {
		s.reject(w, r, id, scope, m.Version, http.StatusBadGateway, "cdn publish failed", err)
		return
	}

	if err := s.store.AppendAudit(scope, store.AuditEntry{
		Actor:   id.Subject,
		Action:  store.ActionRolloutAccepted,
		Target:  m.Version,
		Outcome: "allowed",
	}); err != nil {
		s.fail(w, r, "recording audit entry", err)
		return
	}
	s.log.Info("rollout published", "actor", id.Subject, "org", id.OrgID, "version", m.Version)
	authz.WriteJSON(w, http.StatusAccepted, map[string]string{
		"version": m.Version,
		"digest":  m.Digest,
		"status":  "published",
	})
}

func (s *service) list(w http.ResponseWriter, r *http.Request) {
	_, scope, ok := s.caller(w, r)
	if !ok {
		return
	}
	entries, err := s.store.Audit(scope, "rollout.")
	if err != nil {
		s.fail(w, r, "reading rollout history", err)
		return
	}
	if entries == nil {
		entries = []store.AuditEntry{}
	}
	authz.WriteJSON(w, http.StatusOK, map[string]any{"rollouts": entries})
}

func health(w http.ResponseWriter, _ *http.Request) {
	authz.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// currentVersion is the last release this organisation accepted. The audit log
// is the record of what was pushed, so it is also the answer to what may be
// pushed next - there is no second copy of the state to fall out of step.
func (s *service) currentVersion(scope store.Scope) (string, error) {
	entries, err := s.store.Audit(scope, store.ActionRolloutAccepted)
	if err != nil {
		return "", err
	}
	if len(entries) == 0 {
		return "", nil
	}
	return entries[0].Target, nil // Audit returns newest first.
}

func (s *service) caller(w http.ResponseWriter, r *http.Request) (authn.Identity, store.Scope, bool) {
	id, ok := authz.Caller(r.Context())
	if !ok {
		s.log.Error("handler reached with no caller identity", "path", r.URL.Path)
		authz.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
		return authn.Identity{}, nil, false
	}
	scope, err := store.ScopeFor(id)
	if err != nil {
		s.log.Error("caller has no organisation", "subject", id.Subject)
		authz.WriteJSON(w, http.StatusForbidden, map[string]string{"error": "Forbidden"})
		return authn.Identity{}, nil, false
	}
	return id, scope, true
}

// reject records the refused attempt before answering. A rollout that was
// tried and denied is exactly what an incident report needs, so the audit
// write happens on the failure path too - not only on success.
func (s *service) reject(w http.ResponseWriter, r *http.Request, id authn.Identity, scope store.Scope, version string, status int, reason string, cause error) {
	s.log.Warn("rollout refused",
		"actor", id.Subject,
		"org", id.OrgID,
		"version", version,
		"reason", reason,
		"err", cause,
		"path", r.URL.Path,
	)
	if err := s.store.AppendAudit(scope, store.AuditEntry{
		Actor:   id.Subject,
		Action:  store.ActionRolloutRejected,
		Target:  version,
		Outcome: "denied",
		Reason:  reason,
	}); err != nil {
		s.log.Error("could not record refused rollout", "err", err)
	}
	// The caller learns that it was refused and roughly why, but not the
	// detail of the failure - that is in the log and the audit entry.
	authz.WriteJSON(w, status, map[string]string{"error": http.StatusText(status), "reason": reason})
}

func (s *service) fail(w http.ResponseWriter, r *http.Request, what string, err error) {
	s.log.Error("rollout request failed", "what", what, "path", r.URL.Path, "err", err)
	authz.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "Internal Server Error"})
}
