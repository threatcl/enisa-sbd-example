// Package dashboard is the Dashboard API process: the read side of the
// product, reachable by operators and admins from the internet trust zone over
// the "fleet dashboard" flow (https).
//
// Every handler here is one line of scoping followed by a repository call.
// That is the point: the tenant-tenant boundary from threat
// "cross_tenant_telemetry_read" is held in internal/store, so a handler cannot
// forget it - see store.Scope.
package dashboard

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/threatcl/enisa-sbd-example/internal/authn"
	"github.com/threatcl/enisa-sbd-example/internal/authz"
	"github.com/threatcl/enisa-sbd-example/internal/store"
)

const (
	defaultReadingLimit = 100

	// exportReadingsPerDevice bounds how much history one export pulls back
	// per device, so a large fleet cannot turn a single request into an
	// unbounded response.
	exportReadingsPerDevice = 500

	// deliveryTimeout bounds one push of the export to a caller-nominated
	// destination, so a slow endpoint cannot pin a handler open.
	deliveryTimeout = 10 * time.Second
)

// Fleet views are readable by both roles. Admins are not implicitly operators
// anywhere in this service: every grant lists the roles it allows, so
// widening one is a diff rather than an inherited side effect.
var fleetReaders = []authn.Role{authn.RoleOperator, authn.RoleAdmin}

// Handler builds the Dashboard API's routes.
func Handler(st *store.Store, tokens *authn.Store, log *slog.Logger) *authz.Router {
	if log == nil {
		log = slog.Default()
	}
	s := &service{store: st, log: log}
	r := authz.New(tokens, log)

	r.HandleFunc("GET /api/fleet", fleetReaders, s.fleet)
	r.HandleFunc("GET /api/fleet/export", fleetReaders, s.export)
	r.HandleFunc("POST /api/fleet/export/deliver", fleetReaders, s.deliverExport)
	r.HandleFunc("GET /api/devices/{id}/telemetry", fleetReaders, s.telemetry)
	r.HandlePublic("GET /healthz", http.HandlerFunc(health))

	return r
}

type service struct {
	store *store.Store
	log   *slog.Logger
}

func (s *service) fleet(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.scope(w, r)
	if !ok {
		return
	}
	devices, err := s.store.Fleet(scope)
	if err != nil {
		s.fail(w, r, "listing fleet", err)
		return
	}
	authz.WriteJSON(w, http.StatusOK, map[string]any{"devices": devices})
}

func (s *service) telemetry(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.scope(w, r)
	if !ok {
		return
	}
	limit := defaultReadingLimit
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			authz.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "limit must be a positive integer"})
			return
		}
		limit = n
	}
	// A device belonging to another organisation yields no readings and no
	// error, so this response cannot be used to probe for device ids in other
	// tenants.
	readings, err := s.store.Readings(scope, r.PathValue("id"), limit)
	if err != nil {
		s.fail(w, r, "reading telemetry", err)
		return
	}
	if readings == nil {
		readings = []store.Reading{}
	}
	authz.WriteJSON(w, http.StatusOK, map[string]any{"readings": readings})
}

// export returns the caller's whole fleet as one CSV file.
//
// Operators asked for this so a month of readings can go into a spreadsheet
// instead of being paged out of the JSON API device by device. Scoping is the
// same as every other read in this service: the store will not answer without
// a tenant scope, and the scope comes from the credential.
func (s *service) export(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.scope(w, r)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="fleet-telemetry.csv"`)
	w.Header().Set("Cache-Control", "no-store")

	if err := s.writeCSV(w, scope); err != nil {
		// The 200 and the header rows are already on the wire, so there is no
		// status left to change. Stop and log rather than trailing a truncated
		// file that still looks like a complete one.
		s.log.Error("export truncated", "path", r.URL.Path, "err", err)
	}
}

// deliverExport POSTs the same CSV to a URL the caller nominates.
//
// Operators run the export on a schedule from their own reporting stack, and
// asked to have it pushed rather than polled. The body is
// {"url": "https://..."} and the request is the export, verbatim.
func (s *service) deliverExport(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.scope(w, r)
	if !ok {
		return
	}

	var req struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		authz.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "body must be {\"url\": \"https://...\"}"})
		return
	}
	dest, err := url.Parse(req.URL)
	if err != nil || dest.Scheme != "https" || dest.Host == "" {
		authz.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "url must be absolute https"})
		return
	}

	var buf bytes.Buffer
	if err := s.writeCSV(&buf, scope); err != nil {
		s.fail(w, r, "building export for delivery", err)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), deliveryTimeout)
	defer cancel()

	post, err := http.NewRequestWithContext(ctx, http.MethodPost, dest.String(), &buf)
	if err != nil {
		s.fail(w, r, "building delivery request", err)
		return
	}
	post.Header.Set("Content-Type", "text/csv; charset=utf-8")

	resp, err := http.DefaultClient.Do(post)
	if err != nil {
		s.log.Error("export delivery failed", "host", dest.Host, "err", err)
		authz.WriteJSON(w, http.StatusBadGateway, map[string]string{"error": "delivery failed"})
		return
	}
	defer resp.Body.Close()

	s.log.Info("export delivered", "host", dest.Host, "status", resp.StatusCode, "bytes", buf.Len())
	authz.WriteJSON(w, http.StatusAccepted, map[string]any{"delivered_to": dest.Host, "status": resp.StatusCode})
}

// writeCSV renders the caller's fleet as CSV. Scoping is the same as every
// other read in this service: the store will not answer without a tenant
// scope, and the scope comes from the credential.
func (s *service) writeCSV(w io.Writer, scope store.Scope) error {
	devices, err := s.store.Fleet(scope)
	if err != nil {
		return err
	}

	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"device_id", "model", "metric", "value", "received_at"}); err != nil {
		return err
	}
	for _, d := range devices {
		readings, err := s.store.Readings(scope, d.ID, exportReadingsPerDevice)
		if err != nil {
			return err
		}
		for _, reading := range readings {
			row := []string{
				csvSafe(d.ID),
				csvSafe(d.Model),
				csvSafe(reading.Metric),
				strconv.FormatFloat(reading.Value, 'f', -1, 64),
				reading.ReceivedAt.UTC().Format(time.RFC3339),
			}
			if err := cw.Write(row); err != nil {
				return err
			}
		}
	}
	cw.Flush()
	return cw.Error()
}

// csvSafe defuses spreadsheet formula injection.
//
// Metric names arrive from devices, and a field beginning with =, +, - or @ is
// executed as a formula when the file is opened in Excel or Sheets. Numeric
// columns are formatted separately, so prefixing here cannot mangle a negative
// reading.
func csvSafe(field string) string {
	if field == "" {
		return field
	}
	switch field[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + field
	}
	return field
}

func health(w http.ResponseWriter, _ *http.Request) {
	authz.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// scope derives the caller's tenant scope, which is the only way to reach data
// in this service.
func (s *service) scope(w http.ResponseWriter, r *http.Request) (store.Scope, bool) {
	id, ok := authz.Caller(r.Context())
	if !ok {
		// Unreachable through the router, which authenticates before any
		// handler runs. Kept as a fail-closed backstop in case a handler is
		// ever mounted somewhere else.
		s.log.Error("handler reached with no caller identity", "path", r.URL.Path)
		authz.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
		return nil, false
	}
	scope, err := store.ScopeFor(id)
	if err != nil {
		s.log.Error("caller has no organisation", "subject", id.Subject)
		authz.WriteJSON(w, http.StatusForbidden, map[string]string{"error": "Forbidden"})
		return nil, false
	}
	return scope, true
}

func (s *service) fail(w http.ResponseWriter, r *http.Request, what string, err error) {
	s.log.Error("dashboard request failed", "what", what, "path", r.URL.Path, "err", err)
	authz.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "Internal Server Error"})
}
