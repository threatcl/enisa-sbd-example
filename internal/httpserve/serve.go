// Package httpserve runs the two HTTPS API processes with one set of
// transport defaults, so the Dashboard API and the Rollout Service cannot
// drift into different postures.
package httpserve

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// Options configures one API listener.
type Options struct {
	Addr    string
	Handler http.Handler
	Log     *slog.Logger

	CertFile string
	KeyFile  string

	// AllowPlaintext serves HTTP instead of HTTPS. Both flows into these
	// services are https in the model, so this exists only for local
	// development and has to be asked for by name.
	AllowPlaintext bool
}

// Run serves until ctx is cancelled, then drains in-flight requests.
func Run(ctx context.Context, o Options) error {
	log := o.Log
	if log == nil {
		log = slog.Default()
	}

	srv := &http.Server{
		Addr:    o.Addr,
		Handler: o.Handler,
		// A slow-header client should not hold a connection open indefinitely.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	if !o.AllowPlaintext && (o.CertFile == "" || o.KeyFile == "") {
		return errors.New("httpserve: -tls-cert and -tls-key are required; pass -allow-plaintext only for local development")
	}

	errc := make(chan error, 1)
	go func() {
		if o.AllowPlaintext {
			log.Warn("serving plaintext HTTP; the model expects https on this flow", "addr", o.Addr)
			errc <- srv.ListenAndServe()
			return
		}
		log.Info("serving HTTPS", "addr", o.Addr)
		errc <- srv.ListenAndServeTLS(o.CertFile, o.KeyFile)
	}()

	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("httpserve: %w", err)
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		log.Info("shutting down", "addr", o.Addr)
		return srv.Shutdown(shutdownCtx)
	}
}
