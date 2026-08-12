// Command sensorhub-dashboard is the Dashboard API process from the model's
// data flow diagram: the operator-facing read API, behind HTTPS.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/threatcl/enisa-sbd-example/internal/authn"
	"github.com/threatcl/enisa-sbd-example/internal/dashboard"
	"github.com/threatcl/enisa-sbd-example/internal/httpserve"
	"github.com/threatcl/enisa-sbd-example/internal/store"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "sensorhub-dashboard:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("sensorhub-dashboard", flag.ContinueOnError)
	addr := fs.String("addr", ":8443", "listen address")
	tokensFile := fs.String("tokens", "", "JSON credential store (required)")
	fleetFile := fs.String("fleet", "", "JSON file of enrolled devices (required)")
	certFile := fs.String("tls-cert", "", "PEM server certificate")
	keyFile := fs.String("tls-key", "", "PEM server private key")
	plaintext := fs.Bool("allow-plaintext", false, "serve HTTP instead of HTTPS (local development only)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	for name, value := range map[string]string{"tokens": *tokensFile, "fleet": *fleetFile} {
		if value == "" {
			return fmt.Errorf("-%s is required", name)
		}
	}

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	tokens, err := authn.LoadStore(*tokensFile)
	if err != nil {
		return err
	}
	st := store.New()
	devices, err := store.LoadFleet(*fleetFile)
	if err != nil {
		return err
	}
	if err := st.EnrolAll(devices); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return httpserve.Run(ctx, httpserve.Options{
		Addr:           *addr,
		Handler:        dashboard.Handler(st, tokens, log),
		Log:            log,
		CertFile:       *certFile,
		KeyFile:        *keyFile,
		AllowPlaintext: *plaintext,
	})
}
