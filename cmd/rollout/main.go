// Command sensorhub-rollout is the Rollout Service process from the model's
// data flow diagram: the admin-only privileged path that publishes signed
// firmware to the CDN and writes the audit log.
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
	"github.com/threatcl/enisa-sbd-example/internal/httpserve"
	"github.com/threatcl/enisa-sbd-example/internal/rollout"
	"github.com/threatcl/enisa-sbd-example/internal/store"
)

// cdnTokenEnv holds the CDN credential. Read from the environment rather than
// a flag, because flags are visible in the process table to every other user
// on the host.
const cdnTokenEnv = "SENSORHUB_CDN_TOKEN"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "sensorhub-rollout:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("sensorhub-rollout", flag.ContinueOnError)
	addr := fs.String("addr", ":9443", "listen address")
	tokensFile := fs.String("tokens", "", "JSON credential store (required)")
	releaseKey := fs.String("release-key", "", "PEM Ed25519 public key that release manifests must verify against (required)")
	cdnURL := fs.String("cdn-url", "", "https origin of the firmware CDN (required)")
	certFile := fs.String("tls-cert", "", "PEM server certificate")
	keyFile := fs.String("tls-key", "", "PEM server private key")
	plaintext := fs.Bool("allow-plaintext", false, "serve HTTP instead of HTTPS (local development only)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	for name, value := range map[string]string{"tokens": *tokensFile, "release-key": *releaseKey, "cdn-url": *cdnURL} {
		if value == "" {
			return fmt.Errorf("-%s is required", name)
		}
	}

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	tokens, err := authn.LoadStore(*tokensFile)
	if err != nil {
		return err
	}
	// The verification key is pinned at startup. There is no code path that
	// accepts a key from a request, so a release cannot bring its own trust
	// anchor - see threat "malicious_firmware_via_cdn".
	key, err := rollout.LoadReleaseKey(*releaseKey)
	if err != nil {
		return err
	}
	cdn, err := rollout.NewHTTPPublisher(*cdnURL, os.Getenv(cdnTokenEnv))
	if err != nil {
		return fmt.Errorf("%w (is %s set?)", err, cdnTokenEnv)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return httpserve.Run(ctx, httpserve.Options{
		Addr:           *addr,
		Handler:        rollout.Handler(store.New(), tokens, key, cdn, log),
		Log:            log,
		CertFile:       *certFile,
		KeyFile:        *keyFile,
		AllowPlaintext: *plaintext,
	})
}
