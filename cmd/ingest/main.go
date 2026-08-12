// Command sensorhub-ingest is the Ingest API process from the model's data
// flow diagram: MQTT over mutual TLS, the device-cloud entry point.
//
// It has no plaintext mode. The "telemetry publish" flow is mqtts, and an
// ingest endpoint that can be started without client-certificate verification
// is an ingest endpoint that will be, one afternoon, by someone in a hurry.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/threatcl/enisa-sbd-example/internal/ingest"
	"github.com/threatcl/enisa-sbd-example/internal/store"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "sensorhub-ingest:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("sensorhub-ingest", flag.ContinueOnError)
	addr := fs.String("addr", ":8883", "listen address")
	certFile := fs.String("cert", "", "PEM server certificate (required)")
	keyFile := fs.String("key", "", "PEM server private key (required)")
	deviceCA := fs.String("device-ca", "", "PEM bundle of device CA certificates (required)")
	fleetFile := fs.String("fleet", "", "JSON file of enrolled devices (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	for name, value := range map[string]string{"cert": *certFile, "key": *keyFile, "device-ca": *deviceCA, "fleet": *fleetFile} {
		if value == "" {
			return fmt.Errorf("-%s is required", name)
		}
	}

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	st := store.New()
	devices, err := store.LoadFleet(*fleetFile)
	if err != nil {
		return err
	}
	if err := st.EnrolAll(devices); err != nil {
		return err
	}

	tlsConf, err := ingest.LoadTLSConfig(*certFile, *keyFile, *deviceCA)
	if err != nil {
		return err
	}
	l, err := net.Listen("tcp", *addr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", *addr, err)
	}
	defer l.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Info("ingest listening", "addr", l.Addr().String(), "devices", len(devices))
	return ingest.New(st, log).Serve(ctx, tls.NewListener(l, tlsConf))
}
