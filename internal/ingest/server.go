// Package ingest is the Ingest API process: the device-cloud entry point.
//
// It is the only component reachable from the field_site trust zone, over the
// "telemetry publish" flow (mqtts) in the model's data flow diagram. Two
// controls live here, both from threat "spoofed_device_telemetry":
//
//   - mutual TLS with per-device certificates, refusing unknown CAs and
//     expired certificates at the TLS layer, before application code runs;
//   - the device identity used to store a reading comes from the verified
//     certificate, never from the packet.
package ingest

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/threatcl/enisa-sbd-example/internal/mqtt"
	"github.com/threatcl/enisa-sbd-example/internal/store"
)

// Defaults for the connection budget. A field device connects, publishes and
// idles; none of these need to be generous.
const (
	DefaultHandshakeTimeout = 10 * time.Second
	DefaultIdleTimeout      = 90 * time.Second
	DefaultMaxConns         = 512
	maxMetricNameLen        = 64
)

// TopicFor returns the only topic a device may publish to.
func TopicFor(deviceID string) string { return "fleet/" + deviceID + "/telemetry" }

// Server accepts MQTT-over-TLS connections from enrolled devices.
type Server struct {
	store *store.Store
	log   *slog.Logger

	HandshakeTimeout time.Duration
	IdleTimeout      time.Duration
	MaxConns         int
}

// New returns a server writing telemetry to st.
func New(st *store.Store, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{
		store:            st,
		log:              log,
		HandshakeTimeout: DefaultHandshakeTimeout,
		IdleTimeout:      DefaultIdleTimeout,
		MaxConns:         DefaultMaxConns,
	}
}

// TLSConfig is the ingest listener's transport policy, and is the control
// named by threat "spoofed_device_telemetry". It is a pure function of the
// key material so that tests exercise this policy rather than one of their
// own: RequireAndVerifyClientCert means a connection without a currently
// valid certificate chaining to deviceCAs never reaches application code.
func TLSConfig(serverCert tls.Certificate, deviceCAs *x509.CertPool) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    deviceCAs,
		MinVersion:   tls.VersionTLS12,
	}
}

// LoadTLSConfig reads the server keypair and the device CA bundle from disk
// and returns the same policy as TLSConfig.
func LoadTLSConfig(certFile, keyFile, deviceCAFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("ingest: loading server keypair: %w", err)
	}
	pem, err := os.ReadFile(deviceCAFile)
	if err != nil {
		return nil, fmt.Errorf("ingest: reading device CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("ingest: device CA %s contains no certificates", deviceCAFile)
	}
	return TLSConfig(cert, pool), nil
}

// Serve accepts connections until ctx is cancelled or l fails, then waits for
// in-flight connections to finish.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	var wg sync.WaitGroup
	defer wg.Wait()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()

	slots := make(chan struct{}, max(s.MaxConns, 1))
	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("ingest: accept: %w", err)
		}
		select {
		case slots <- struct{}{}:
		default:
			// At capacity. Shedding load is preferable to accepting a
			// connection the process cannot service.
			s.log.Warn("ingest at connection capacity, refusing", "remote", conn.RemoteAddr().String())
			_ = conn.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-slots }()
			s.handle(ctx, conn)
		}()
	}
}

func (s *Server) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()

	// The listener is wrapped in TLS by the caller. Asserting it here means a
	// misconfigured deployment that serves plaintext refuses every connection
	// instead of accepting unauthenticated telemetry.
	tc, ok := conn.(*tls.Conn)
	if !ok {
		s.log.Error("ingest received a non-TLS connection, refusing", "remote", remote)
		return
	}

	hsCtx, cancel := context.WithTimeout(ctx, s.HandshakeTimeout)
	defer cancel()
	if err := tc.HandshakeContext(hsCtx); err != nil {
		s.log.Warn("device handshake refused", "remote", remote, "err", err)
		return
	}

	deviceID, err := deviceIDFrom(tc.ConnectionState())
	if err != nil {
		s.log.Warn("device certificate unusable", "remote", remote, "err", err)
		return
	}
	// A valid certificate from the fleet CA is necessary but not sufficient:
	// the device must also still be enrolled, so decommissioning a unit does
	// not depend on certificate expiry.
	if _, ok := s.store.Device(deviceID); !ok {
		s.log.Warn("device not enrolled", "remote", remote, "device", deviceID)
		return
	}

	if err := s.session(tc, deviceID); err != nil && !isClosed(err) {
		s.log.Warn("device session ended", "remote", remote, "device", deviceID, "err", err)
	}
}

// deviceIDFrom takes the device identity from the verified certificate chain.
func deviceIDFrom(state tls.ConnectionState) (string, error) {
	if len(state.PeerCertificates) == 0 {
		return "", errors.New("no client certificate presented")
	}
	cn := strings.TrimSpace(state.PeerCertificates[0].Subject.CommonName)
	if cn == "" {
		return "", errors.New("client certificate has an empty common name")
	}
	return cn, nil
}

func (s *Server) session(conn net.Conn, deviceID string) error {
	br := bufio.NewReaderSize(conn, 4<<10)

	if err := conn.SetDeadline(time.Now().Add(s.HandshakeTimeout)); err != nil {
		return err
	}
	first, err := mqtt.Read(br, mqtt.MaxPacketSize)
	if err != nil {
		return err
	}
	if first.Type != mqtt.CONNECT {
		return fmt.Errorf("%w: first packet was %s, not CONNECT", mqtt.ErrMalformed, first.Type)
	}
	if _, err := mqtt.DecodeConnect(first.Body); err != nil {
		code := mqtt.ConnRefusedBadProtocol
		if errors.Is(err, mqtt.ErrCredsInCon) {
			code = mqtt.ConnRefusedNotAuthed
		}
		_ = mqtt.WriteConnAck(conn, code)
		return err
	}
	if err := mqtt.WriteConnAck(conn, mqtt.ConnAccepted); err != nil {
		return err
	}
	s.log.Info("device connected", "device", deviceID)

	topic := TopicFor(deviceID)
	for {
		if err := conn.SetDeadline(time.Now().Add(s.IdleTimeout)); err != nil {
			return err
		}
		p, err := mqtt.Read(br, mqtt.MaxPacketSize)
		if err != nil {
			return err
		}
		switch p.Type {
		case mqtt.PUBLISH:
			pub, err := mqtt.DecodePublish(p.Flags, p.Body)
			if err != nil {
				return err
			}
			// The topic must name the device that the certificate identifies.
			// Without this, any enrolled device could publish as any other -
			// authentication without authorisation.
			if pub.Topic != topic {
				return fmt.Errorf("device %s published to %q, not its own topic", deviceID, pub.Topic)
			}
			if err := s.record(deviceID, pub.Payload); err != nil {
				return err
			}
			if pub.QoS == 1 {
				if err := mqtt.WritePubAck(conn, pub.PacketID); err != nil {
					return err
				}
			}
		case mqtt.PINGREQ:
			if err := mqtt.Write(conn, mqtt.PINGRESP, 0, nil); err != nil {
				return err
			}
		case mqtt.DISCONNECT:
			return nil
		default:
			return fmt.Errorf("%w: unexpected %s from device", mqtt.ErrMalformed, p.Type)
		}
	}
}

// sample is the telemetry wire format. Unknown fields are refused so a device
// running newer firmware than the fleet's contract fails visibly rather than
// having half its payload silently dropped.
type sample struct {
	Metric string    `json:"metric"`
	Value  float64   `json:"value"`
	At     time.Time `json:"at"`
}

func (s *Server) record(deviceID string, payload []byte) error {
	dec := json.NewDecoder(strings.NewReader(string(payload)))
	dec.DisallowUnknownFields()
	var smp sample
	if err := dec.Decode(&smp); err != nil {
		return fmt.Errorf("device %s sent an undecodable sample: %w", deviceID, err)
	}
	switch {
	case smp.Metric == "" || len(smp.Metric) > maxMetricNameLen:
		return fmt.Errorf("device %s sent a sample with an unusable metric name", deviceID)
	case math.IsNaN(smp.Value) || math.IsInf(smp.Value, 0):
		return fmt.Errorf("device %s sent a non-finite value for %s", deviceID, smp.Metric)
	}
	return s.store.RecordReading(deviceID, store.Reading{
		Metric: smp.Metric,
		Value:  smp.Value,
		At:     smp.At,
	})
}

// isClosed reports whether err is a device hanging up or idling out, neither
// of which is worth a log line.
func isClosed(err error) bool {
	return errors.Is(err, io.EOF) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, os.ErrDeadlineExceeded)
}
