package tests

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/threatcl/enisa-sbd-example/internal/authn"
	"github.com/threatcl/enisa-sbd-example/internal/ingest"
	"github.com/threatcl/enisa-sbd-example/internal/mqtt"
	"github.com/threatcl/enisa-sbd-example/internal/store"
)

// No key material is committed to this repository. Every certificate below is
// generated per test run, which also means the expired and foreign-CA cases
// are genuinely expired and genuinely foreign rather than fixtures that will
// themselves expire one day and turn a negative test green for the wrong
// reason.

type certAuthority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

type certOpts struct {
	commonName string
	server     bool
	notBefore  time.Time
	notAfter   time.Time
}

func newCA(t *testing.T, name string) *certAuthority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(t),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing CA certificate: %v", err)
	}
	return &certAuthority{cert: cert, key: key}
}

func (ca *certAuthority) issue(t *testing.T, o certOpts) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating leaf key: %v", err)
	}
	if o.notBefore.IsZero() {
		o.notBefore = time.Now().Add(-time.Hour)
	}
	if o.notAfter.IsZero() {
		o.notAfter = time.Now().Add(24 * time.Hour)
	}
	usage := x509.ExtKeyUsageClientAuth
	tmpl := &x509.Certificate{
		SerialNumber: serial(t),
		Subject:      pkix.Name{CommonName: o.commonName},
		NotBefore:    o.notBefore,
		NotAfter:     o.notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if o.server {
		usage = x509.ExtKeyUsageServerAuth
		tmpl.DNSNames = []string{"localhost"}
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	tmpl.ExtKeyUsage = []x509.ExtKeyUsage{usage}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("issuing certificate for %s: %v", o.commonName, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing issued certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func (ca *certAuthority) pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	return pool
}

func serial(t *testing.T) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generating serial: %v", err)
	}
	return n
}

// discardLogger keeps service logs out of test output. The tests state what
// they proved with t.Logf, which is what the CI evidence artifact should read
// like.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}

// ── ingest harness ─────────────────────────────────────────────────────────

// fleetHarness is a running Ingest API with the certificate authorities the
// tests need: a device CA the server trusts, a server CA the devices trust,
// and one foreign CA that nobody trusts.
type fleetHarness struct {
	addr      string
	store     *store.Store
	deviceCA  *certAuthority
	foreignCA *certAuthority
	serverCA  *certAuthority
}

func startIngest(t *testing.T, st *store.Store) *fleetHarness {
	t.Helper()
	h := &fleetHarness{
		store:     st,
		deviceCA:  newCA(t, "SensorHub Device CA"),
		foreignCA: newCA(t, "Some Other CA"),
		serverCA:  newCA(t, "SensorHub Server CA"),
	}
	serverCert := h.serverCA.issue(t, certOpts{commonName: "ingest.sensorhub.example", server: true})

	// The TLS policy under test is the production one: ingest.TLSConfig, not a
	// configuration assembled here. A test that builds its own tls.Config
	// proves only that the test is careful.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	tlsListener := tls.NewListener(l, ingest.TLSConfig(serverCert, h.deviceCA.pool()))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = ingest.New(st, discardLogger()).Serve(ctx, tlsListener)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	h.addr = l.Addr().String()
	return h
}

// device is a minimal MQTT client: enough of a field device to connect,
// publish and be refused.
type device struct {
	conn net.Conn
	br   *bufio.Reader
}

// dial connects as a device and completes the MQTT handshake.
//
// It deliberately runs the whole sequence - TLS handshake, CONNECT, CONNACK -
// before reporting success. Under TLS 1.3 a server rejects a client
// certificate after its own Finished message, so a client-side Handshake()
// can return nil on a connection the server has already refused. Only an
// answered CONNECT proves the device was let in.
func (h *fleetHarness) dial(t *testing.T, clientCert *tls.Certificate) (*device, error) {
	t.Helper()
	conf := &tls.Config{
		RootCAs:    h.serverCA.pool(),
		ServerName: "localhost",
		MinVersion: tls.VersionTLS12,
	}
	if clientCert != nil {
		// GetClientCertificate rather than Certificates, deliberately.
		//
		// Go's client filters Certificates against the acceptable-CA list the
		// server advertises, so a certificate from a foreign CA is never put
		// on the wire and the server refuses the connection for having no
		// certificate at all. That would make the foreign-CA case below prove
		// only that Go's client is well behaved, which an attacker's will not
		// be. This callback hands over whatever it is given, so the refusal
		// under test is the server verifying the chain.
		conf.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return clientCert, nil
		}
	}
	conn, err := tls.Dial("tcp", h.addr, conf)
	if err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		conn.Close()
		return nil, err
	}
	d := &device{conn: conn, br: bufio.NewReader(conn)}
	t.Cleanup(func() { conn.Close() })

	clientID := "test-device"
	if clientCert != nil && clientCert.Leaf != nil {
		clientID = clientCert.Leaf.Subject.CommonName
	}
	if err := mqtt.Write(conn, mqtt.CONNECT, 0, mqtt.EncodeConnect(mqtt.Connect{ClientID: clientID, KeepAlive: 30})); err != nil {
		return nil, err
	}
	code, err := mqtt.ReadConnAck(d.br)
	if err != nil {
		return nil, err
	}
	if code != mqtt.ConnAccepted {
		return nil, &connRefused{code: code}
	}
	return d, nil
}

type connRefused struct{ code byte }

func (e *connRefused) Error() string {
	return "ingest refused the connection with CONNACK code " + string(rune('0'+e.code))
}

// publish sends one QoS 1 sample and waits for the acknowledgement.
func (d *device) publish(topic string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	flags, pkt := mqtt.EncodePublish(mqtt.Publish{Topic: topic, QoS: 1, PacketID: 1, Payload: body})
	if err := mqtt.Write(d.conn, mqtt.PUBLISH, flags, pkt); err != nil {
		return err
	}
	p, err := mqtt.Read(d.br, 64)
	if err != nil {
		return err
	}
	if p.Type != mqtt.PUBACK {
		return &connRefused{code: byte(p.Type)}
	}
	return nil
}

// ── API harness ────────────────────────────────────────────────────────────

// credential returns a token store entry, and the plaintext token to present.
func credential(token, subject, org string, role authn.Role) authn.Entry {
	return authn.Entry{
		TokenSHA256: authn.HashToken(token),
		Subject:     subject,
		OrgID:       org,
		Role:        role,
	}
}

func tokenStore(t *testing.T, entries ...authn.Entry) *authn.Store {
	t.Helper()
	s, err := authn.NewStore(entries)
	if err != nil {
		t.Fatalf("building token store: %v", err)
	}
	return s
}

func serve(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

// call makes a request with an optional bearer token and returns the response
// with its body already read.
func call(t *testing.T, srv *httptest.Server, method, path, token string, body io.Reader) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, body)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatalf("reading response body: %v", err)
	}
	return resp, raw
}

func decode[T any](t *testing.T, raw []byte) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("decoding response %q: %v", raw, err)
	}
	return v
}
