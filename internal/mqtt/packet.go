// Package mqtt implements the slice of MQTT 3.1.1 that SensorHub's device
// fleet actually uses: connect, publish telemetry, keep alive, disconnect.
//
// It is deliberately not a broker. A field device publishes to one topic and
// reads nothing back, so subscriptions, retained messages, will messages and
// QoS 2 are absent rather than stubbed - unimplemented protocol surface is
// surface an attacker cannot reach. The wire format lives here, shared by the
// ingest server and by tests that need to behave like a device.
package mqtt

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Type is an MQTT control packet type.
type Type byte

// The control packets this implementation knows about.
const (
	CONNECT    Type = 1
	CONNACK    Type = 2
	PUBLISH    Type = 3
	PUBACK     Type = 4
	PINGREQ    Type = 12
	PINGRESP   Type = 13
	DISCONNECT Type = 14
)

func (t Type) String() string {
	switch t {
	case CONNECT:
		return "CONNECT"
	case CONNACK:
		return "CONNACK"
	case PUBLISH:
		return "PUBLISH"
	case PUBACK:
		return "PUBACK"
	case PINGREQ:
		return "PINGREQ"
	case PINGRESP:
		return "PINGRESP"
	case DISCONNECT:
		return "DISCONNECT"
	}
	return fmt.Sprintf("packet(%d)", byte(t))
}

// MaxPacketSize caps a single control packet. MQTT permits 256MB; a telemetry
// sample is a few hundred bytes, so the limit is set where the product needs
// it rather than where the protocol allows.
const MaxPacketSize = 64 << 10

// ProtocolLevel4 is MQTT 3.1.1.
const ProtocolLevel4 = 4

// Wire errors. All of them are terminal: the connection is closed rather than
// resynchronised, because a stream that has gone out of frame cannot be
// trusted to describe its own length.
var (
	ErrMalformed  = errors.New("mqtt: malformed packet")
	ErrTooLarge   = errors.New("mqtt: packet exceeds maximum size")
	ErrCredsInCon = errors.New("mqtt: CONNECT carries username or password")
)

// Packet is a control packet with its body still encoded.
type Packet struct {
	Type  Type
	Flags byte
	Body  []byte
}

// Read reads one control packet, refusing anything larger than max bytes.
func Read(r *bufio.Reader, max int) (Packet, error) {
	if max <= 0 || max > MaxPacketSize {
		max = MaxPacketSize
	}
	h, err := r.ReadByte()
	if err != nil {
		return Packet{}, err
	}
	n, err := readVarint(r)
	if err != nil {
		return Packet{}, err
	}
	if n > max {
		return Packet{}, fmt.Errorf("%w: %d bytes", ErrTooLarge, n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return Packet{}, err
	}
	return Packet{Type: Type(h >> 4), Flags: h & 0x0f, Body: body}, nil
}

// Write writes one control packet.
func Write(w io.Writer, t Type, flags byte, body []byte) error {
	if len(body) > MaxPacketSize {
		return ErrTooLarge
	}
	buf := make([]byte, 0, 5+len(body))
	buf = append(buf, byte(t)<<4|flags&0x0f)
	buf = appendVarint(buf, len(body))
	buf = append(buf, body...)
	_, err := w.Write(buf)
	return err
}

// Connect is the subset of CONNECT that SensorHub reads.
type Connect struct {
	ClientID  string
	Level     byte
	KeepAlive uint16
}

// EncodeConnect builds a clean-session CONNECT with no credentials.
func EncodeConnect(c Connect) []byte {
	if c.Level == 0 {
		c.Level = ProtocolLevel4
	}
	body := appendString(nil, "MQTT")
	body = append(body, c.Level, 0x02) // 0x02: clean session, no will, no credentials
	body = binary.BigEndian.AppendUint16(body, c.KeepAlive)
	return appendString(body, c.ClientID)
}

// DecodeConnect parses a CONNECT body.
//
// A CONNECT carrying a username or password is refused rather than ignored.
// Devices authenticate with a client certificate; accepting a second,
// password-shaped identity would create a weaker path to the same topic, which
// is the kind of thing threat "spoofed_device_telemetry" is about.
func DecodeConnect(body []byte) (Connect, error) {
	name, rest, err := decodeString(body)
	if err != nil {
		return Connect{}, err
	}
	if name != "MQTT" {
		return Connect{}, fmt.Errorf("%w: protocol name %q", ErrMalformed, name)
	}
	if len(rest) < 4 {
		return Connect{}, ErrMalformed
	}
	level, flags := rest[0], rest[1]
	if level != ProtocolLevel4 {
		return Connect{}, fmt.Errorf("%w: unsupported protocol level %d", ErrMalformed, level)
	}
	if flags&0xC0 != 0 {
		return Connect{}, ErrCredsInCon
	}
	keepAlive := binary.BigEndian.Uint16(rest[2:4])
	clientID, _, err := decodeString(rest[4:])
	if err != nil {
		return Connect{}, err
	}
	return Connect{ClientID: clientID, Level: level, KeepAlive: keepAlive}, nil
}

// ConnAck return codes used by the ingest server.
const (
	ConnAccepted           byte = 0
	ConnRefusedBadProtocol byte = 1
	ConnRefusedNotAuthed   byte = 5
)

// WriteConnAck writes a CONNACK with no session present.
func WriteConnAck(w io.Writer, code byte) error {
	return Write(w, CONNACK, 0, []byte{0x00, code})
}

// ReadConnAck reads a CONNACK and returns its return code.
func ReadConnAck(r *bufio.Reader) (byte, error) {
	p, err := Read(r, 8)
	if err != nil {
		return 0, err
	}
	if p.Type != CONNACK || len(p.Body) != 2 {
		return 0, fmt.Errorf("%w: expected CONNACK, got %s", ErrMalformed, p.Type)
	}
	return p.Body[1], nil
}

// Publish is an application message.
type Publish struct {
	Topic    string
	QoS      byte
	PacketID uint16
	Payload  []byte
}

// EncodePublish returns the fixed-header flags and body for a PUBLISH.
func EncodePublish(p Publish) (byte, []byte) {
	body := appendString(nil, p.Topic)
	if p.QoS > 0 {
		body = binary.BigEndian.AppendUint16(body, p.PacketID)
	}
	return (p.QoS & 0x03) << 1, append(body, p.Payload...)
}

// DecodePublish parses a PUBLISH body given its fixed-header flags.
func DecodePublish(flags byte, body []byte) (Publish, error) {
	qos := (flags >> 1) & 0x03
	if qos > 1 {
		// QoS 2 needs four-way delivery state per message. SensorHub does not
		// use it, so it is refused rather than half-implemented.
		return Publish{}, fmt.Errorf("%w: unsupported QoS %d", ErrMalformed, qos)
	}
	topic, rest, err := decodeString(body)
	if err != nil {
		return Publish{}, err
	}
	p := Publish{Topic: topic, QoS: qos}
	if qos > 0 {
		if len(rest) < 2 {
			return Publish{}, ErrMalformed
		}
		p.PacketID = binary.BigEndian.Uint16(rest[:2])
		rest = rest[2:]
	}
	p.Payload = rest
	return p, nil
}

// WritePubAck acknowledges a QoS 1 publish.
func WritePubAck(w io.Writer, packetID uint16) error {
	return Write(w, PUBACK, 0, binary.BigEndian.AppendUint16(nil, packetID))
}

func appendString(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint16(b, uint16(len(s)))
	return append(b, s...)
}

func decodeString(b []byte) (string, []byte, error) {
	if len(b) < 2 {
		return "", nil, ErrMalformed
	}
	n := int(binary.BigEndian.Uint16(b[:2]))
	if len(b) < 2+n {
		return "", nil, ErrMalformed
	}
	return string(b[2 : 2+n]), b[2+n:], nil
}

// readVarint reads MQTT's remaining-length encoding: seven bits per byte, at
// most four bytes.
func readVarint(r *bufio.Reader) (int, error) {
	var value, multiplier int
	for range 4 {
		b, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		value += int(b&0x7f) << multiplier
		if b&0x80 == 0 {
			return value, nil
		}
		multiplier += 7
	}
	return 0, fmt.Errorf("%w: remaining length is not terminated", ErrMalformed)
}

func appendVarint(b []byte, n int) []byte {
	for {
		digit := byte(n % 128)
		n /= 128
		if n > 0 {
			digit |= 0x80
		}
		b = append(b, digit)
		if n == 0 {
			return b
		}
	}
}
