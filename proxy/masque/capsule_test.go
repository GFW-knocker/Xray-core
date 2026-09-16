package masque

import (
	"bytes"
	"errors"
	"io"
	"net/netip"
	"strings"
	"testing"

	"github.com/apernet/quic-go/quicvarint"
)

// ipv4Packet is the smallest thing looksLikeIPPacket will accept, with a
// recognisable last byte so packets can be told apart.
func ipv4Packet(mark byte) []byte {
	p := make([]byte, 20)
	p[0] = 0x45
	p[9] = 17 // UDP
	p[19] = mark
	return p
}

func ipv6Packet(mark byte) []byte {
	p := make([]byte, 40)
	p[0] = 0x60
	p[39] = mark
	return p
}

func TestCapsuleRoundTrip(t *testing.T) {
	var wire []byte
	wire = appendCapsule(wire, capsuleAddressRequest, []byte("hello"))

	reader := newCapsuleReader(bytes.NewReader(wire))
	kind, value, err := reader.next()
	if err != nil {
		t.Fatalf("next: %v", err)
	}
	if kind != capsuleAddressRequest {
		t.Errorf("type = %d, want %d", kind, capsuleAddressRequest)
	}
	if string(value) != "hello" {
		t.Errorf("value = %q, want %q", value, "hello")
	}

	if _, _, err := reader.next(); !errors.Is(err, io.EOF) {
		t.Errorf("after the last capsule the error is %v, want io.EOF", err)
	}
}

// Several packets written back to back have to come back out one at a time, in
// order: on the HTTP/2 carrier this is how every packet travels.
func TestCapsulesWrittenBackToBackStaySeparable(t *testing.T) {
	first, second, third := ipv4Packet(1), ipv4Packet(2), ipv6Packet(3)

	var wire []byte
	for _, p := range [][]byte{first, second, third} {
		wire = appendDatagramCapsule(wire, p)
	}

	reader := newCapsuleReader(bytes.NewReader(wire))
	var got [][]byte
	for {
		kind, value, err := reader.next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("next: %v", err)
		}
		if kind != capsuleDatagram {
			t.Fatalf("type = %d, want DATAGRAM", kind)
		}
		packet, ok := stripDatagramContext(value)
		if !ok {
			t.Fatalf("a DATAGRAM capsule did not yield a packet")
		}
		// The reader reuses its buffer, so this has to be copied to be kept.
		got = append(got, bytes.Clone(packet))
	}

	if len(got) != 3 {
		t.Fatalf("read %d packets, want 3", len(got))
	}
	for i, want := range [][]byte{first, second, third} {
		if !bytes.Equal(got[i], want) {
			t.Errorf("packet %d = %x, want %x", i, got[i], want)
		}
	}
}

// The edge wants the packet bare in a DATAGRAM capsule, without the context ID
// RFC 9484 would put there.
func TestDatagramCapsuleCarriesTheBarePacket(t *testing.T) {
	packet := ipv4Packet(9)
	wire := appendDatagramCapsule(nil, packet)

	reader := newCapsuleReader(bytes.NewReader(wire))
	_, value, err := reader.next()
	if err != nil {
		t.Fatalf("next: %v", err)
	}
	if !bytes.Equal(value, packet) {
		t.Errorf("capsule value = %x, want the packet itself %x", value, packet)
	}
}

// The HTTP/3 carrier does put the context ID in front, because quic-go writes
// only the quarter stream ID.
func TestH3DatagramCarriesTheContextID(t *testing.T) {
	packet := ipv4Packet(7)
	payload := appendH3Datagram(nil, packet)

	if len(payload) != len(packet)+1 || payload[0] != 0x00 {
		t.Fatalf("payload starts %x, want a single zero context ID then the packet", payload[:1])
	}
	got, ok := stripDatagramContext(payload)
	if !ok {
		t.Fatal("the payload did not yield a packet")
	}
	if !bytes.Equal(got, packet) {
		t.Errorf("packet = %x, want %x", got, packet)
	}
}

func TestStripDatagramContext(t *testing.T) {
	for _, c := range []struct {
		name    string
		payload []byte
		want    []byte
	}{
		{"bare ipv4", ipv4Packet(1), ipv4Packet(1)},
		{"bare ipv6", ipv6Packet(1), ipv6Packet(1)},
		{"context then ipv4", append([]byte{0x00}, ipv4Packet(2)...), ipv4Packet(2)},
		{"context then ipv6", append([]byte{0x00}, ipv6Packet(2)...), ipv6Packet(2)},
		{"empty", nil, nil},
		{"too short to be a packet", []byte{0x45, 0x00, 0x00}, nil},
		{"not an IP version", bytes.Repeat([]byte{0xff}, 40), nil},
		{"context then rubbish", append([]byte{0x00}, bytes.Repeat([]byte{0xff}, 40)...), nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, ok := stripDatagramContext(c.payload)
			if c.want == nil {
				if ok {
					t.Errorf("accepted %x, want it refused", c.payload)
				}
				return
			}
			if !ok {
				t.Fatalf("refused %x, want it accepted", c.payload)
			}
			if !bytes.Equal(got, c.want) {
				t.Errorf("packet = %x, want %x", got, c.want)
			}
		})
	}
}

func TestParseAddressAssign(t *testing.T) {
	var value []byte
	value = quicvarint.Append(value, 7)
	value = append(value, 4, 172, 16, 0, 2, 32)
	value = quicvarint.Append(value, 8)
	value = append(value, 6)
	value = append(value, netip.MustParseAddr("2606:4700:110:8a1b::1").AsSlice()...)
	value = append(value, 128)

	assigned, err := parseAddressAssign(value)
	if err != nil {
		t.Fatalf("parseAddressAssign: %v", err)
	}
	if len(assigned) != 2 {
		t.Fatalf("got %d addresses, want 2", len(assigned))
	}
	if got, want := assigned[0].Prefix.String(), "172.16.0.2/32"; got != want {
		t.Errorf("first prefix = %s, want %s", got, want)
	}
	if assigned[0].RequestID != 7 {
		t.Errorf("first request ID = %d, want 7", assigned[0].RequestID)
	}
	if got, want := assigned[1].Prefix.String(), "2606:4700:110:8a1b::1/128"; got != want {
		t.Errorf("second prefix = %s, want %s", got, want)
	}
}

func TestParseAddressAssignRejectsBadInput(t *testing.T) {
	for _, c := range []struct {
		name, want string
		value      []byte
	}{
		{"unknown IP version", "IP version", []byte{0x01, 9, 1, 2, 3, 4, 32}},
		{"truncated address", "before its 4 byte address", []byte{0x01, 4, 172, 16}},
		{"no prefix length", "before its prefix length", []byte{0x01, 4, 172, 16, 0, 2}},
		{"prefix too long for the family", "prefix", []byte{0x01, 4, 172, 16, 0, 2, 33}},
		{"nothing after the request ID", "IP version", []byte{0x01}},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := parseAddressAssign(c.value)
			if err == nil {
				t.Fatalf("parse succeeded, want an error mentioning %q", c.want)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error is %q, want it to mention %q", err, c.want)
			}
		})
	}
}

func TestParseRouteAdvertisement(t *testing.T) {
	value := []byte{4, 10, 0, 0, 0, 10, 255, 255, 255, 0}
	value = append(value, 6)
	value = append(value, netip.MustParseAddr("::").AsSlice()...)
	value = append(value, netip.MustParseAddr("ffff::").AsSlice()...)
	value = append(value, 17)

	routes, err := parseRouteAdvertisement(value)
	if err != nil {
		t.Fatalf("parseRouteAdvertisement: %v", err)
	}
	if len(routes) != 2 {
		t.Fatalf("got %d routes, want 2", len(routes))
	}
	if got, want := routes[0].Start.String(), "10.0.0.0"; got != want {
		t.Errorf("first start = %s, want %s", got, want)
	}
	if got, want := routes[0].End.String(), "10.255.255.255"; got != want {
		t.Errorf("first end = %s, want %s", got, want)
	}
	if routes[0].Protocol != 0 {
		t.Errorf("first protocol = %d, want 0 (any)", routes[0].Protocol)
	}
	if got, want := routes[1].End.String(), "ffff::"; got != want {
		t.Errorf("second end = %s, want %s", got, want)
	}
	if routes[1].Protocol != 17 {
		t.Errorf("second protocol = %d, want 17", routes[1].Protocol)
	}
}

func TestParseRouteAdvertisementRejectsBadInput(t *testing.T) {
	for _, c := range []struct {
		name, want string
		value      []byte
	}{
		{"unknown IP version", "IP version", []byte{9, 1, 2, 3, 4}},
		{"range cut short", "part way through", []byte{4, 10, 0, 0, 0, 10, 255}},
		{"no protocol", "part way through", []byte{4, 10, 0, 0, 0, 10, 255, 255, 255}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := parseRouteAdvertisement(c.value); err == nil {
				t.Fatalf("parse succeeded, want an error mentioning %q", c.want)
			} else if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error is %q, want it to mention %q", err, c.want)
			}
		})
	}
}

// A length field is the one place a hostile peer can ask for an unbounded
// allocation, so it is capped rather than trusted.
func TestCapsuleReaderRefusesAnAbsurdLength(t *testing.T) {
	var wire []byte
	wire = quicvarint.Append(wire, uint64(capsuleDatagram))
	wire = quicvarint.Append(wire, 1<<30)
	wire = append(wire, 1, 2, 3)

	_, _, err := newCapsuleReader(bytes.NewReader(wire)).next()
	if err == nil {
		t.Fatal("the reader accepted a capsule claiming a gigabyte")
	}
	if !strings.Contains(err.Error(), "limit") {
		t.Errorf("error is %q, want it to mention the limit", err)
	}
}

func TestCapsuleReaderReportsATruncatedCapsule(t *testing.T) {
	full := appendDatagramCapsule(nil, ipv4Packet(1))

	_, _, err := newCapsuleReader(bytes.NewReader(full[:len(full)-4])).next()
	if err == nil {
		t.Fatal("the reader accepted a capsule that stops early")
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("error is %v, want it to wrap io.ErrUnexpectedEOF", err)
	}
}

// RFC 9297 says unknown capsule types are to be skipped, so the reader hands
// them over rather than failing and the caller decides.
func TestCapsuleReaderPassesUnknownTypesThrough(t *testing.T) {
	var wire []byte
	wire = appendCapsule(wire, capsuleType(0x4242), []byte("who knows"))
	wire = appendDatagramCapsule(wire, ipv4Packet(5))

	reader := newCapsuleReader(bytes.NewReader(wire))
	kind, value, err := reader.next()
	if err != nil {
		t.Fatalf("next: %v", err)
	}
	if kind != capsuleType(0x4242) || string(value) != "who knows" {
		t.Errorf("got type %d value %q, want the unknown capsule intact", kind, value)
	}

	kind, _, err = reader.next()
	if err != nil {
		t.Fatalf("next after the unknown capsule: %v", err)
	}
	if kind != capsuleDatagram {
		t.Errorf("type = %d, want the DATAGRAM that followed", kind)
	}
}

func FuzzCapsuleReader(f *testing.F) {
	f.Add(appendDatagramCapsule(nil, ipv4Packet(1)))
	f.Add(appendCapsule(nil, capsuleAddressAssign, []byte{0x01, 4, 172, 16, 0, 2, 32}))
	f.Add([]byte{0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		reader := newCapsuleReader(bytes.NewReader(data))
		for i := 0; i < 32; i++ {
			kind, value, err := reader.next()
			if err != nil {
				return
			}
			switch kind {
			case capsuleAddressAssign:
				parseAddressAssign(value)
			case capsuleRouteAdvertisement:
				parseRouteAdvertisement(value)
			case capsuleDatagram:
				stripDatagramContext(value)
			}
		}
	})
}

func FuzzParseAddressAssign(f *testing.F) {
	f.Add([]byte{0x01, 4, 172, 16, 0, 2, 32})
	f.Add([]byte{0x01, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 128})
	f.Fuzz(func(t *testing.T, data []byte) {
		parseAddressAssign(data)
		parseRouteAdvertisement(data)
	})
}
