package masque

import (
	"bufio"
	"io"
	"net/netip"

	"github.com/GFW-knocker/Xray-core/common/errors"
	"github.com/apernet/quic-go/quicvarint"
)

// The capsule types of CONNECT-IP, RFC 9484 section 4.7. A capsule is framed as
// a varint type, a varint length, and that many bytes of value (RFC 9297).
type capsuleType uint64

const (
	capsuleDatagram           capsuleType = 0x00
	capsuleAddressAssign      capsuleType = 0x01
	capsuleAddressRequest     capsuleType = 0x02
	capsuleRouteAdvertisement capsuleType = 0x03
)

// connectIPContextID is the context this tunnel carries plain IP packets in.
// Zero is the only one CONNECT-IP defines.
const connectIPContextID uint64 = 0

// maxCapsuleValue bounds what one capsule may claim to be, so a corrupt or
// hostile length cannot make us allocate without limit. The largest capsule the
// edge has any reason to send is one IP packet.
const maxCapsuleValue = 256 * 1024

// AssignedAddress is one address the edge handed the tunnel, from an
// ADDRESS_ASSIGN capsule.
type AssignedAddress struct {
	RequestID uint64
	Prefix    netip.Prefix
}

// AdvertisedRoute is one range the edge says it will route, from a
// ROUTE_ADVERTISEMENT capsule. Protocol 0 means every protocol.
type AdvertisedRoute struct {
	Start    netip.Addr
	End      netip.Addr
	Protocol uint8
}

func appendCapsule(dst []byte, kind capsuleType, value []byte) []byte {
	dst = quicvarint.Append(dst, uint64(kind))
	dst = quicvarint.Append(dst, uint64(len(value)))
	return append(dst, value...)
}

// appendDatagramCapsule frames one IP packet for the HTTP/2 carrier, where there
// are no datagrams and everything rides the request stream.
//
// The packet goes in bare, with no context ID in front of it, which is what
// Cloudflare's edge expects even though RFC 9484 puts one there. The receive
// side takes it either way.
func appendDatagramCapsule(dst []byte, packet []byte) []byte {
	return appendCapsule(dst, capsuleDatagram, packet)
}

// appendH3Datagram frames one IP packet for the HTTP/3 carrier. Only the context
// ID is added: the quarter stream ID that RFC 9297 puts first is quic-go's to
// write, since it owns the stream.
func appendH3Datagram(dst []byte, packet []byte) []byte {
	dst = quicvarint.Append(dst, connectIPContextID)
	return append(dst, packet...)
}

// capsuleReader reads capsules off the request stream.
type capsuleReader struct {
	source *bufio.Reader
	value  []byte
}

func newCapsuleReader(r io.Reader) *capsuleReader {
	return &capsuleReader{source: bufio.NewReader(r)}
}

// next returns the next capsule, blocking until one is complete. It reports
// io.EOF once the stream ends cleanly between capsules.
//
// The returned value is only good until the next call: it is a window onto a
// buffer this reader reuses, which is what keeps the HTTP/2 carrier from
// allocating once per packet. Copy it if it has to outlive the call.
func (c *capsuleReader) next() (capsuleType, []byte, error) {
	kind, err := quicvarint.Read(c.source)
	if err != nil {
		// Between capsules, the end of the stream is just the end of the stream.
		return 0, nil, err
	}

	length, err := quicvarint.Read(c.source)
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return 0, nil, errors.New("masque: capsule ", kind, " has no length").Base(err)
	}
	if length > maxCapsuleValue {
		return 0, nil, errors.New("masque: capsule ", kind, " claims ", length, " bytes, over the ", maxCapsuleValue, " byte limit")
	}

	if uint64(cap(c.value)) < length {
		c.value = make([]byte, length)
	}
	value := c.value[:length]
	if _, err := io.ReadFull(c.source, value); err != nil {
		return 0, nil, errors.New("masque: capsule ", kind, " was cut short").Base(err)
	}
	return capsuleType(kind), value, nil
}

// parseAddressAssign reads an ADDRESS_ASSIGN capsule, which carries one entry
// per address: a request ID, an IP version, the address, and a prefix length.
func parseAddressAssign(value []byte) ([]AssignedAddress, error) {
	var assigned []AssignedAddress
	for len(value) > 0 {
		requestID, n, err := quicvarint.Parse(value)
		if err != nil {
			return nil, errors.New("masque: ADDRESS_ASSIGN has a malformed request ID").Base(err)
		}
		value = value[n:]

		addr, rest, err := parseVersionedAddress(value)
		if err != nil {
			return nil, errors.New("masque: ADDRESS_ASSIGN").Base(err)
		}
		value = rest

		if len(value) < 1 {
			return nil, errors.New("masque: ADDRESS_ASSIGN ends before its prefix length")
		}
		bits := int(value[0])
		value = value[1:]
		if bits > addr.BitLen() {
			return nil, errors.New("masque: ADDRESS_ASSIGN gives ", addr, " a /", bits, " prefix")
		}

		assigned = append(assigned, AssignedAddress{
			RequestID: requestID,
			Prefix:    netip.PrefixFrom(addr, bits),
		})
	}
	return assigned, nil
}

// parseRouteAdvertisement reads a ROUTE_ADVERTISEMENT capsule, which carries one
// entry per range: an IP version, the first and last address of the range, and a
// protocol. One version byte covers both addresses.
func parseRouteAdvertisement(value []byte) ([]AdvertisedRoute, error) {
	var routes []AdvertisedRoute
	for len(value) > 0 {
		size, err := addressSize(value[0])
		if err != nil {
			return nil, errors.New("masque: ROUTE_ADVERTISEMENT").Base(err)
		}
		value = value[1:]

		// Two addresses and the protocol byte.
		if len(value) < 2*size+1 {
			return nil, errors.New("masque: ROUTE_ADVERTISEMENT ends part way through a range")
		}
		start, _ := netip.AddrFromSlice(value[:size])
		end, _ := netip.AddrFromSlice(value[size : 2*size])
		protocol := value[2*size]
		value = value[2*size+1:]

		routes = append(routes, AdvertisedRoute{Start: start, End: end, Protocol: protocol})
	}
	return routes, nil
}

// parseVersionedAddress reads the "IP version then address" shape, and returns
// what is left after it.
func parseVersionedAddress(value []byte) (netip.Addr, []byte, error) {
	if len(value) < 1 {
		return netip.Addr{}, nil, errors.New("ends before its IP version")
	}
	size, err := addressSize(value[0])
	if err != nil {
		return netip.Addr{}, nil, err
	}
	value = value[1:]

	if len(value) < size {
		return netip.Addr{}, nil, errors.New("ends before its ", size, " byte address")
	}
	addr, ok := netip.AddrFromSlice(value[:size])
	if !ok {
		return netip.Addr{}, nil, errors.New("has an address that will not parse")
	}
	return addr, value[size:], nil
}

func addressSize(version byte) (int, error) {
	switch version {
	case 4:
		return 4, nil
	case 6:
		return 16, nil
	default:
		return 0, errors.New("has IP version ", version, ", want 4 or 6")
	}
}

// stripDatagramContext takes the IP packet out of a DATAGRAM capsule's value or
// an HTTP/3 datagram's payload.
//
// RFC 9484 puts a context ID in front of the packet; Cloudflare's edge sends the
// packet bare on the HTTP/2 carrier. Both are accepted, which is safe because
// the first byte of an IP packet cannot be read as a zero varint: an IPv4 packet
// starts 0x45, which is a two-byte varint of 1349, and an IPv6 packet starts
// 0x6_, which is four bytes.
func stripDatagramContext(payload []byte) ([]byte, bool) {
	if len(payload) == 0 {
		return nil, false
	}

	if context, n, err := quicvarint.Parse(payload); err == nil && context == connectIPContextID {
		if inner := payload[n:]; looksLikeIPPacket(inner) {
			return inner, true
		}
	}
	if looksLikeIPPacket(payload) {
		return payload, true
	}
	return nil, false
}

// looksLikeIPPacket is the same shape check the netstack does before it accepts
// a packet, used here to tell a context-prefixed payload from a bare one.
func looksLikeIPPacket(b []byte) bool {
	if len(b) < 20 {
		return false
	}
	version := b[0] >> 4
	return version == 4 || version == 6
}
