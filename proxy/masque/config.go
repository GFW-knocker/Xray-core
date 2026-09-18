package masque

import "time"

// Defaults for Cloudflare's consumer MASQUE service, which is what this outbound
// is built against. They are not part of any RFC: the edge answers extended
// CONNECT on a fixed authority and path, and names its own protocol token rather
// than RFC 9484's "connect-ip". A different MASQUE server will want all three
// set explicitly.
const (
	DefaultAuthority       = "cloudflareaccess.com"
	DefaultPath            = "/"
	DefaultConnectProtocol = "cf-connect-ip"
	DefaultSNI             = "consumer-masque.cloudflareclient.com"
)

// Defaults for the HTTP/2 carrier's keepalive, taken from the reference client
// (aether v2.0.0, masque_h2.rs): ping every fifteen seconds, and give the tunnel
// up after twenty seconds without an answer.
//
// The timeout is what makes this more than a NAT keepalive. Without it a
// connection the edge has quietly dropped stays "open" until something tries to
// write, so the failure lands on a user's connection instead of on a reconnect.
const (
	DefaultKeepAlivePeriod  = 15 * time.Second
	DefaultKeepAliveTimeout = 20 * time.Second
)

// keepAlive turns the configured seconds into the pair the HTTP/2 transport
// wants. A negative period is how a configuration asks for no ping at all;
// zero, the unset value, takes the defaults.
func (c *Config) keepAlive() (period, timeout time.Duration) {
	switch {
	case c.KeepAlivePeriod < 0:
		period = 0 // x/net/http2 reads a zero ReadIdleTimeout as "no health check"
	case c.KeepAlivePeriod == 0:
		period = DefaultKeepAlivePeriod
	default:
		period = time.Duration(c.KeepAlivePeriod) * time.Second
	}

	if c.KeepAliveTimeout > 0 {
		timeout = time.Duration(c.KeepAliveTimeout) * time.Second
	} else {
		timeout = DefaultKeepAliveTimeout
	}
	return period, timeout
}

// DefaultMTU is deliberately conservative. Every inner IP packet has to fit in
// one QUIC datagram, which cannot be fragmented, inside a QUIC packet, inside
// the path MTU, and a udpmask that prepends a header takes another bite out of
// that. 1280 is the smallest MTU IPv6 guarantees, so it clears all of it.
const DefaultMTU = 1280

// Packet sizes for a tunnel that carries another tunnel.
//
// Chaining one HTTP/3 tunnel through another is a size problem before it is
// anything else. The inner IP packets of the chained tunnel travel as QUIC
// datagrams of the tunnel underneath, and a datagram has to fit in one QUIC
// packet -- it cannot be fragmented and cannot be split across packets. So the
// tunnel underneath has to send packets big enough to hold the other tunnel's,
// and the chained tunnel has to keep its own small enough to fit.
//
// quic-go sizes packets at 1280 by default, which leaves 1243 bytes of datagram
// -- about thirty short of what a chained tunnel sends. Nothing reports this:
// the tunnels both come up, small requests work, and anything that fills a
// packet disappears. These are the numbers that make the two fit, and they are
// the ones the aether client uses.
const (
	// MaxPacketSize is the largest QUIC packet a carrying tunnel sends. Large
	// enough that its datagrams hold a DefaultMTU packet with room for headers.
	MaxPacketSize = 1350
	// MinPacketSize is quic-go's floor, and QUIC's.
	MinPacketSize = 1200
	// packetOverhead is how much bigger a QUIC packet is than the IP packet its
	// datagram carries: QUIC framing, the datagram frame header, and the h3
	// datagram's context id.
	packetOverhead = MaxPacketSize - DefaultMTU
)

// chainedPacketSize is the QUIC packet size for a tunnel dialled through
// another one, given the MTU of the tunnel underneath.
//
// The packets this tunnel sends become IP packets on the tunnel underneath, so
// they have to leave room for that tunnel's IP and UDP headers.
func chainedPacketSize(carrierMTU int, carrierIsIPv6 bool) int {
	headers := 28 // IPv4 + UDP
	if carrierIsIPv6 {
		headers = 48
	}
	return clampPacketSize(carrierMTU - headers)
}

// chainedMTU is the interface MTU that goes with a packet size, so the packets
// this tunnel's own netstack produces fit in its own datagrams.
func chainedMTU(packetSize int) int {
	mtu := packetSize - packetOverhead
	if mtu < 576 {
		mtu = 576
	}
	if mtu > 1500 {
		mtu = 1500
	}
	return mtu
}

func clampPacketSize(size int) int {
	if size < MinPacketSize {
		return MinPacketSize
	}
	if size > MaxPacketSize {
		return MaxPacketSize
	}
	return size
}
