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
