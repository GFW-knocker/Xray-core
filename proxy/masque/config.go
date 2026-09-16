package masque

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

// DefaultMTU is deliberately conservative. Every inner IP packet has to fit in
// one QUIC datagram, which cannot be fragmented, inside a QUIC packet, inside
// the path MTU, and a udpmask that prepends a header takes another bite out of
// that. 1280 is the smallest MTU IPv6 guarantees, so it clears all of it.
const DefaultMTU = 1280
