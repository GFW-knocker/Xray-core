package noise

// Named packet generators, an alternative to handing "packet" a literal blob.
//
// A generator differs from a literal in the one way that matters here: it is
// re-rolled on every datagram, so the connection IDs and padding are never the
// same twice. A 1200-byte literal would work against the classifiers described
// below, but it would put a byte-identical blob on the wire for every
// connection the client ever makes.
//
// The packet shapes are xray's WireGuard noise (GFW-knocker/wireguard
// device/send.go), so a name that works as a WireGuard outbound's "wnoise"
// works here unchanged. That package holds the other copy of these constants;
// it is upstream of this module and cannot import it, so the two have to be
// kept in step by hand.

import (
	"crypto/rand"

	"github.com/GFW-knocker/Xray-core/common/crypto"
)

const (
	GenQUIC     = "quic"     // QUIC v2, RFC 9369
	GenQUICv1   = "quicv1"   // QUIC v1, RFC 9000
	GenQUICInit = "quicinit" // a structurally valid v2 client Initial
)

// quicInitSize is the length of a "quicinit" datagram. RFC 9000 14.1 requires a
// client Initial to be padded to at least 1200 bytes, and that turns out to be
// load-bearing rather than cosmetic: measured against Cloudflare edges from a
// filtered path, a 1200-byte prime let the following handshake through 10/10,
// 1100 bytes 4/10, and anything at or below 1000 bytes 0-3/10. The classifier
// only files a flow as QUIC on a datagram that could actually be a conformant
// Initial.
const quicInitSize = 1200

// Version fields for the header presets, which is the only part of the header
// the filters they defeat are known to read.
var (
	quicVersion2 = []byte{0x6B, 0x33, 0x43, 0xCF} // RFC 9369
	quicVersion1 = []byte{0x00, 0x00, 0x00, 0x01} // RFC 9000
)

// IsGenerator reports whether name is a known generator. The config builder
// uses it to reject a typo, which would otherwise send nothing at all and look
// exactly like noise that did not help.
func IsGenerator(name string) bool {
	switch name {
	case GenQUIC, GenQUICv1, GenQUICInit:
		return true
	default:
		return false
	}
}

// IsFixedSize reports whether a generator produces a whole datagram whose
// length is itself what makes it work, so that appending a "rand" payload would
// destroy the property it exists for.
func IsFixedSize(name string) bool {
	return name == GenQUICInit
}

// generate builds one datagram for the named generator, re-rolled per call.
//
// A nil return means the entropy pool could not be read, and the caller sends
// nothing rather than a malformed prime: a prime with the wrong first byte does
// not merely fail to help, it files the flow as QUIC and poisons it.
func generate(name string) []byte {
	switch name {
	case GenQUIC:
		return quicHeader(quicVersion2)
	case GenQUICv1:
		return quicHeader(quicVersion1)
	case GenQUICInit:
		return quicInitPacket()
	default:
		return nil
	}
}

// quicHeader builds the 18-byte pseudo-QUIC long header.
//
// It is not a valid packet and does not need to be: the length varint claims
// 1232 bytes with nothing like that many following. What it carries is a
// version number in bytes 1..4 and enough of a long header in front of it to
// get that far. On its own this primes a QUIC flow only about one time in four
// -- see GenQUICInit for the shape that works -- but it is what a WireGuard
// flow needs, and is kept for parity with "wnoise".
func quicHeader(version []byte) []byte {
	// The first byte's high nibble names a long-header packet type, and its low
	// nibble is header-protected in a real packet. The type is irrelevant to
	// the filters this defeats, so it is drawn from a list rather than fixed,
	// to avoid handing anyone a constant byte to match on.
	clist := []byte{0xDC, 0xDE, 0xD3, 0xD9, 0xD0, 0xEC, 0xEE, 0xE3}

	dcid := make([]byte, 8)
	if _, err := rand.Read(dcid); err != nil {
		return nil
	}
	h := make([]byte, 0, 18)
	// RandBetween's upper bound is exclusive, so len(clist) covers every index.
	h = append(h, clist[crypto.RandBetween(0, int64(len(clist)))])
	h = append(h, version...)
	h = append(h, 0x08) // DCID length
	h = append(h, dcid...)
	h = append(h, 0x00, 0x00, 0x44, 0xD0) // SCID length, token length, length varint
	return h
}

// quicInitPacket builds a complete, structurally valid QUIC v2 client Initial
// of quicInitSize bytes, with a random payload where the CRYPTO frames would
// be. It decrypts to nothing, which is fine: no peer is meant to answer it.
//
// Two fields are load-bearing and were isolated by ablation against a
// Cloudflare edge, holding everything else constant:
//
//   - The first byte must be in 0xc0-0xcf, the long-header Initial encoding.
//     0xc0, 0xc3 and 0xcf each primed the flow 10/10; 0xd0 and 0xf0 gave 0/10,
//     and the bytes quicHeader draws from (0xdc, 0xee, ...) gave 1-3/10. Note
//     this is the *v1* meaning of the type bits even though the version says
//     v2, where 0b00 would be Retry. The classifier is matching the v1
//     encoding, not honouring RFC 9369's remap.
//   - The version must not be v1 or a draft. v2 and a reserved value both gave
//     10/10; draft-29 and v1 both gave 0/10.
//
// Padding content, SCID length and the length varint made no difference
// (10/10 either way), so they are filled the way a real client would.
func quicInitPacket() []byte {
	p := make([]byte, quicInitSize)
	if _, err := rand.Read(p); err != nil {
		return nil
	}
	p[0] = 0xC0 | (p[0] & 0x0F) // long header, Initial; low nibble is free
	copy(p[1:5], quicVersion2)
	p[5] = 8     // DCID length, bytes 6..13 stay random
	p[14] = 8    // SCID length, bytes 15..22 stay random
	p[23] = 0x00 // token length
	p[24], p[25] = 0x44, 0x00
	return p
}
