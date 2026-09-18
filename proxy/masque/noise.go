package masque

// Built-in noise: datagrams put on the wire ahead of the QUIC handshake.
//
// This duplicates the packet shapes in transport/internet/finalmask/noise
// rather than importing them, for the same reason the netstack here is a copy:
// the outbound owns its own behaviour and does not change when a shared package
// does. The two are kept in step by hand, and the shapes are the WireGuard
// outbound's "wnoise" shapes, so a profile written for that outbound means the
// same thing here.
//
// It is also independent of the udpmasks in every direction. A mask configured
// in streamSettings still applies, and applies *around* this: the noise is
// written through the masked connection, so a mask that prepends a header or
// adds its own noise treats these datagrams exactly as it treats real ones.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	"github.com/GFW-knocker/Xray-core/common/crypto"
	"github.com/GFW-knocker/Xray-core/common/errors"
	"github.com/GFW-knocker/Xray-core/common/net"
)

// Generator names accepted by "wnoise", matching the WireGuard outbound.
const (
	NoiseNone     = "none"
	NoiseRandom   = "random"
	NoiseQUIC     = "quic"     // QUIC v2 long header, RFC 9369
	NoiseQUICv1   = "quicv1"   // QUIC v1 long header, RFC 9000
	NoiseQUICInit = "quicinit" // a complete, conformant v2 client Initial
)

// Defaults, again the WireGuard outbound's: one or two datagrams, five to ten
// milliseconds apart, five to ten bytes of payload.
const (
	defaultNoiseCountFrom   = 1
	defaultNoiseCountTo     = 2
	defaultNoiseDelayFrom   = 5
	defaultNoiseDelayTo     = 10
	defaultPayloadSizeFrom  = 5
	defaultPayloadSizeTo    = 10
	maxNoiseCount           = 50
	maxNoiseDelay           = 100
	maxPayloadSize          = 100
	maxNoiseHeaderHexLength = 100
)

// quicInitSize is fixed by RFC 9000 14.1, which requires a client Initial to be
// padded to at least 1200 bytes. That is load-bearing rather than cosmetic: a
// classifier only files a flow as QUIC on a datagram that could actually be a
// conformant Initial, and a shorter one does not prime the path.
const quicInitSize = 1200

var (
	quicVersion2 = []byte{0x6B, 0x33, 0x43, 0xCF} // RFC 9369
	quicVersion1 = []byte{0x00, 0x00, 0x00, 0x01} // RFC 9000
)

// noiseConfig is the parsed form of the four settings.
type noiseConfig struct {
	// head is the fixed start of every datagram: a generated header, a literal
	// from a hex "wnoise", or nothing at all for "random".
	gen    string
	header []byte

	countFrom, countTo     int
	delayFrom, delayTo     int
	payloadFrom, payloadTo int
}

// enabled reports whether anything should be sent. "" and "none" are off, which
// is what a configuration that never mentions noise gets.
func (c *noiseConfig) enabled() bool {
	return c != nil && c.gen != "" && c.gen != NoiseNone
}

// parseNoise turns the four strings into something sendable.
//
// Unparseable numbers fall back to the defaults rather than failing, matching
// the WireGuard outbound: these are obfuscation knobs, and refusing to start
// over a malformed range would be worse than quietly using a sane one. A
// "wnoise" that names nothing recognisable is treated as a hex literal, which
// is also how that outbound reads it.
func parseNoise(conf *Config) *noiseConfig {
	c := &noiseConfig{
		gen:         strings.ToLower(strings.TrimSpace(conf.Wnoise)),
		countFrom:   defaultNoiseCountFrom,
		countTo:     defaultNoiseCountTo,
		delayFrom:   defaultNoiseDelayFrom,
		delayTo:     defaultNoiseDelayTo,
		payloadFrom: defaultPayloadSizeFrom,
		payloadTo:   defaultPayloadSizeTo,
	}

	switch c.gen {
	case "", NoiseNone, NoiseRandom, NoiseQUIC, NoiseQUICv1, NoiseQUICInit:
	default:
		// A hex literal. Odd length is padded and anything past the cap is
		// dropped, both to match the WireGuard outbound exactly.
		text := conf.Wnoise
		if len(text)%2 != 0 {
			text += "0"
		}
		if len(text) > maxNoiseHeaderHexLength {
			text = text[:maxNoiseHeaderHexLength]
		}
		decoded, err := hex.DecodeString(text)
		if err != nil {
			// Not a generator and not hex either. Nothing sensible to send.
			c.gen = NoiseNone
			return c
		}
		c.header = decoded
	}

	c.countFrom, c.countTo = parseNoiseRange(conf.Wnoisecount, c.countFrom, c.countTo, maxNoiseCount)
	c.delayFrom, c.delayTo = parseNoiseRange(conf.Wnoisedelay, c.delayFrom, c.delayTo, maxNoiseDelay)
	c.payloadFrom, c.payloadTo = parseNoiseRange(conf.Wpayloadsize, c.payloadFrom, c.payloadTo, maxPayloadSize)
	return c
}

// parseNoiseRange reads "N" or "N-M", keeping the fallback when it cannot.
func parseNoiseRange(text string, fallbackFrom, fallbackTo, max int) (int, int) {
	from, to := fallbackFrom, fallbackTo

	switch parts := strings.Split(strings.TrimSpace(text), "-"); len(parts) {
	case 1:
		if v, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 32); err == nil {
			from, to = int(v), int(v)
		}
	case 2:
		v1, err1 := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 32)
		v2, err2 := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 32)
		if err1 == nil && err2 == nil {
			from, to = int(v1), int(v2)
		}
	}

	if from > to {
		from, to = to, from
	}
	if from > max {
		from = max
	}
	if to > max {
		to = max
	}
	return from, to
}

// datagram builds one noise datagram.
//
// A nil return means the entropy pool could not be read, and the caller sends
// nothing rather than something malformed: a primer with the wrong first byte
// does not merely fail to help, it files the flow as QUIC and poisons it.
func (c *noiseConfig) datagram() []byte {
	var head []byte
	switch c.gen {
	case NoiseQUICInit:
		// Complete and self-sized. Appending a payload would destroy the one
		// property it exists for, so the payload is skipped for this generator.
		return quicInitPacket()
	case NoiseQUIC:
		head = quicHeader(quicVersion2)
	case NoiseQUICv1:
		head = quicHeader(quicVersion1)
	case NoiseRandom:
		head = nil
	default:
		head = c.header
	}
	if head == nil && c.gen != NoiseRandom {
		return nil
	}

	size := int(crypto.RandBetween(int64(c.payloadFrom), int64(c.payloadTo)))
	if size <= 0 && len(head) == 0 {
		// "random" with no payload would be an empty datagram, which says
		// nothing and may not even leave the host.
		size = 1
	}
	payload := make([]byte, size)
	if size > 0 {
		if _, err := rand.Read(payload); err != nil {
			return nil
		}
	}

	out := make([]byte, 0, len(head)+size)
	out = append(out, head...)
	out = append(out, payload...)
	return out
}

// quicHeader builds the 18-byte pseudo-QUIC long header.
//
// It is not a valid packet and does not need to be: the length varint claims
// 1232 bytes with nothing like that many following. What it carries is a version
// number in bytes 1..4 and enough of a long header in front of it to get that
// far. On its own this primes a QUIC flow only about one time in four -- see
// quicInitPacket for the shape that works -- but it is what a WireGuard flow
// needs, and is kept so the names mean the same thing in both outbounds.
func quicHeader(version []byte) []byte {
	// The first byte's high nibble names a long-header packet type and its low
	// nibble is header-protected in a real packet. The type is irrelevant to the
	// filters this defeats, so it is drawn from a list rather than fixed, to
	// avoid handing anyone a constant byte to match on.
	clist := []byte{0xDC, 0xDE, 0xD3, 0xD9, 0xD0, 0xEC, 0xEE, 0xE3}

	dcid := make([]byte, 8)
	if _, err := rand.Read(dcid); err != nil {
		return nil
	}
	h := make([]byte, 0, 18)
	h = append(h, clist[crypto.RandBetween(0, int64(len(clist)))])
	h = append(h, version...)
	h = append(h, 0x08)
	h = append(h, dcid...)
	h = append(h, 0x00, 0x00, 0x44, 0xD0)
	return h
}

// quicInitPacket builds a complete, structurally valid QUIC v2 client Initial of
// quicInitSize bytes, with random bytes where the CRYPTO frames would be. It
// decrypts to nothing, which is fine: no peer is meant to answer it.
//
// The first byte must be in 0xc0-0xcf, the long-header Initial encoding. Held
// against a Cloudflare edge with everything else constant, 0xc0/0xc3/0xcf each
// primed the flow 10/10, while 0xd0 and 0xf0 gave 0/10.
func quicInitPacket() []byte {
	pkt := make([]byte, quicInitSize)
	if _, err := rand.Read(pkt); err != nil {
		return nil
	}

	// Byte for byte what the finalmask preset builds, including the length
	// varint, which claims 1024 rather than what actually follows. That was
	// measured as making no difference, and matching it keeps this copy and the
	// tested original from drifting into two slightly different packets.
	pkt[0] = 0xC0 | (pkt[0] & 0x0F) // long header, Initial; low nibble is free
	copy(pkt[1:5], quicVersion2)
	pkt[5] = 8     // DCID length, bytes 6..13 stay random
	pkt[14] = 8    // SCID length, bytes 15..22 stay random
	pkt[23] = 0x00 // token length
	pkt[24], pkt[25] = 0x44, 0x00
	return pkt
}

// sendNoise puts the configured datagrams on the wire, before anything else
// does. Failures are logged and ignored: noise that did not go out is a missed
// chance to prime the path, not a reason to refuse the tunnel.
func (h *Handler) sendNoise(ctx context.Context, conn net.PacketConn, remote net.Addr) {
	noise := parseNoise(h.conf)
	if !noise.enabled() {
		return
	}

	count := int(crypto.RandBetween(int64(noise.countFrom), int64(noise.countTo)))
	sent := 0
	for i := 0; i < count; i++ {
		packet := noise.datagram()
		if packet == nil {
			continue
		}
		if _, err := conn.WriteTo(packet, remote); err != nil {
			errors.LogDebug(ctx, "masque: noise datagram ", i, " did not go out: ", err)
			continue
		}
		sent++
		if noise.delayTo > 0 {
			time.Sleep(time.Duration(crypto.RandBetween(int64(noise.delayFrom), int64(noise.delayTo))) * time.Millisecond)
		}
	}
	errors.LogDebug(ctx, "masque: sent ", sent, " noise datagrams as \"", noise.gen, "\" before the handshake")
}
