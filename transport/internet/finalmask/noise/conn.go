package noise

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/GFW-knocker/Xray-core/common/crypto"
)

const asciiLetters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

type noiseConn struct {
	net.PacketConn
	config *Config
	m      map[string]time.Time
	mu     sync.Mutex
	// counter feeds the <c> segment of "exp" items
	counter atomic.Uint32
}

func NewConnClient(c *Config, raw net.PacketConn) (net.PacketConn, error) {
	return &noiseConn{
		PacketConn: raw,
		config:     c,
		m:          make(map[string]time.Time),
	}, nil
}

func NewConnServer(c *Config, raw net.PacketConn) (net.PacketConn, error) {
	return NewConnClient(c, raw)
}

func (c *noiseConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	t := c.m[addr.String()]

	if t.IsZero() || (c.config.ResetMax > 0 && time.Now().After(t)) {
		for _, item := range c.config.Items {
			if buf, ok := item.datagram(&c.counter); ok {
				c.PacketConn.WriteTo(buf, addr)
			}
			time.Sleep(time.Duration(crypto.RandBetween(item.DelayMin, item.DelayMax)) * time.Millisecond)
		}
	}

	c.m[addr.String()] = time.Now().Add(time.Duration(crypto.RandBetween(c.config.ResetMin, c.config.ResetMax)) * time.Second)

	return c.PacketConn.WriteTo(p, addr)
}

// datagram builds the bytes for one noise item.
//
// The head of the datagram is a literal "packet", the output of a named
// generator, or an "exp" pattern of segments, and "rand" appends that many
// random bytes after it. The config builder has already rejected the
// combinations that make no sense, so the only failure left here is a
// generator or segment that could not read entropy, which reports false and is
// skipped rather than sent malformed.
func (i *Item) datagram(counter *atomic.Uint32) ([]byte, bool) {
	head := i.Packet
	if len(i.Segments) > 0 {
		var ok bool
		if head, ok = buildSegments(i.Segments, counter); !ok {
			return nil, false
		}
	} else if i.Gen != "" {
		if head = generate(i.Gen); head == nil {
			return nil, false
		}
	}

	if i.RandMax <= 0 {
		return head, true
	}

	payload := make([]byte, crypto.RandBetween(i.RandMin, i.RandMax))
	crypto.RandBytesBetween(payload, byte(i.RandRangeMin), byte(i.RandRangeMax))
	if len(head) == 0 {
		return payload, true
	}

	buf := make([]byte, 0, len(head)+len(payload))
	buf = append(buf, head...)
	buf = append(buf, payload...)
	return buf, true
}

// buildSegments assembles an "exp" pattern (upstream #6862).
func buildSegments(segments []*Segment, counter *atomic.Uint32) ([]byte, bool) {
	var out []byte
	for _, seg := range segments {
		b, ok := buildSegment(seg, counter)
		if !ok {
			return nil, false
		}
		out = append(out, b...)
	}
	return out, true
}

func buildSegment(seg *Segment, counter *atomic.Uint32) ([]byte, bool) {
	switch seg.Kind {
	case Segment_BYTES:
		return seg.Bytes, true
	case Segment_TIMESTAMP:
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, uint32(time.Now().Unix()))
		return b, true
	case Segment_COUNTER:
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, counter.Add(1))
		return b, true
	case Segment_NONCE:
		b := make([]byte, 8)
		if _, err := rand.Read(b); err != nil {
			return nil, false
		}
		return b, true
	default:
		// sizes are inclusive: RandBetween's upper bound is not
		size := crypto.RandBetween(seg.MinSize, seg.MaxSize+1)
		if size <= 0 {
			return nil, true
		}
		buf := make([]byte, size)
		if _, err := rand.Read(buf); err != nil {
			return nil, false
		}
		switch seg.Kind {
		case Segment_RANDOM_ASCII:
			for i := range buf {
				buf[i] = asciiLetters[int(buf[i])%len(asciiLetters)]
			}
		case Segment_RANDOM_DIGIT:
			for i := range buf {
				buf[i] = '0' + buf[i]%10
			}
		}
		return buf, true
	}
}
