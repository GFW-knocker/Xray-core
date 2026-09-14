package noise

import (
	"net"
	"sync"
	"time"

	"github.com/GFW-knocker/Xray-core/common/crypto"
)

type noiseConn struct {
	net.PacketConn
	config *Config
	m      map[string]time.Time
	mu     sync.Mutex
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
			if buf, ok := item.datagram(); ok {
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
// The head of the datagram is either a literal "packet" or the output of a
// named generator, and "rand" appends that many random bytes after it. The
// config builder has already rejected the combinations that make no sense, so
// the only failure left here is a generator that could not read entropy, which
// reports false and is skipped rather than sent malformed.
func (i *Item) datagram() ([]byte, bool) {
	head := i.Packet
	if i.Gen != "" {
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
