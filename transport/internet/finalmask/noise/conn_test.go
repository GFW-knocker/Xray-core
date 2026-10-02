package noise

import (
	"bytes"
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The "exp" tests follow upstream #6862's conn_test.go, adapted to the fork,
// where items are built by Item.datagram (which also handles "gen" and lets
// "rand" follow any head).

type fakePacketConn struct {
	mu      sync.Mutex
	written [][]byte
}

func (c *fakePacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.written = append(c.written, bytes.Clone(p))
	return len(p), nil
}

func (c *fakePacketConn) packets() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.written
}

func (c *fakePacketConn) ReadFrom(_ []byte) (int, net.Addr, error) { return 0, nil, nil }
func (c *fakePacketConn) Close() error                             { return nil }
func (c *fakePacketConn) LocalAddr() net.Addr                      { return &net.UDPAddr{} }
func (c *fakePacketConn) SetDeadline(time.Time) error              { return nil }
func (c *fakePacketConn) SetReadDeadline(time.Time) error          { return nil }
func (c *fakePacketConn) SetWriteDeadline(time.Time) error         { return nil }

func segment(t *testing.T, s *Segment, counter *atomic.Uint32) []byte {
	t.Helper()
	b, ok := buildSegment(s, counter)
	require.True(t, ok)
	return b
}

func TestBuildSegmentBytes(t *testing.T) {
	got := segment(t, &Segment{Kind: Segment_BYTES, Bytes: []byte{0x0d, 0x0a, 0x0d, 0x0a}}, new(atomic.Uint32))
	require.Equal(t, []byte{0x0d, 0x0a, 0x0d, 0x0a}, got)
}

func TestBuildSegmentTimestamp(t *testing.T) {
	before := time.Now().Unix()
	got := segment(t, &Segment{Kind: Segment_TIMESTAMP}, new(atomic.Uint32))
	require.Len(t, got, 4)
	ts := int64(binary.BigEndian.Uint32(got))
	require.GreaterOrEqual(t, ts, before)
	require.LessOrEqual(t, ts, time.Now().Unix())
}

func TestBuildSegmentCounter(t *testing.T) {
	counter := new(atomic.Uint32)
	first := binary.BigEndian.Uint32(segment(t, &Segment{Kind: Segment_COUNTER}, counter))
	second := binary.BigEndian.Uint32(segment(t, &Segment{Kind: Segment_COUNTER}, counter))
	require.Equal(t, uint32(1), first)
	require.Equal(t, uint32(2), second)
}

func TestBuildSegmentNonce(t *testing.T) {
	a := segment(t, &Segment{Kind: Segment_NONCE}, new(atomic.Uint32))
	b := segment(t, &Segment{Kind: Segment_NONCE}, new(atomic.Uint32))
	require.Len(t, a, 8)
	require.Len(t, b, 8)
	require.NotEqual(t, a, b)
}

func TestBuildSegmentRandomSizes(t *testing.T) {
	counter := new(atomic.Uint32)
	for range 200 {
		require.Len(t, segment(t, &Segment{Kind: Segment_RANDOM, MinSize: 24, MaxSize: 24}, counter), 24)

		n := len(segment(t, &Segment{Kind: Segment_RANDOM, MinSize: 20, MaxSize: 32}, counter))
		require.GreaterOrEqual(t, n, 20)
		require.LessOrEqual(t, n, 32)

		for _, b := range segment(t, &Segment{Kind: Segment_RANDOM_ASCII, MinSize: 40, MaxSize: 40}, counter) {
			require.True(t, (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z'), "not a letter: %q", b)
		}
		for _, b := range segment(t, &Segment{Kind: Segment_RANDOM_DIGIT, MinSize: 40, MaxSize: 40}, counter) {
			require.True(t, b >= '0' && b <= '9', "not a digit: %q", b)
		}
	}
	// a zero size gives an empty segment, not a failure
	require.Empty(t, segment(t, &Segment{Kind: Segment_RANDOM, MinSize: 0, MaxSize: 0}, counter))
}

func TestDatagramExpComposite(t *testing.T) {
	item := &Item{Segments: []*Segment{
		{Kind: Segment_BYTES, Bytes: []byte{0x0d, 0x0a, 0x0d, 0x0a}},
		{Kind: Segment_TIMESTAMP},
		{Kind: Segment_RANDOM, MinSize: 24, MaxSize: 24},
	}}
	got, ok := item.datagram(new(atomic.Uint32))
	require.True(t, ok)
	require.Len(t, got, 4+4+24)
	require.Equal(t, []byte{0x0d, 0x0a, 0x0d, 0x0a}, got[:4])
}

// GFW-knocker: "rand" follows an exp pattern like it follows "packet" or "gen"
func TestDatagramExpThenRand(t *testing.T) {
	item := &Item{
		Segments:     []*Segment{{Kind: Segment_BYTES, Bytes: []byte{0xaa, 0xbb}}},
		RandMin:      10,
		RandMax:      10,
		RandRangeMin: 0x41,
		RandRangeMax: 0x41,
	}
	got, ok := item.datagram(new(atomic.Uint32))
	require.True(t, ok)
	require.Len(t, got, 2+10)
	require.Equal(t, []byte{0xaa, 0xbb}, got[:2])
	require.Equal(t, bytes.Repeat([]byte{0x41}, 10), got[2:])
}

func TestDatagramLegacy(t *testing.T) {
	got, ok := (&Item{Packet: []byte{1, 2, 3}}).datagram(new(atomic.Uint32))
	require.True(t, ok)
	require.Equal(t, []byte{1, 2, 3}, got)
	got, ok = (&Item{RandMin: 16, RandMax: 17}).datagram(new(atomic.Uint32))
	require.True(t, ok)
	require.Len(t, got, 16)
}

func TestWriteToSendsNoiseThenPayload(t *testing.T) {
	raw := &fakePacketConn{}
	c := &noiseConn{
		PacketConn: raw,
		m:          make(map[string]time.Time),
		config: &Config{Items: []*Item{
			{Segments: []*Segment{{Kind: Segment_BYTES, Bytes: []byte{0x0d, 0x0a, 0x0d, 0x0a}}, {Kind: Segment_RANDOM, MinSize: 8, MaxSize: 8}}},
			{RandMin: 40, RandMax: 41},
			{Segments: []*Segment{{Kind: Segment_COUNTER}}},
		}},
	}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 51820}
	payload := []byte("real-handshake")
	_, err := c.WriteTo(payload, addr)
	require.NoError(t, err)

	sent := raw.packets()
	require.Len(t, sent, 4)
	require.Len(t, sent[0], 12)
	require.Equal(t, []byte{0x0d, 0x0a, 0x0d, 0x0a}, sent[0][:4])
	require.Len(t, sent[1], 40)
	require.Equal(t, uint32(1), binary.BigEndian.Uint32(sent[2]))
	require.Equal(t, payload, sent[3])

	// the noise went out once for this address; the next write is just payload
	_, err = c.WriteTo(payload, addr)
	require.NoError(t, err)
	require.Len(t, raw.packets(), 5)
}
