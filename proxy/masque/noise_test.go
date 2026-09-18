package masque

import (
	"bytes"
	"context"
	stdnet "net"
	"sync"
	"testing"
	"time"

	"github.com/GFW-knocker/Xray-core/common/net"
)

// recordingPacketConn keeps every datagram written to it, so a test can look at
// what actually went on the wire rather than at what was configured.
type recordingPacketConn struct {
	net.PacketConn
	mu      sync.Mutex
	written [][]byte
}

func (c *recordingPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.written = append(c.written, append([]byte(nil), p...))
	return len(p), nil
}

func (c *recordingPacketConn) packets() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.written
}

func (c *recordingPacketConn) Close() error                     { return nil }
func (c *recordingPacketConn) LocalAddr() net.Addr              { return &stdnet.UDPAddr{} }
func (c *recordingPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *recordingPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordingPacketConn) SetWriteDeadline(time.Time) error { return nil }
func (c *recordingPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, stdnet.ErrClosed
}

func noiseHandler(conf *Config) *Handler {
	return &Handler{conf: conf}
}

// What goes on the wire has to match what was asked for, because a primer with
// the wrong shape does not merely fail to help: it files the flow as QUIC and
// poisons it.
func TestNoiseSendsTheShapeThatWasAskedFor(t *testing.T) {
	cases := []struct {
		name   string
		conf   *Config
		verify func(t *testing.T, packets [][]byte)
	}{
		{
			name: "quicinit is a conformant 1200 byte v2 Initial",
			conf: &Config{Wnoise: NoiseQUICInit, Wnoisecount: "3", Wnoisedelay: "0"},
			verify: func(t *testing.T, packets [][]byte) {
				if len(packets) != 3 {
					t.Fatalf("sent %d datagrams, want 3", len(packets))
				}
				for i, p := range packets {
					if len(p) != quicInitSize {
						t.Errorf("datagram %d is %d bytes, want %d", i, len(p), quicInitSize)
					}
					if p[0]&0xF0 != 0xC0 {
						t.Errorf("datagram %d starts %#x, want the long-header Initial encoding 0xc0-0xcf", i, p[0])
					}
					if !bytes.Equal(p[1:5], quicVersion2) {
						t.Errorf("datagram %d carries version % x, want v2 % x", i, p[1:5], quicVersion2)
					}
				}
			},
		},
		{
			name: "a hex wnoise is used as the head, with the payload after it",
			conf: &Config{Wnoise: "0d0a0d0a", Wnoisecount: "2", Wnoisedelay: "0", Wpayloadsize: "8"},
			verify: func(t *testing.T, packets [][]byte) {
				if len(packets) != 2 {
					t.Fatalf("sent %d datagrams, want 2", len(packets))
				}
				for i, p := range packets {
					if want := 4 + 8; len(p) != want {
						t.Errorf("datagram %d is %d bytes, want %d", i, len(p), want)
					}
					if !bytes.HasPrefix(p, []byte{0x0d, 0x0a, 0x0d, 0x0a}) {
						t.Errorf("datagram %d starts % x, want the configured literal", i, p[:4])
					}
				}
			},
		},
		{
			name: "quic is the v2 header plus a payload",
			conf: &Config{Wnoise: NoiseQUIC, Wnoisecount: "1", Wnoisedelay: "0", Wpayloadsize: "10"},
			verify: func(t *testing.T, packets [][]byte) {
				if len(packets) != 1 {
					t.Fatalf("sent %d datagrams, want 1", len(packets))
				}
				if want := 18 + 10; len(packets[0]) != want {
					t.Errorf("datagram is %d bytes, want %d", len(packets[0]), want)
				}
				if !bytes.Equal(packets[0][1:5], quicVersion2) {
					t.Errorf("carries version % x, want v2", packets[0][1:5])
				}
			},
		},
		{
			name: "random is payload only",
			conf: &Config{Wnoise: NoiseRandom, Wnoisecount: "4", Wnoisedelay: "0", Wpayloadsize: "40-40"},
			verify: func(t *testing.T, packets [][]byte) {
				if len(packets) != 4 {
					t.Fatalf("sent %d datagrams, want 4", len(packets))
				}
				for i, p := range packets {
					if len(p) != 40 {
						t.Errorf("datagram %d is %d bytes, want 40", i, len(p))
					}
				}
			},
		},
		{
			name:   "unset sends nothing",
			conf:   &Config{},
			verify: func(t *testing.T, packets [][]byte) { expectSilence(t, packets) },
		},
		{
			name:   "none sends nothing",
			conf:   &Config{Wnoise: NoiseNone, Wnoisecount: "5"},
			verify: func(t *testing.T, packets [][]byte) { expectSilence(t, packets) },
		},
		{
			name:   "a wnoise that is neither a generator nor hex sends nothing",
			conf:   &Config{Wnoise: "zzzz", Wnoisecount: "5"},
			verify: func(t *testing.T, packets [][]byte) { expectSilence(t, packets) },
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			conn := &recordingPacketConn{}
			noiseHandler(c.conf).sendNoise(context.Background(), conn, &stdnet.UDPAddr{})
			c.verify(t, conn.packets())
		})
	}
}

func expectSilence(t *testing.T, packets [][]byte) {
	t.Helper()
	if len(packets) != 0 {
		t.Errorf("sent %d datagrams, want none", len(packets))
	}
}

// quicinit is a complete datagram whose size is the whole point, so the payload
// setting has to be ignored for it rather than appended.
func TestNoiseIgnoresThePayloadSizeForQUICInit(t *testing.T) {
	conn := &recordingPacketConn{}
	noiseHandler(&Config{
		Wnoise: NoiseQUICInit, Wnoisecount: "1", Wnoisedelay: "0", Wpayloadsize: "100",
	}).sendNoise(context.Background(), conn, &stdnet.UDPAddr{})

	packets := conn.packets()
	if len(packets) != 1 {
		t.Fatalf("sent %d datagrams, want 1", len(packets))
	}
	if len(packets[0]) != quicInitSize {
		t.Errorf("datagram is %d bytes, want exactly %d with no payload appended", len(packets[0]), quicInitSize)
	}
}

// The ranges are the WireGuard outbound's, down to the defaults and the caps, so
// a profile written for that outbound means the same thing here.
func TestNoiseRangesMatchTheWireGuardOutbound(t *testing.T) {
	cases := []struct {
		name                 string
		conf                 *Config
		count, delay, length [2]int
	}{
		{"unset takes the defaults", &Config{Wnoise: NoiseRandom}, [2]int{1, 2}, [2]int{5, 10}, [2]int{5, 10}},
		{
			"a single number is a range of one",
			&Config{Wnoise: NoiseRandom, Wnoisecount: "7", Wnoisedelay: "3", Wpayloadsize: "9"},
			[2]int{7, 7}, [2]int{3, 3}, [2]int{9, 9},
		},
		{
			"a reversed range is put the right way round",
			&Config{Wnoise: NoiseRandom, Wnoisecount: "9-2"},
			[2]int{2, 9}, [2]int{5, 10}, [2]int{5, 10},
		},
		{
			"out of range values are capped, not rejected",
			&Config{Wnoise: NoiseRandom, Wnoisecount: "999", Wnoisedelay: "999", Wpayloadsize: "999"},
			[2]int{maxNoiseCount, maxNoiseCount}, [2]int{maxNoiseDelay, maxNoiseDelay}, [2]int{maxPayloadSize, maxPayloadSize},
		},
		{
			"nonsense falls back to the defaults rather than failing",
			&Config{Wnoise: NoiseRandom, Wnoisecount: "abc", Wnoisedelay: "x-y", Wpayloadsize: ""},
			[2]int{1, 2}, [2]int{5, 10}, [2]int{5, 10},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := parseNoise(c.conf)
			if [2]int{got.countFrom, got.countTo} != c.count {
				t.Errorf("count = %d-%d, want %d-%d", got.countFrom, got.countTo, c.count[0], c.count[1])
			}
			if [2]int{got.delayFrom, got.delayTo} != c.delay {
				t.Errorf("delay = %d-%d, want %d-%d", got.delayFrom, got.delayTo, c.delay[0], c.delay[1])
			}
			if [2]int{got.payloadFrom, got.payloadTo} != c.length {
				t.Errorf("payload = %d-%d, want %d-%d", got.payloadFrom, got.payloadTo, c.length[0], c.length[1])
			}
		})
	}
}

// The built-in noise and the udpmasks are additive, which is the whole point of
// having both: the noise is written through the masked connection, so a mask
// that transforms real traffic transforms the noise the same way.
func TestNoiseGoesThroughTheUdpMask(t *testing.T) {
	recorder := &recordingPacketConn{}
	masked := &prefixingPacketConn{PacketConn: recorder, prefix: []byte{0xAB, 0xCD}}

	noiseHandler(&Config{
		Wnoise: NoiseRandom, Wnoisecount: "2", Wnoisedelay: "0", Wpayloadsize: "16-16"},
	).sendNoise(context.Background(), masked, &stdnet.UDPAddr{})

	packets := recorder.packets()
	if len(packets) != 2 {
		t.Fatalf("the mask saw %d datagrams, want 2", len(packets))
	}
	for i, p := range packets {
		if !bytes.HasPrefix(p, []byte{0xAB, 0xCD}) {
			t.Errorf("datagram %d reached the wire as % x, want the mask's prefix on it", i, p[:2])
		}
		if want := 2 + 16; len(p) != want {
			t.Errorf("datagram %d is %d bytes, want %d", i, len(p), want)
		}
	}
}

// prefixingPacketConn stands in for a udpmask that rewrites what it is given.
type prefixingPacketConn struct {
	net.PacketConn
	prefix []byte
}

func (c *prefixingPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return c.PacketConn.WriteTo(append(append([]byte(nil), c.prefix...), p...), addr)
}
