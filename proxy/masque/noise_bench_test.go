package masque

import (
	"context"
	stdnet "net"
	"testing"
	"time"

	"github.com/GFW-knocker/Xray-core/common/net"
)

// discardPacketConn is the cheapest possible floor: it does nothing at all, so
// the benchmark measures the wrapper and not the kernel.
type discardPacketConn struct{ net.PacketConn }

func (discardPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }

// What a datagram costs on a busy tunnel, where the idle check never fires.
func BenchmarkWriteThroughNoiseConn(b *testing.B) {
	conn := &noisePacketConn{
		PacketConn: discardPacketConn{},
		ctx:        context.Background(),
		noise:      parseNoise(&Config{Wnoise: NoiseRandom}),
		gap:        7500 * time.Millisecond,
	}
	addr := &stdnet.UDPAddr{}
	payload := make([]byte, 1200)

	// The first write is the handshake burst; take it before timing.
	conn.WriteTo(payload, addr)

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn.WriteTo(payload, addr)
	}
}

// The same traffic with noise switched off, which is what the wrapper costs
// against: wrapNoise returns the connection untouched, so this is the floor.
func BenchmarkWriteWithoutNoiseConn(b *testing.B) {
	conn := net.PacketConn(discardPacketConn{})
	addr := &stdnet.UDPAddr{}
	payload := make([]byte, 1200)

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn.WriteTo(payload, addr)
	}
}

// Concurrent writers, since quic-go can send from more than one goroutine and
// the wrapper serialises them on a mutex.
func BenchmarkWriteThroughNoiseConnParallel(b *testing.B) {
	conn := &noisePacketConn{
		PacketConn: discardPacketConn{},
		ctx:        context.Background(),
		noise:      parseNoise(&Config{Wnoise: NoiseRandom}),
		gap:        7500 * time.Millisecond,
	}
	addr := &stdnet.UDPAddr{}
	payload := make([]byte, 1200)
	conn.WriteTo(payload, addr)

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			conn.WriteTo(payload, addr)
		}
	})
}
