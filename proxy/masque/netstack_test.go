package masque

import (
	"context"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

const testMTU = 1280

func newTestDevice(t *testing.T) *netTun {
	t.Helper()
	dev, _, _, err := CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.0.0.2")}, nil, testMTU, true)
	if err != nil {
		t.Fatalf("CreateNetTUN: %v", err)
	}
	t.Cleanup(func() { dev.Close() })
	return dev
}

// A connection opened on the stack has to leave as an IP packet on ReadPacket,
// because that is the only way the MASQUE side ever sees traffic.
func TestReadPacketCarriesTheStacksOutboundTraffic(t *testing.T) {
	dev := newTestDevice(t)

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		// Nothing answers, so this never connects; it only has to emit a SYN.
		conn, err := dev.DialContextTCPAddrPort(ctx, netip.MustParseAddrPort("1.2.3.4:80"))
		if err == nil {
			conn.Close()
		}
	}()

	type read struct {
		n   int
		err error
	}
	buf := make([]byte, testMTU)
	got := make(chan read, 1)
	go func() {
		n, err := dev.ReadPacket(buf)
		got <- read{n, err}
	}()

	select {
	case r := <-got:
		if r.err != nil {
			t.Fatalf("ReadPacket: %v", r.err)
		}
		if r.n < header.IPv4MinimumSize {
			t.Fatalf("packet is %d bytes, shorter than an IPv4 header", r.n)
		}
		ip := header.IPv4(buf[:r.n])
		if got, want := ip.SourceAddress().String(), "10.0.0.2"; got != want {
			t.Errorf("source address = %s, want %s", got, want)
		}
		if got, want := ip.DestinationAddress().String(), "1.2.3.4"; got != want {
			t.Errorf("destination address = %s, want %s", got, want)
		}
		if ip.Protocol() != uint8(header.TCPProtocolNumber) {
			t.Fatalf("protocol = %d, want TCP", ip.Protocol())
		}
		tcp := header.TCP(ip.Payload())
		if got, want := tcp.DestinationPort(), uint16(80); got != want {
			t.Errorf("destination port = %d, want %d", got, want)
		}
		if tcp.Flags()&header.TCPFlagSyn == 0 {
			t.Errorf("flags = %v, want SYN set", tcp.Flags())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no packet came out of the stack within 5s")
	}
}

// WritePacket has to sort packets by IP version and refuse anything else,
// because the far end can send whatever it likes.
func TestWritePacketChecksTheIPVersion(t *testing.T) {
	dev := newTestDevice(t)

	if err := dev.WritePacket(nil); err != nil {
		t.Errorf("WritePacket(nil) = %v, want nil", err)
	}

	// Version 7 is neither IPv4 nor IPv6.
	if err := dev.WritePacket([]byte{0x70, 0x00, 0x00, 0x00}); err != syscall.EAFNOSUPPORT {
		t.Errorf("WritePacket(version 7) = %v, want EAFNOSUPPORT", err)
	}

	// A well-formed but unroutable IPv4 packet is handed to the stack, which
	// drops it. Accepting it without an error is the contract.
	ip := make([]byte, header.IPv4MinimumSize)
	header.IPv4(ip).Encode(&header.IPv4Fields{
		TotalLength: header.IPv4MinimumSize,
		TTL:         64,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     tcpip.AddrFrom4([4]byte{10, 0, 0, 3}),
		DstAddr:     tcpip.AddrFrom4([4]byte{10, 0, 0, 2}),
	})
	if err := dev.WritePacket(ip); err != nil {
		t.Errorf("WritePacket(IPv4) = %v, want nil", err)
	}
}

// The (Knocker) shutdown handling has to survive the copy: Close is called from
// the packet pump and from the handler, so a second call must not panic on an
// already-closed channel.
func TestCloseIsIdempotentAndUnblocksReadPacket(t *testing.T) {
	dev, _, _, err := CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.0.0.2")}, nil, testMTU, true)
	if err != nil {
		t.Fatalf("CreateNetTUN: %v", err)
	}

	blocked := make(chan error, 1)
	go func() {
		_, err := dev.ReadPacket(make([]byte, testMTU))
		blocked <- err
	}()
	// Give the reader a moment to park on the channel.
	time.Sleep(50 * time.Millisecond)

	if err := dev.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := dev.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	select {
	case err := <-blocked:
		if err != os.ErrClosed {
			t.Errorf("ReadPacket after Close = %v, want os.ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not unblock ReadPacket")
	}
}

// Closing while the stack still has packets to hand over is the race the
// (Knocker) fix addresses: WriteNotify parks on the unbuffered channel because
// nothing is reading, and Close then closes that channel underneath it. Without
// the fix this panics with "send on closed channel". The race detector cannot
// run in this checkout (cgo is broken for -race), so this leans on repetition.
func TestCloseWhileTheStackIsProducingPackets(t *testing.T) {
	for i := 0; i < 50; i++ {
		dev, _, _, err := CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.0.0.2")}, nil, testMTU, true)
		if err != nil {
			t.Fatalf("iteration %d, CreateNetTUN: %v", i, err)
		}

		// Deliberately nobody calls ReadPacket.
		var wg sync.WaitGroup
		for j := 0; j < 3; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
				defer cancel()
				if conn, err := dev.DialContextTCPAddrPort(ctx, netip.MustParseAddrPort("1.2.3.4:80")); err == nil {
					conn.Close()
				}
			}()
		}

		// Let a SYN reach WriteNotify and park there before pulling the rug.
		time.Sleep(time.Millisecond)
		if err := dev.Close(); err != nil {
			t.Fatalf("iteration %d, Close: %v", i, err)
		}
		wg.Wait()
	}
}

func TestMTUIsReported(t *testing.T) {
	if got := newTestDevice(t).MTU(); got != testMTU {
		t.Errorf("MTU = %d, want %d", got, testMTU)
	}
}
