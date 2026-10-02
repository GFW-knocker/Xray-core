package quic

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	gonet "net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/GFW-knocker/Xray-core/common/net"
	"github.com/GFW-knocker/Xray-core/common/protocol"
	"github.com/GFW-knocker/Xray-core/common/protocol/tls/cert"
	"github.com/GFW-knocker/Xray-core/testing/servers/udp"
	"github.com/GFW-knocker/Xray-core/transport/internet"
	"github.com/GFW-knocker/Xray-core/transport/internet/stat"
	"github.com/GFW-knocker/Xray-core/transport/internet/tls"
)

func serverSettings() *internet.MemoryStreamConfig {
	ct, _ := cert.MustGenerate(nil, cert.DNSNames("www.example.com"), cert.CommonName("www.example.com"))
	c := tls.ParseCertificate(ct)
	// no hot-reload goroutine: it races the first handshakes in package tls
	// (shared by every TLS server, not this transport), which -race would
	// report here instead of anything in this package
	c.OneTimeLoading = true
	return &internet.MemoryStreamConfig{
		ProtocolName:     "quic",
		ProtocolSettings: &Config{},
		SecurityType:     "tls",
		SecuritySettings: &tls.Config{
			Certificate: []*tls.Certificate{c},
		},
	}
}

func clientSettings() *internet.MemoryStreamConfig {
	return &internet.MemoryStreamConfig{
		ProtocolName:     "quic",
		ProtocolSettings: &Config{},
		SecurityType:     "tls",
		SecuritySettings: &tls.Config{
			ServerName:    "www.example.com",
			AllowInsecure: true,
		},
	}
}

// startServer runs a quic listener that hands each stream to handle.
func startServer(t *testing.T, handle func(stat.Connection)) net.Port {
	t.Helper()
	port := udp.PickPort()
	l, err := Listen(context.Background(), net.LocalHostIP, port, serverSettings(), func(conn stat.Connection) {
		go handle(conn)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return port
}

func echo(conn stat.Connection) {
	defer conn.Close()
	io.Copy(conn, conn)
}

// startBlackhole binds a UDP port that never answers, like a dead server.
func startBlackhole(t *testing.T) net.Port {
	t.Helper()
	pc, err := gonet.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		b := make([]byte, 2048)
		for {
			if _, _, err := pc.ReadFrom(b); err != nil {
				return
			}
		}
	}()
	return net.Port(pc.LocalAddr().(*gonet.UDPAddr).Port)
}

func dial(ctx context.Context, port net.Port) (stat.Connection, error) {
	return Dial(ctx, net.UDPDestination(net.LocalHostIP, port), clientSettings())
}

func roundTrip(conn stat.Connection) error {
	msg := make([]byte, 1024)
	rand.Read(msg)
	if _, err := conn.Write(msg); err != nil {
		return err
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		return err
	}
	if !bytes.Equal(got, msg) {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func destState(port net.Port) *destConnections {
	client.access.Lock()
	defer client.access.Unlock()
	return client.dests[net.UDPDestination(net.LocalHostIP, port)]
}

func connCount(port net.Port) int {
	client.access.Lock()
	defer client.access.Unlock()
	if d := client.dests[net.UDPDestination(net.LocalHostIP, port)]; d != nil {
		return len(d.conns)
	}
	return 0
}

// The bug this package had: one lock for every destination, held across the
// handshake, so a dead server stalled dials to every other server for up to
// 16 s (8 s handshake timeout x 2 versions).
func TestDeadServerDoesNotBlockOtherServers(t *testing.T) {
	live := startServer(t, echo)
	dead := startBlackhole(t)

	deadCtx, cancelDead := context.WithCancel(context.Background())
	defer cancelDead()
	deadDone := make(chan struct{})
	go func() {
		defer close(deadDone)
		if conn, err := dial(deadCtx, dead); err == nil {
			conn.Close()
			t.Error("dial to a blackhole succeeded")
		}
	}()
	time.Sleep(300 * time.Millisecond) // the dead dial is mid-handshake now

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dial(ctx, live)
	if err != nil {
		t.Fatal("live server dial failed while a dead one was dialing: ", err)
	}
	defer conn.Close()
	if err := roundTrip(conn); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatal("live server dial took ", d, ", it waited for the dead one")
	}

	cancelDead()
	select {
	case <-deadDone:
	case <-time.After(3 * time.Second):
		t.Fatal("cancelling the context did not stop the dead dial")
	}
}

// A request that gives up must stop its handshake, not run on for 16 s.
func TestDialStopsWithContext(t *testing.T) {
	dead := startBlackhole(t)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	start := time.Now()
	if conn, err := dial(ctx, dead); err == nil {
		conn.Close()
		t.Fatal("dial to a blackhole succeeded")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatal("dial returned after ", d, ", it ignored the context")
	}
}

// A second request to a destination that is mid-handshake waits for that
// handshake, but can still give up on its own context.
func TestWaiterGivesUpOnContext(t *testing.T) {
	dead := startBlackhole(t)

	firstCtx, cancelFirst := context.WithCancel(context.Background())
	defer cancelFirst()
	go dial(firstCtx, dead)
	time.Sleep(200 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := dial(ctx, dead); err == nil {
		t.Fatal("waiting dial succeeded")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatal("waiter returned after ", d)
	}
}

// Many requests at once to one server, racing the periodic cleanup: no data
// race, no lost connection, and they share connections instead of each
// dialing one.
func TestConcurrentDialsShareConnectionsWithCleanup(t *testing.T) {
	live := startServer(t, echo)

	stop := make(chan struct{})
	cleanerDone := make(chan struct{})
	go func() {
		defer close(cleanerDone)
		for {
			select {
			case <-stop:
				return
			default:
				client.cleanConnections()
				time.Sleep(time.Millisecond)
			}
		}
	}()

	const workers = 64
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			conn, err := dial(ctx, live)
			if err != nil {
				errs <- err
				return
			}
			defer conn.Close()
			if err := roundTrip(conn); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(stop)
	<-cleanerDone
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	// the server allows 32 streams per connection, so 64 at once need at
	// least 2; far more would mean requests were not sharing
	if n := connCount(live); n < 1 || n > 4 {
		t.Fatal("expected 1-4 shared connections, got ", n)
	}
}

// Close must release the stream's read side: a Read blocked in another
// goroutine returns, instead of hanging until the peer sends FIN.
func TestCloseUnblocksRead(t *testing.T) {
	hold := make(chan struct{})
	defer close(hold)
	live := startServer(t, func(conn stat.Connection) {
		defer conn.Close()
		<-hold // reads nothing, writes nothing
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dial(ctx, live)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}

	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		conn.Read(make([]byte, 16))
	}()
	time.Sleep(200 * time.Millisecond)
	conn.Close()

	select {
	case <-readDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Read still blocked after Close")
	}
}

// Failed dials and closed connections must not leave goroutines behind.
func TestNoGoroutineLeak(t *testing.T) {
	live := startServer(t, echo)
	dead := startBlackhole(t)

	// warm up anything lazily started (cleanup task, pools, the listener)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	conn, err := dial(ctx, live)
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	closeAll(live)
	time.Sleep(500 * time.Millisecond)
	before := runtime.NumGoroutine()

	for i := 0; i < 20; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		dial(ctx, dead)
		cancel()
	}
	for i := 0; i < 20; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		conn, err := dial(ctx, live)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		if err := roundTrip(conn); err != nil {
			t.Fatal(err)
		}
		conn.Close()
		closeAll(live) // force a fresh connection next time
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		after := runtime.NumGoroutine()
		if after <= before+2 {
			return
		}
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<20)
			n := runtime.Stack(buf, true)
			t.Fatalf("goroutines grew from %d to %d\n%s", before, after, buf[:n])
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// closeAll closes every client connection to port, the way cleanup closes an
// inactive one.
func closeAll(port net.Port) {
	d := destState(port)
	if d == nil {
		return
	}
	client.access.Lock()
	conns := d.conns
	d.conns = nil
	client.access.Unlock()
	for _, c := range conns {
		c.close()
	}
}

// A sealed packet whose plaintext is bigger than quic-go's read buffer used to
// make Open return a fresh slice, and quic-go then panicked slicing its own
// buffer to that length. It must be dropped and the next packet delivered.
func TestOversizedSealedPacketIsDropped(t *testing.T) {
	config := &Config{Key: "k", Security: &protocol.SecurityConfig{Type: protocol.SecurityType_AES128_GCM}}

	rc, err := gonet.ListenUDP("udp", &gonet.UDPAddr{IP: gonet.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := wrapSysConn(rc, config)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()

	wc, err := gonet.ListenUDP("udp", &gonet.UDPAddr{IP: gonet.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	writer, err := wrapSysConn(wc, config)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()

	if _, err := writer.WriteTo(make([]byte, 1600), rc.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	small := []byte("small packet")
	if _, err := writer.WriteTo(small, rc.LocalAddr()); err != nil {
		t.Fatal(err)
	}

	// quic-go reads into a 1452-byte buffer
	p := make([]byte, 1452)
	reader.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := reader.ReadFrom(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p[:n], small) {
		t.Fatalf("got %d bytes, want the small packet", n)
	}

	// and a write that cannot fit the pooled buffer fails instead of panicking
	if _, err := writer.WriteTo(make([]byte, 4096), rc.LocalAddr()); err == nil {
		t.Fatal("oversized write did not fail")
	}
}

func heapInUse() uint64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapInuse
}

// Streams closed while the peer is still sending -- an app aborting a
// download -- must be released on both ends. With a send-only Close each one
// stayed in its connection, holding the data that arrived after it.
func TestAbortedStreamsDoNotLeak(t *testing.T) {
	live := startServer(t, echo)
	payload := make([]byte, 32*1024)
	rand.Read(payload)

	abort := func(n int) {
		for i := 0; i < n; i++ {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			conn, err := dial(ctx, live)
			cancel()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := conn.Write(payload); err != nil {
				t.Fatal(err)
			}
			// the echo has started coming back; walk away from the rest
			if _, err := io.ReadFull(conn, make([]byte, 1)); err != nil {
				t.Fatal(err)
			}
			conn.Close()
		}
	}

	abort(50) // warm up pools
	closeAll(live)
	time.Sleep(500 * time.Millisecond)
	goBefore := runtime.NumGoroutine()
	before := heapInUse()

	const n = 1500
	abort(n)
	time.Sleep(time.Second) // let STOP_SENDING / RESET_STREAM settle

	after := heapInUse()
	grown := int64(after) - int64(before)
	t.Logf("heap in use %d -> %d (%+d bytes after %d aborted streams)", before, after, grown, n)
	// a leak keeps up to 32 KiB of echoed data per stream: ~47 MiB here
	if grown > 8<<20 {
		t.Fatalf("heap grew by %d bytes after %d aborted streams", grown, n)
	}
	// Up to quic-go v0.61 (and upstream master as of 2026-10), a Write woken by
	// the peer's STOP_SENDING re-buffers its tail after the reset; that frame is
	// never sent, so the stream never completes and keeps one of the server's
	// 32 stream slots until the connection closes. About 1 in 10 aborted streams
	// hits it here, so the client spreads over a few connections (1-2 with the
	// quic-go fix). One leaked slot per abort would mean ~47 connections.
	c := connCount(live)
	t.Logf("%d aborted streams used %d connection(s)", n, c)
	if c > n/100 {
		t.Fatal("aborted streams piled up into ", c, " connections")
	}

	// each live connection runs its own goroutines; with them closed, nothing
	// from the aborted streams may be left
	closeAll(live)
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > goBefore+2 {
		if time.Now().After(deadline) {
			t.Fatalf("goroutines grew from %d to %d", goBefore, runtime.NumGoroutine())
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// Heavy parallel traffic through one server: every byte arrives intact and
// everything is released afterwards.
func TestHighTrafficIntegrity(t *testing.T) {
	live := startServer(t, echo)
	time.Sleep(200 * time.Millisecond)
	goBefore := runtime.NumGoroutine()

	const workers = 96
	const size = 256 * 1024
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			conn, err := dial(ctx, live)
			if err != nil {
				errs <- err
				return
			}
			defer conn.Close()
			msg := make([]byte, size)
			rand.Read(msg)
			go conn.Write(msg)
			got := make([]byte, size)
			if _, err := io.ReadFull(conn, got); err != nil {
				errs <- err
				return
			}
			if !bytes.Equal(got, msg) {
				errs <- io.ErrUnexpectedEOF
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	closeAll(live)
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > goBefore+4 {
		if time.Now().After(deadline) {
			t.Fatalf("goroutines grew from %d to %d", goBefore, runtime.NumGoroutine())
		}
		time.Sleep(100 * time.Millisecond)
	}
}
