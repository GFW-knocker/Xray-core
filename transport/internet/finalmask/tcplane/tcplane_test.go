package tcplane

import (
	"bytes"
	"fmt"
	gonet "net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GFW-knocker/Xray-core/common/net"
	"github.com/GFW-knocker/Xray-core/transport/internet/finalmask"
)

func testConfig() *Config {
	return &Config{
		PacketsMin: 3, PacketsMax: 3,
		LifeMin: 10000, LifeMax: 10000,
		Lanes: 2, MaxRate: 0,
		Grace: 500, Idle: 20000, MaxLife: 60000,
		DownLife: 5000,
	}
}

// echoServer starts a tcplane server on loopback that echoes every datagram,
// and returns it with its port and the set of client addresses it saw.
func echoServer(t *testing.T, cfg *Config) (*serverConn, int, *sync.Map) {
	t.Helper()
	lc := &finalmask.ListenConfig{
		Listen: func(a net.Addr) (net.Listener, error) { return gonet.Listen("tcp", a.String()) },
	}
	s, err := newServerConn(cfg, &gonet.UDPAddr{IP: gonet.IPv4(127, 0, 0, 1)}, lc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	seen := &sync.Map{}
	go func() {
		b := make([]byte, 65536)
		for {
			n, addr, err := s.ReadFrom(b)
			if err != nil {
				return
			}
			seen.Store(addr.String(), true)
			s.WriteTo(b[:n], addr)
		}
	}()
	return s, s.local.(*gonet.UDPAddr).Port, seen
}

func newClient(t *testing.T, cfg *Config, port int) (*clientConn, *atomic.Int32) {
	t.Helper()
	var dials atomic.Int32
	d := func(dest net.Destination) (net.Conn, error) {
		dials.Add(1)
		return gonet.Dial("tcp", dest.NetAddr())
	}
	dest := net.UDPDestination(net.LocalHostIP, net.Port(port))
	c, err := newClientConn(cfg, &dest, &finalmask.Dialer{DialTCP: d, DialTCPDetached: d})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c, &dials
}

func roundTrip(t *testing.T, c *clientConn, msg []byte) {
	t.Helper()
	if _, err := c.WriteTo(msg, &gonet.UDPAddr{}); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 65536)
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := c.ReadFrom(b)
	if err != nil {
		t.Fatalf("no echo for %q: %v", msg[:min(len(msg), 16)], err)
	}
	if !bytes.Equal(b[:n], msg) {
		t.Fatalf("echo mismatch: got %d bytes, want %d", n, len(msg))
	}
}

func TestEchoRotatesOnPackets(t *testing.T) {
	cfg := testConfig()
	_, port, _ := echoServer(t, cfg)
	c, dials := newClient(t, cfg, port)
	const N = 60
	for i := 0; i < N; i++ {
		roundTrip(t, c, []byte(fmt.Sprintf("datagram %d %s", i, bytes.Repeat([]byte{'x'}, i*20))))
	}
	// 3 frames per lane: at least N/3 lanes were used
	if d := dials.Load(); d < N/3 {
		t.Fatalf("only %d lanes dialed for %d datagrams at 3 per lane", d, N)
	}
}

func TestRotatesOnLifetime(t *testing.T) {
	cfg := testConfig()
	cfg.PacketsMin, cfg.PacketsMax = 1000, 1000
	cfg.LifeMin, cfg.LifeMax = 40, 40
	_, port, _ := echoServer(t, cfg)
	c, dials := newClient(t, cfg, port)
	for i := 0; i < 6; i++ {
		roundTrip(t, c, []byte{byte(i)})
		time.Sleep(60 * time.Millisecond)
	}
	if d := dials.Load(); d < 6 {
		t.Fatalf("%d lanes dialed, want one per 40 ms lifetime (>= 6)", d)
	}
}

func TestRotatesOnReceivedBytes(t *testing.T) {
	cfg := testConfig()
	cfg.PacketsMin, cfg.PacketsMax = 1000, 1000
	cfg.BytesMin, cfg.BytesMax = 3000, 3000
	_, port, _ := echoServer(t, cfg)
	c, dials := newClient(t, cfg, port)
	msg := bytes.Repeat([]byte{'y'}, 1000)
	for i := 0; i < 12; i++ {
		roundTrip(t, c, msg)
	}
	// ~3 echoes per lane
	if d := dials.Load(); d < 4 {
		t.Fatalf("%d lanes dialed, want a new one every ~3 KB received", d)
	}
}

func TestClientsAreSeparate(t *testing.T) {
	cfg := testConfig()
	_, port, seen := echoServer(t, cfg)
	var wg sync.WaitGroup
	for k := 0; k < 4; k++ {
		c, _ := newClient(t, cfg, port)
		wg.Add(1)
		go func(k int) {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				msg := []byte(fmt.Sprintf("client %d datagram %d", k, i))
				if _, err := c.WriteTo(msg, nil); err != nil {
					t.Error(err)
					return
				}
				b := make([]byte, 256)
				c.SetReadDeadline(time.Now().Add(3 * time.Second))
				n, _, err := c.ReadFrom(b)
				if err != nil || !bytes.Equal(b[:n], msg) {
					t.Errorf("client %d got %q, %v; want %q", k, b[:n], err, msg)
					return
				}
			}
		}(k)
	}
	wg.Wait()
	addrs := 0
	seen.Range(func(k, _ any) bool {
		addrs++
		if ip := gonet.ParseIP(must(gonet.SplitHostPort(k.(string)))); !ip.Equal(gonet.IPv4(127, 0, 0, 1)) {
			t.Errorf("session address %s is not the client's real IP", k)
		}
		return true
	})
	if addrs != 4 {
		t.Fatalf("server saw %d client addresses, want 4", addrs)
	}
}

func must(host, _ string, err error) string {
	if err != nil {
		panic(err)
	}
	return host
}

func TestWrongPasswordIsDropped(t *testing.T) {
	scfg := testConfig()
	scfg.Password = "right"
	_, port, seen := echoServer(t, scfg)
	ccfg := testConfig()
	ccfg.Password = "wrong"
	c, _ := newClient(t, ccfg, port)
	c.WriteTo([]byte("hello"), nil)
	c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if _, _, err := c.ReadFrom(make([]byte, 64)); err == nil {
		t.Fatal("a lane with the wrong password got an answer")
	}
	seen.Range(func(k, _ any) bool {
		t.Fatalf("server delivered a datagram from %s", k)
		return false
	})

	ccfg.Password = "right"
	ok, _ := newClient(t, ccfg, port)
	roundTrip(t, ok, []byte("hello"))
}

func TestReplayedLaneIsDropped(t *testing.T) {
	cfg := testConfig()
	_, port, _ := echoServer(t, cfg)
	k := newKeys("")
	var hdr [headerLen]byte
	k.seal(hdr[:], laneHeader{session: sessionID{1, 2, 3}, nonce: [8]byte{9, 9, 9}, role: roleUp})
	send := func() bool {
		c, err := gonet.Dial("tcp", fmt.Sprint("127.0.0.1:", port))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.Write(appendFrame(hdr[:], []byte("ping")))
		c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		var lb [2]byte
		_, err = readFrame(c, lb[:])
		return err == nil
	}
	if !send() {
		t.Fatal("first lane got no echo")
	}
	if send() {
		t.Fatal("a replayed lane header was accepted")
	}
}

func TestPortRange(t *testing.T) {
	// pick two free ports
	var ports []uint32
	for i := 0; i < 2; i++ {
		l, err := gonet.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ports = append(ports, uint32(l.Addr().(*gonet.TCPAddr).Port))
		l.Close()
	}
	cfg := testConfig()
	cfg.Ports = ports
	_, _, _ = echoServer(t, cfg)
	var used sync.Map
	var dials atomic.Int32
	d := func(dest net.Destination) (net.Conn, error) {
		dials.Add(1)
		used.Store(dest.Port, true)
		return gonet.Dial("tcp", dest.NetAddr())
	}
	dest := net.UDPDestination(net.LocalHostIP, 1) // port comes from cfg.Ports
	c, err := newClientConn(cfg, &dest, &finalmask.Dialer{DialTCPDetached: d})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for i := 0; i < 60; i++ {
		roundTrip(t, c, []byte{byte(i)})
	}
	n := 0
	used.Range(func(any, any) bool { n++; return true })
	if n != 2 {
		t.Fatalf("lanes used %d of the 2 ports", n)
	}
}

func TestCloseUnblocksRead(t *testing.T) {
	cfg := testConfig()
	_, port, _ := echoServer(t, cfg)
	c, _ := newClient(t, cfg, port)
	done := make(chan error, 1)
	go func() {
		_, _, err := c.ReadFrom(make([]byte, 64))
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	c.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("read returned no error after close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("close did not unblock ReadFrom")
	}
}

func TestReadDeadline(t *testing.T) {
	cfg := testConfig()
	_, port, _ := echoServer(t, cfg)
	c, _ := newClient(t, cfg, port)
	c.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	start := time.Now()
	if _, _, err := c.ReadFrom(make([]byte, 64)); err == nil {
		t.Fatal("no timeout")
	}
	if el := time.Since(start); el > time.Second {
		t.Fatalf("deadline took %s", el)
	}
	// cleared deadline: a later datagram is read normally
	c.SetReadDeadline(time.Time{})
	roundTrip(t, c, []byte("after"))
}

func TestMaxRateLimitsDials(t *testing.T) {
	cfg := testConfig()
	cfg.PacketsMin, cfg.PacketsMax = 1, 1
	cfg.MaxRate = 20
	_, port, _ := echoServer(t, cfg)
	c, dials := newClient(t, cfg, port)
	start := time.Now()
	for i := 0; i < 30; i++ {
		roundTrip(t, c, []byte{byte(i)})
	}
	el := time.Since(start).Seconds()
	// burst (lanes+1) plus 20/s
	if limit := float64(burst(cfg)) + 20*el + 2; float64(dials.Load()) > limit {
		t.Fatalf("%d dials in %.2fs exceeds maxRate 20/s", dials.Load(), el)
	}
	if el < 1 {
		t.Fatalf("30 one-packet lanes at 20/s took only %.2fs", el)
	}
}

// With the server gone, failed dials back off instead of spinning.
func TestDialFailuresBackOff(t *testing.T) {
	l, err := gonet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*gonet.TCPAddr).Port
	l.Close()
	cfg := testConfig()
	cfg.Lanes = 4
	c, dials := newClient(t, cfg, port)
	c.WriteTo([]byte("x"), nil) // waits writeWait for a lane, then drops
	time.Sleep(writeWait)
	if d := dials.Load(); d > 20 {
		t.Fatalf("%d dials in %s to a closed port, want backoff", d, writeWait)
	}
}

// The server pushes datagrams the client never asked for, more than one down
// lane may carry: they must arrive over fresh down lanes with no client
// writes in between. (The first design answered only on the lane the client
// last wrote on, and deadlocked when that lane was cut.)
func TestServerPushRotatesDownLanes(t *testing.T) {
	cfg := testConfig()
	cfg.BytesMin, cfg.BytesMax = 4000, 4000
	lc := &finalmask.ListenConfig{
		Listen: func(a net.Addr) (net.Listener, error) { return gonet.Listen("tcp", a.String()) },
	}
	s, err := newServerConn(cfg, &gonet.UDPAddr{IP: gonet.IPv4(127, 0, 0, 1)}, lc)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	const N = 40
	go func() {
		b := make([]byte, 64)
		_, addr, err := s.ReadFrom(b)
		if err != nil {
			return
		}
		for i := 0; i < N; i++ {
			msg := append([]byte{byte(i)}, bytes.Repeat([]byte{'z'}, 999)...)
			for {
				// a real QUIC sender retransmits; here, wait for a lane
				s.mu.Lock()
				sess := s.byAddr[addr.String()]
				s.mu.Unlock()
				sess.mu.Lock()
				open := 0
				for _, l := range sess.lanes {
					if l.role == roleDown && !l.full && l.alive() && l.sent+1002 <= l.budget {
						open++
					}
				}
				sess.mu.Unlock()
				if open > 0 {
					break
				}
				time.Sleep(5 * time.Millisecond)
			}
			s.WriteTo(msg, addr)
		}
	}()
	c, dials := newClient(t, cfg, s.local.(*gonet.UDPAddr).Port)
	c.WriteTo([]byte("start"), nil)
	b := make([]byte, 2000)
	for i := 0; i < N; i++ {
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, _, err := c.ReadFrom(b)
		if err != nil {
			t.Fatalf("datagram %d of %d never came: %v", i, N, err)
		}
		if n != 1000 {
			t.Fatalf("datagram %d: %d bytes", i, n)
		}
	}
	// 40 KB at 4 KB per down lane: at least ~10 down lanes
	if d := dials.Load(); d < 10 {
		t.Fatalf("%d lanes dialed for 40 KB at 4 KB per down lane", d)
	}
}

// Small datagrams within the flush time share one TCP write.
func TestFlushCoalescesWrites(t *testing.T) {
	cfg := testConfig()
	cfg.PacketsMin, cfg.PacketsMax = 100, 100
	cfg.Flush = 50
	_, port, _ := echoServer(t, cfg)
	c, _ := newClient(t, cfg, port)
	for i := 0; i < 10; i++ {
		c.WriteTo([]byte{byte(i)}, nil)
	}
	b := make([]byte, 64)
	for i := 0; i < 10; i++ {
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, _, err := c.ReadFrom(b); err != nil {
			t.Fatalf("echo %d: %v", i, err)
		}
	}
	c.mu.Lock()
	w := c.current.written
	c.mu.Unlock()
	if w > 2 {
		t.Fatalf("10 one-byte datagrams took %d writes, want them coalesced", w)
	}
}

// A burst larger than the open down lanes can take waits for the client's
// next down lanes instead of being dropped or pushed onto an up lane.
func TestServerBurstWaitsForDownLanes(t *testing.T) {
	cfg := testConfig()
	cfg.BytesMin, cfg.BytesMax = 4000, 4000
	lc := &finalmask.ListenConfig{
		Listen: func(a net.Addr) (net.Listener, error) { return gonet.Listen("tcp", a.String()) },
	}
	s, err := newServerConn(cfg, &gonet.UDPAddr{IP: gonet.IPv4(127, 0, 0, 1)}, lc)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	const N = 40
	go func() {
		b := make([]byte, 64)
		_, addr, err := s.ReadFrom(b)
		if err != nil {
			return
		}
		for i := 0; i < N; i++ {
			s.WriteTo(append([]byte{byte(i)}, bytes.Repeat([]byte{'z'}, 999)...), addr)
		}
	}()
	c, _ := newClient(t, cfg, s.local.(*gonet.UDPAddr).Port)
	c.WriteTo([]byte("start"), nil)
	b := make([]byte, 2000)
	for i := 0; i < N; i++ {
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, _, err := c.ReadFrom(b); err != nil {
			t.Fatalf("datagram %d of %d never came: %v", i, N, err)
		}
	}
}
