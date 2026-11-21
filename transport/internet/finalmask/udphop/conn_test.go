package udphop

import (
	gonet "net"
	"testing"
	"time"

	"github.com/GFW-knocker/Xray-core/common/net"
	"github.com/GFW-knocker/Xray-core/transport/internet/finalmask"
)

// loopbackDialer opens a real UDP socket per dial, as the FinalMask dialer
// would, aimed at server.
func loopbackDialer(t *testing.T, server *gonet.UDPAddr) (*finalmask.Dialer, *int) {
	t.Helper()
	dials := 0
	return &finalmask.Dialer{
		DialUDP: func(net.Destination) (net.Conn, error) {
			c, err := gonet.ListenUDP("udp", &gonet.UDPAddr{IP: gonet.IPv4(127, 0, 0, 1)})
			if err != nil {
				return nil, err
			}
			dials++
			return &net.PacketConnWrapper{PacketConn: c, Dest: server}, nil
		},
	}, &dials
}

func newPacketLocal(t *testing.T, server *gonet.UDPConn, n int64) (*udpHopConn, *int) {
	t.Helper()
	addr := server.LocalAddr().(*gonet.UDPAddr)
	dialer, dials := loopbackDialer(t, addr)
	dest := net.UDPDestination(net.IPAddress(addr.IP), net.Port(addr.Port))
	pc, err := NewUDPHopConn(&Config{PacketLocal: true, PacketsMin: n, PacketsMax: n, IntervalMin: 30, IntervalMax: 30}, &dest, dialer)
	if err != nil {
		t.Fatal(err)
	}
	return pc.(*udpHopConn), dials
}

func listenServer(t *testing.T) *gonet.UDPConn {
	t.Helper()
	s, err := gonet.ListenUDP("udp", &gonet.UDPAddr{IP: gonet.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// readFrom reads one datagram on the server and returns its source port.
func readFrom(t *testing.T, s *gonet.UDPConn) (byte, *gonet.UDPAddr) {
	t.Helper()
	buf := make([]byte, 64)
	s.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, from, err := s.ReadFromUDP(buf)
	if err != nil || n != 1 {
		t.Fatalf("server read: n=%d err=%v", n, err)
	}
	return buf[0], from
}

func TestPacketLocalRotatesEveryN(t *testing.T) {
	server := listenServer(t)
	c, dials := newPacketLocal(t, server, 3)
	defer c.Close()

	var ports []int
	for i := 0; i < 10; i++ {
		if _, err := c.WriteTo([]byte{byte(i)}, nil); err != nil {
			t.Fatal(err)
		}
		b, from := readFrom(t, server)
		if int(b) != i {
			t.Fatalf("datagram %d arrived as %d", i, b)
		}
		ports = append(ports, from.Port)
	}
	// 3, 3, 3, 1 datagrams on four ports, in order
	for i, p := range ports {
		if p != ports[i/3*3] {
			t.Fatalf("datagram %d left from port %d, want the port of datagram %d (%d): %v", i, p, i/3*3, ports[i/3*3], ports)
		}
	}
	for g := 1; g < 4; g++ {
		if ports[g*3] == ports[(g-1)*3] {
			t.Fatalf("no new port for datagram %d: %v", g*3, ports)
		}
	}
	if *dials != 4 {
		t.Fatalf("dialed %d sockets, want 4", *dials)
	}
}

// A retired port must keep receiving: a QUIC server keeps answering the first
// port, WireGuard answers the newest one.
func TestPacketLocalRetiredPortsStillReceive(t *testing.T) {
	server := listenServer(t)
	c, _ := newPacketLocal(t, server, 2)
	defer c.Close()

	var first, last *gonet.UDPAddr
	for i := 0; i < 7; i++ {
		if _, err := c.WriteTo([]byte{byte(i)}, nil); err != nil {
			t.Fatal(err)
		}
		_, from := readFrom(t, server)
		if first == nil {
			first = from
		}
		last = from
	}
	if first.Port == last.Port {
		t.Fatal("never rotated")
	}

	for _, to := range []*gonet.UDPAddr{first, last} {
		if _, err := server.WriteToUDP([]byte{0xAB}, to); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 64)
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := c.ReadFrom(buf)
		if err != nil || n != 1 || buf[0] != 0xAB {
			t.Fatalf("reply to port %d: n=%d err=%v", to.Port, n, err)
		}
	}
	c.SetReadDeadline(time.Time{})
}

func TestPacketLocalClose(t *testing.T) {
	server := listenServer(t)
	c, _ := newPacketLocal(t, server, 1)
	for i := 0; i < 5; i++ {
		if _, err := c.WriteTo([]byte{byte(i)}, nil); err != nil {
			t.Fatal(err)
		}
		readFrom(t, server)
	}
	done := make(chan error, 1)
	go func() { done <- c.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Close hung")
	}
	if len(c.retired) != 0 {
		t.Fatalf("%d retired sockets left after Close", len(c.retired))
	}
	if _, err := c.WriteTo([]byte{9}, nil); err == nil {
		t.Fatal("write after Close succeeded")
	}
}

func TestPacketLocalConfigChecks(t *testing.T) {
	server := listenServer(t)
	addr := server.LocalAddr().(*gonet.UDPAddr)
	dialer, _ := loopbackDialer(t, addr)
	dest := net.UDPDestination(net.IPAddress(addr.IP), net.Port(addr.Port))
	for _, c := range []*Config{
		{PacketLocal: true, Local: true, PacketsMin: 8, PacketsMax: 8, IntervalMin: 30, IntervalMax: 30},
		{PacketLocal: true, PacketsMin: 0, PacketsMax: 8, IntervalMin: 30, IntervalMax: 30},
		{PacketLocal: true, PacketsMin: 9, PacketsMax: 8, IntervalMin: 30, IntervalMax: 30},
	} {
		if pc, err := NewUDPHopConn(c, &dest, dialer); err == nil {
			pc.Close()
			t.Errorf("%+v: accepted", c)
		}
	}
}
