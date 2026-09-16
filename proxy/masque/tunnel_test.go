package masque

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	gotls "crypto/tls"
	"encoding/hex"
	"io"
	stdnet "net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	xnet "github.com/GFW-knocker/Xray-core/common/net"
	"github.com/GFW-knocker/Xray-core/transport/internet"
	"github.com/apernet/quic-go/http3"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	clientAddress = "10.0.0.2"
	edgeAddress   = "10.0.0.1"
)

// routingEdge is a fake edge that terminates the tunnel on a netstack of its
// own, so packets the client sends are actually routed and answered rather than
// bounced back. That makes a real TCP connection over the tunnel possible
// without leaving the process.
type routingEdge struct {
	port   int
	pin    string
	stacks chan *stack.Stack
	// assign, when set, is sent as an ADDRESS_ASSIGN capsule once the tunnel
	// opens, standing in for what the real edge volunteers.
	assign []byte
}

func startRoutingEdge(t *testing.T) *routingEdge {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	certificate, err := SelfSignedCertificate(key)
	if err != nil {
		t.Fatalf("SelfSignedCertificate: %v", err)
	}
	pin := PublicKeySHA256(certificate.Leaf)

	conn, err := stdnet.ListenUDP("udp", &stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}

	edge := &routingEdge{
		port:   conn.LocalAddr().(*stdnet.UDPAddr).Port,
		pin:    hex.EncodeToString(pin[:]),
		stacks: make(chan *stack.Stack, 4),
	}

	server := &http3.Server{
		EnableDatagrams: true,
		TLSConfig: &gotls.Config{
			Certificates: []gotls.Certificate{certificate},
			NextProtos:   []string{"h3"},
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodConnect {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusOK)
			streamer, ok := w.(http3.HTTPStreamer)
			if !ok {
				return
			}
			stream := streamer.HTTPStream()
			defer stream.Close()

			device, _, netStack, err := CreateNetTUN(
				[]netip.Addr{netip.MustParseAddr(edgeAddress)}, nil, DefaultMTU, true)
			if err != nil {
				return
			}
			defer device.Close()
			edge.stacks <- netStack

			if edge.assign != nil {
				if _, err := stream.Write(appendCapsule(nil, capsuleAddressAssign, edge.assign)); err != nil {
					return
				}
			}

			done := make(chan struct{})
			// The edge's netstack sends: forward to the client.
			go func() {
				defer close(done)
				buf := make([]byte, DefaultMTU)
				for {
					n, err := device.ReadPacket(buf)
					if err != nil {
						return
					}
					if err := stream.SendDatagram(appendH3Datagram(nil, buf[:n])); err != nil {
						return
					}
				}
			}()
			// The client sends: hand to the edge's netstack.
			for {
				payload, err := stream.ReceiveDatagram(r.Context())
				if err != nil {
					// Close the device before waiting: the reader only unblocks
					// once it does, and the deferred close is too late for that.
					device.Close()
					<-done
					return
				}
				if packet, ok := stripDatagramContext(payload); ok {
					device.WritePacket(packet)
				}
			}
		}),
	}

	go server.Serve(conn)
	t.Cleanup(func() {
		server.Close()
		conn.Close()
	})
	return edge
}

func handlerForRoutingEdge(t *testing.T, edge *routingEdge, addresses []string) *Handler {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	parsed, err := parseAddresses(addresses)
	if err != nil {
		t.Fatalf("parseAddresses: %v", err)
	}
	return &Handler{
		conf: &Config{
			Transport:                 Config_H3,
			Authority:                 "edge.invalid",
			Path:                      DefaultPath,
			ConnectProtocol:           DefaultConnectProtocol,
			Mtu:                       DefaultMTU,
			PinnedPeerPublicKeySha256: []string{edge.pin},
		},
		streamSettings: &internet.MemoryStreamConfig{},
		endpoint: xnet.Destination{
			Address: xnet.ParseAddress("127.0.0.1"),
			Port:    xnet.Port(edge.port),
			Network: xnet.Network_UDP,
		},
		privateKey: key,
		addresses:  parsed,
		mtu:        DefaultMTU,
	}
}

// listenOnEdge puts a TCP listener on the edge's netstack, which is what the
// client's traffic has to reach for the pump to be doing its job.
func listenOnEdge(t *testing.T, netStack *stack.Stack, port uint16) *gonet.TCPListener {
	t.Helper()
	listener, err := gonet.ListenTCP(netStack, tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(netip.MustParseAddr(edgeAddress).AsSlice()),
		Port: port,
	}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("ListenTCP on the edge: %v", err)
	}
	t.Cleanup(func() { listener.Close() })
	return listener
}

// The point of the whole thing: a TCP connection opened on the client's
// netstack has to reach a listener on the far side of the tunnel, and carry
// bytes both ways.
func TestTunnelCarriesATCPConnection(t *testing.T) {
	edge := startRoutingEdge(t)
	handler := handlerForRoutingEdge(t, edge, []string{clientAddress + "/32"})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tunnel, err := handler.startTunnel(ctx)
	if err != nil {
		t.Fatalf("startTunnel: %v", err)
	}
	defer tunnel.Close()

	var netStack *stack.Stack
	select {
	case netStack = <-edge.stacks:
	case <-time.After(10 * time.Second):
		t.Fatal("the edge never brought its netstack up")
	}
	listener := listenOnEdge(t, netStack, 80)

	accepted := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			accepted <- err
			return
		}
		defer conn.Close()
		// Read the greeting and answer it, so both directions are exercised.
		buf := make([]byte, 5)
		if _, err := io.ReadFull(conn, buf); err != nil {
			accepted <- err
			return
		}
		if string(buf) != "hello" {
			accepted <- io.ErrUnexpectedEOF
			return
		}
		_, err = conn.Write([]byte("world"))
		accepted <- err
	}()

	dialCtx, dialCancel := context.WithTimeout(ctx, 15*time.Second)
	defer dialCancel()
	conn, err := tunnel.tnet.DialContextTCPAddrPort(dialCtx, netip.MustParseAddrPort(edgeAddress+":80"))
	if err != nil {
		t.Fatalf("dialing through the tunnel: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("writing through the tunnel: %v", err)
	}
	reply := make([]byte, 5)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("reading through the tunnel: %v", err)
	}
	if string(reply) != "world" {
		t.Errorf("got %q back, want %q", reply, "world")
	}

	select {
	case err := <-accepted:
		if err != nil {
			t.Errorf("the far side reported %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("the far side never finished")
	}
}

// With no address configured, the tunnel has to take the one the edge assigns.
func TestTunnelTakesTheAddressTheEdgeAssigns(t *testing.T) {
	edge := startRoutingEdge(t)
	// One ADDRESS_ASSIGN: request ID 1, IPv4, 10.0.0.2/32.
	edge.assign = []byte{0x01, 4, 10, 0, 0, 2, 32}

	handler := handlerForRoutingEdge(t, edge, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tunnel, err := handler.startTunnel(ctx)
	if err != nil {
		t.Fatalf("startTunnel: %v", err)
	}
	defer tunnel.Close()

	// The address only counts if the netstack actually holds it, which a
	// connection from it proves.
	netStack := <-edge.stacks
	listener := listenOnEdge(t, netStack, 81)

	from := make(chan string, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			from <- ""
			return
		}
		defer conn.Close()
		from <- conn.RemoteAddr().String()
	}()

	dialCtx, dialCancel := context.WithTimeout(ctx, 15*time.Second)
	defer dialCancel()
	conn, err := tunnel.tnet.DialContextTCPAddrPort(dialCtx, netip.MustParseAddrPort(edgeAddress+":81"))
	if err != nil {
		t.Fatalf("dialing through the tunnel: %v", err)
	}
	defer conn.Close()

	select {
	case remote := <-from:
		if !strings.HasPrefix(remote, clientAddress+":") {
			t.Errorf("the far side saw the connection from %q, want it from the assigned %s", remote, clientAddress)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the far side never saw the connection")
	}
}

// A tunnel whose configuration names no address and whose edge assigns none has
// to give up rather than hang.
func TestTunnelGivesUpWithoutAnAddress(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out the address timeout")
	}
	edge := startRoutingEdge(t) // assigns nothing
	handler := handlerForRoutingEdge(t, edge, nil)

	ctx, cancel := context.WithTimeout(context.Background(), addressWait+20*time.Second)
	defer cancel()

	started := time.Now()
	tunnel, err := handler.startTunnel(ctx)
	if err == nil {
		tunnel.Close()
		t.Fatal("the tunnel came up without an address")
	}
	if !strings.Contains(err.Error(), "assigned no address") {
		t.Errorf("error is %q, want it to say no address arrived", err)
	}
	if waited := time.Since(started); waited < addressWait {
		t.Errorf("gave up after %v, want it to wait the full %v", waited, addressWait)
	}
}

// Closing has to stop every loop, and has to be safe from more than one of them
// at once, since each calls it on the way out.
func TestTunnelCloseIsIdempotent(t *testing.T) {
	edge := startRoutingEdge(t)
	handler := handlerForRoutingEdge(t, edge, []string{clientAddress + "/32"})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tunnel, err := handler.startTunnel(ctx)
	if err != nil {
		t.Fatalf("startTunnel: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := tunnel.Close(); err != nil {
			t.Fatalf("Close %d: %v", i, err)
		}
	}

	// Once closed, the netstack is gone and dialling through it must fail
	// rather than block forever.
	dialCtx, dialCancel := context.WithTimeout(ctx, 5*time.Second)
	defer dialCancel()
	if conn, err := tunnel.tnet.DialContextTCPAddrPort(dialCtx, netip.MustParseAddrPort(edgeAddress+":80")); err == nil {
		conn.Close()
		t.Error("dialling through a closed tunnel succeeded")
	}
}
