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
	"github.com/GFW-knocker/Xray-core/transport/internet/finalmask"
	"github.com/GFW-knocker/Xray-core/transport/internet/finalmask/fragment"
	"golang.org/x/net/http2"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// h2Edge is the HTTP/2 counterpart of routingEdge: it terminates the tunnel on
// a netstack of its own, but every packet arrives as a DATAGRAM capsule on the
// request stream because there are no datagrams here.
//
// It demands a client certificate, which is how the real edge authenticates a
// registered key, so a carrier that failed to present one would not get this far.
type h2Edge struct {
	port     int
	pin      string
	stacks   chan *stack.Stack
	requests chan connectRequest
}

// connectRequest is what the edge saw, so a test can assert the shape of the
// CONNECT and not merely that one arrived.
type connectRequest struct {
	// protocol is the cf-connect-proto header, which is where this carrier
	// names the tunnel protocol.
	protocol string
	// extended is the :protocol pseudo-header. It has to be empty: an extended
	// CONNECT is what the HTTP/3 carrier sends, and what this edge would refuse.
	extended string
	path     string
}

func startH2Edge(t *testing.T) *h2Edge {
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

	listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	edge := &h2Edge{
		port:     listener.Addr().(*stdnet.TCPAddr).Port,
		pin:      hex.EncodeToString(pin[:]),
		stacks:   make(chan *stack.Stack, 4),
		requests: make(chan connectRequest, 4),
	}

	tlsConfig := &gotls.Config{
		Certificates: []gotls.Certificate{certificate},
		NextProtos:   []string{"h2"},
		ClientAuth:   gotls.RequireAnyClientCert,
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		select {
		case edge.requests <- connectRequest{
			protocol: r.Header.Get(connectProtocolHeader),
			extended: r.Header.Get(":protocol"),
			path:     r.URL.Path,
		}:
		default:
		}

		w.WriteHeader(http.StatusOK)
		flusher, ok := w.(http.Flusher)
		if !ok {
			return
		}
		flusher.Flush()

		device, _, netStack, err := CreateNetTUN(
			[]netip.Addr{netip.MustParseAddr(edgeAddress)}, nil, DefaultMTU, true)
		if err != nil {
			return
		}
		defer device.Close()
		edge.stacks <- netStack

		done := make(chan struct{})
		// The edge's netstack sends: frame as capsules on the response body.
		go func() {
			defer close(done)
			buf := make([]byte, DefaultMTU)
			for {
				n, err := device.ReadPacket(buf)
				if err != nil {
					return
				}
				if _, err := w.Write(appendDatagramCapsule(nil, buf[:n])); err != nil {
					return
				}
				flusher.Flush()
			}
		}()

		// The client sends: capsules on the request body.
		capsules := newCapsuleReader(r.Body)
		for {
			kind, value, err := capsules.next()
			if err != nil {
				device.Close()
				<-done
				return
			}
			if kind != capsuleDatagram {
				continue
			}
			if packet, ok := stripDatagramContext(value); ok {
				device.WritePacket(packet)
			}
		}
	})

	go func() {
		server := &http2.Server{}
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				tlsConn := gotls.Server(conn, tlsConfig)
				if err := tlsConn.Handshake(); err != nil {
					conn.Close()
					return
				}
				server.ServeConn(tlsConn, &http2.ServeConnOpts{Handler: handler})
			}()
		}
	}()
	return edge
}

func handlerForH2Edge(t *testing.T, edge *h2Edge, stream *internet.MemoryStreamConfig) *Handler {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	parsed, err := parseAddresses([]string{clientAddress + "/32"})
	if err != nil {
		t.Fatalf("parseAddresses: %v", err)
	}
	if stream == nil {
		stream = &internet.MemoryStreamConfig{}
	}
	return &Handler{
		conf: &Config{
			Transport:                 Config_H2,
			Authority:                 "edge.invalid",
			Path:                      DefaultPath,
			ConnectProtocol:           DefaultConnectProtocol,
			Mtu:                       DefaultMTU,
			PinnedPeerPublicKeySha256: []string{edge.pin},
		},
		streamSettings: stream,
		endpoint: xnet.Destination{
			Address: xnet.ParseAddress("127.0.0.1"),
			Port:    xnet.Port(edge.port),
			// The HTTP/2 carrier rides TCP, which parseEndpoint would have set.
			Network: xnet.Network_TCP,
		},
		privateKey: key,
		addresses:  parsed,
		mtu:        DefaultMTU,
	}
}

// The same proof as for HTTP/3, over a carrier with no datagrams: a TCP
// connection on the client's netstack reaches a listener on the far side, with
// every packet travelling as a capsule.
func TestH2TunnelCarriesATCPConnection(t *testing.T) {
	edge := startH2Edge(t)
	handler := handlerForH2Edge(t, edge, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tunnel, err := handler.startTunnel(ctx)
	if err != nil {
		t.Fatalf("startTunnel: %v", err)
	}
	defer tunnel.Close()

	select {
	case request := <-edge.requests:
		if request.protocol != DefaultConnectProtocol {
			t.Errorf("the edge saw %s %q, want %q",
				connectProtocolHeader, request.protocol, DefaultConnectProtocol)
		}
		// An ordinary CONNECT, which is what this edge answers. See
		// connectProtocolHeader for why the two carriers differ here.
		if request.extended != "" {
			t.Errorf("the edge saw :protocol %q, want an ordinary CONNECT with none", request.extended)
		}
		if request.path != "" {
			t.Errorf("the edge saw :path %q, want an ordinary CONNECT with none", request.path)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the edge never saw the CONNECT")
	}

	var netStack *stack.Stack
	select {
	case netStack = <-edge.stacks:
	case <-time.After(10 * time.Second):
		t.Fatal("the edge never brought its netstack up")
	}
	echoOnEdge(t, netStack, 82)

	dialCtx, dialCancel := context.WithTimeout(ctx, 15*time.Second)
	defer dialCancel()
	conn, err := tunnel.tnet.DialContextTCPAddrPort(dialCtx, netip.MustParseAddrPort(edgeAddress+":82"))
	if err != nil {
		t.Fatalf("dialling through the tunnel: %v", err)
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
	if string(reply) != "HELLO" {
		t.Errorf("got %q back, want HELLO", reply)
	}
}

// Where the SNI is filtered, the HTTP/2 carrier only reaches the edge if the
// ClientHello is fragmented, which means the tcpmask has to sit under TLS
// rather than over it. A tunnel that comes up with a fragment mask configured
// is a tunnel whose ClientHello went through it.
func TestH2TunnelWorksThroughAFragmentMask(t *testing.T) {
	edge := startH2Edge(t)

	handler := handlerForH2Edge(t, edge, fragmentMaskSettings())

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tunnel, err := handler.startTunnel(ctx)
	if err != nil {
		t.Fatalf("startTunnel with a fragment mask: %v", err)
	}
	defer tunnel.Close()

	netStack := <-edge.stacks
	echoOnEdge(t, netStack, 83)

	conn, err := tunnel.tnet.DialContextTCPAddrPort(ctx, netip.MustParseAddrPort(edgeAddress+":83"))
	if err != nil {
		t.Fatalf("dialling through the fragmented tunnel: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))

	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("writing through the fragmented tunnel: %v", err)
	}
	reply := make([]byte, 5)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("reading through the fragmented tunnel: %v", err)
	}
	if string(reply) != "HELLO" {
		t.Errorf("got %q back, want HELLO", reply)
	}
}

// An edge that refuses the protocol token has to surface as an error.
func TestH2TunnelReportsARefusedTunnel(t *testing.T) {
	edge := startH2Edge(t)
	handler := handlerForH2Edge(t, edge, nil)
	handler.conf.Authority = ""

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	if tunnel, err := handler.startTunnel(ctx); err == nil {
		tunnel.Close()
		t.Fatal("the tunnel came up without an authority")
	} else if !strings.Contains(err.Error(), "authority") {
		t.Errorf("error is %q, want it to name the missing authority", err)
	}
}

// fragmentMaskSettings builds the "tlshello" shape of the fragment mask: split
// the first TLS record, which is the ClientHello carrying the SNI.
func fragmentMaskSettings() *internet.MemoryStreamConfig {
	config := &fragment.Config{
		PacketsFrom: 0,
		PacketsTo:   1,
		LengthsMin:  []int64{10},
		LengthsMax:  []int64{30},
		DelaysMin:   []int64{0},
		DelaysMax:   []int64{0},
	}
	return &internet.MemoryStreamConfig{
		TcpmaskManager: finalmask.NewTcpmaskManager([]finalmask.Tcpmask{config}),
	}
}

// The HTTP/2 carrier is the only one without a keepalive of its own, so what
// this resolves to is the whole of its liveness story.
func TestKeepAliveResolvesToTheRightPair(t *testing.T) {
	cases := []struct {
		name            string
		period, timeout int32
		wantPeriod      time.Duration
		wantTimeout     time.Duration
	}{
		{"unset takes the reference client's numbers", 0, 0, DefaultKeepAlivePeriod, DefaultKeepAliveTimeout},
		{"a period on its own keeps the default timeout", 30, 0, 30 * time.Second, DefaultKeepAliveTimeout},
		{"a timeout on its own keeps the default period", 0, 45, DefaultKeepAlivePeriod, 45 * time.Second},
		{"both set are both used", 5, 7, 5 * time.Second, 7 * time.Second},
		// x/net/http2 reads a zero ReadIdleTimeout as "no health check", which
		// is how a negative period turns the ping off.
		{"a negative period turns the ping off", -1, 0, 0, DefaultKeepAliveTimeout},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			period, timeout := (&Config{KeepAlivePeriod: c.period, KeepAliveTimeout: c.timeout}).keepAlive()
			if period != c.wantPeriod {
				t.Errorf("period = %v, want %v", period, c.wantPeriod)
			}
			if timeout != c.wantTimeout {
				t.Errorf("timeout = %v, want %v", timeout, c.wantTimeout)
			}
		})
	}
}
