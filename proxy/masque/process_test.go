package masque

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GFW-knocker/Xray-core/common/buf"
	xnet "github.com/GFW-knocker/Xray-core/common/net"
	"github.com/GFW-knocker/Xray-core/common/session"
	"github.com/GFW-knocker/Xray-core/features/policy"
	"github.com/GFW-knocker/Xray-core/transport"
	"github.com/GFW-knocker/Xray-core/transport/internet"
	"github.com/GFW-knocker/Xray-core/transport/internet/stat"
	"github.com/GFW-knocker/Xray-core/transport/pipe"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// stubDialer stands in for the system dialer. Process only uses it to record
// the outbound gateway; the tunnel does its own dialling.
type stubDialer struct{}

func (stubDialer) Dial(context.Context, xnet.Destination) (stat.Connection, error) {
	return nil, io.ErrUnexpectedEOF
}
func (stubDialer) DestIpAddress() xnet.IP                                { return nil }
func (stubDialer) SetOutboundGateway(context.Context, *session.Outbound) {}

// echoOnEdge answers one connection on the edge's netstack, turning what it
// reads into upper case so the reply cannot be confused with an echo of the
// request travelling the wrong way.
func echoOnEdge(t *testing.T, netStack *stack.Stack, port uint16) {
	t.Helper()
	listener := listenOnEdge(t, netStack, port)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 5)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		conn.Write([]byte(strings.ToUpper(string(buf))))
	}()
}

func processHandler(t *testing.T, edge *routingEdge) *Handler {
	t.Helper()
	h := handlerForRoutingEdge(t, edge, []string{clientAddress + "/32"})
	h.policyManager = policy.DefaultManager{}
	return h
}

// contextForTarget builds the session context an outbound is dispatched with.
func contextForTarget(ctx context.Context, target xnet.Destination) context.Context {
	return session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: target}})
}

// The whole outbound, end to end: bytes handed to Process have to come out of a
// listener on the far side of the tunnel, and the answer has to come back.
func TestProcessCarriesATCPConnection(t *testing.T) {
	edge := startRoutingEdge(t)
	handler := processHandler(t, edge)
	t.Cleanup(func() { handler.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Bring the tunnel up first so the edge's netstack exists to listen on.
	if _, err := handler.session(ctx); err != nil {
		t.Fatalf("session: %v", err)
	}
	echoOnEdge(t, <-edge.stacks, 90)

	upReader, upWriter := pipe.New(pipe.WithoutSizeLimit())
	downReader, downWriter := pipe.New(pipe.WithoutSizeLimit())

	done := make(chan error, 1)
	go func() {
		done <- handler.Process(
			contextForTarget(ctx, xnet.TCPDestination(xnet.ParseAddress(edgeAddress), 90)),
			&transport.Link{Reader: upReader, Writer: downWriter},
			stubDialer{},
		)
	}()

	if err := upWriter.WriteMultiBuffer(buf.MergeBytes(nil, []byte("hello"))); err != nil {
		t.Fatalf("writing into the link: %v", err)
	}

	reply, err := readN(downReader, 5, 15*time.Second)
	if err != nil {
		t.Fatalf("reading the reply: %v", err)
	}
	if reply != "HELLO" {
		t.Errorf("got %q back, want %q", reply, "HELLO")
	}

	upWriter.Close()
	select {
	case err := <-done:
		// Process returns once both directions finish; either way it must not
		// report a failure of its own.
		if err != nil && !strings.Contains(err.Error(), "connection ends") {
			t.Errorf("Process reported %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Error("Process never returned")
	}
}

// readN collects n bytes from a buf.Reader, or gives up.
func readN(reader buf.Reader, n int, wait time.Duration) (string, error) {
	type result struct {
		s   string
		err error
	}
	out := make(chan result, 1)
	go func() {
		var got []byte
		for len(got) < n {
			mb, err := reader.ReadMultiBuffer()
			if err != nil {
				out <- result{string(got), err}
				return
			}
			for _, b := range mb {
				got = append(got, b.Bytes()...)
			}
			buf.ReleaseMulti(mb)
		}
		out <- result{string(got[:n]), nil}
	}()

	select {
	case r := <-out:
		return r.s, r.err
	case <-time.After(wait):
		return "", context.DeadlineExceeded
	}
}

// A target Process cannot carry has to be reported, not panicked on. A UNIX
// destination is valid as far as Destination.IsValid is concerned, so it reaches
// the switch; the WireGuard outbound panics on it, this one does not.
func TestProcessRefusesAnUnsupportedNetwork(t *testing.T) {
	edge := startRoutingEdge(t)
	handler := processHandler(t, edge)
	t.Cleanup(func() { handler.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	target := xnet.Destination{
		Address: xnet.ParseAddress(edgeAddress),
		Port:    90,
		Network: xnet.Network_UNIX,
	}
	upReader, _ := pipe.New(pipe.WithoutSizeLimit())
	_, downWriter := pipe.New(pipe.WithoutSizeLimit())

	err := handler.Process(
		contextForTarget(ctx, target),
		&transport.Link{Reader: upReader, Writer: downWriter},
		stubDialer{},
	)
	if err == nil {
		t.Fatal("Process accepted a network it cannot carry")
	}
	if !strings.Contains(err.Error(), "cannot carry") {
		t.Errorf("error is %q, want it to say the network is not carried", err)
	}
}

// The tunnel is shared and long lived, so a dead one has to be replaced rather
// than leaving the outbound broken for good.
func TestProcessReopensADeadTunnel(t *testing.T) {
	edge := startRoutingEdge(t)
	handler := processHandler(t, edge)
	t.Cleanup(func() { handler.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	first, err := handler.session(ctx)
	if err != nil {
		t.Fatalf("first session: %v", err)
	}
	<-edge.stacks

	// Whatever killed it, from the outbound's point of view the tunnel is gone.
	first.Close()
	if first.alive() {
		t.Fatal("the tunnel still reports itself alive after Close")
	}

	second, err := handler.session(ctx)
	if err != nil {
		t.Fatalf("second session: %v", err)
	}
	if second == first {
		t.Fatal("the outbound handed back the dead tunnel")
	}
	if !second.alive() {
		t.Error("the replacement tunnel is not alive")
	}

	// And it works: a connection over the replacement reaches the edge.
	echoOnEdge(t, <-edge.stacks, 91)
	conn, err := second.tnet.DialContextTCPAddrPort(ctx, netip.MustParseAddrPort(edgeAddress+":91"))
	if err != nil {
		t.Fatalf("dialling over the replacement: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("writing over the replacement: %v", err)
	}
	reply := make([]byte, 5)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("reading over the replacement: %v", err)
	}
	if string(reply) != "HELLO" {
		t.Errorf("got %q, want HELLO", reply)
	}
}

// Once closed, the outbound stays closed rather than quietly dialling again.
func TestProcessStopsAfterClose(t *testing.T) {
	edge := startRoutingEdge(t)
	handler := processHandler(t, edge)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, err := handler.session(ctx); err != nil {
		t.Fatalf("session: %v", err)
	}
	if err := handler.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, err := handler.session(ctx); err == nil {
		t.Fatal("the outbound opened a tunnel after it was closed")
	} else if !strings.Contains(err.Error(), "closed") {
		t.Errorf("error is %q, want it to say the outbound is closed", err)
	}

	// Closing twice is what a shutdown path does.
	if err := handler.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

// Close has to return while a dial is still in flight.
//
// The dial can block for a very long time and, when the carrier is itself
// another masque tunnel, effectively forever: a TCP connect through a netstack
// to an address that never answers has nothing to refuse it. If Close waits for
// the dial -- which it does when both take the same mutex -- the process stops
// responding to Ctrl+C for exactly as long. Reported against two chained masque
// outbounds where the outer one pointed at a non-Cloudflare address.
func TestCloseDoesNotWaitForAnInFlightDial(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	parsed, err := parseAddresses([]string{clientAddress + "/32"})
	if err != nil {
		t.Fatalf("parseAddresses: %v", err)
	}

	// A port nothing listens on, reached through a dialer that simply never
	// answers, which is what an unreachable endpoint inside a tunnel looks like.
	blocked := make(chan struct{})
	defer close(blocked)

	h := &Handler{
		conf: &Config{
			Transport:       Config_H2,
			Authority:       "edge.invalid",
			Path:            DefaultPath,
			ConnectProtocol: DefaultConnectProtocol,
			Mtu:             DefaultMTU,
		},
		streamSettings: &internet.MemoryStreamConfig{},
		endpoint: xnet.Destination{
			Address: xnet.ParseAddress("198.51.100.1"), // TEST-NET-2, never routes
			Port:    xnet.Port(443),
			Network: xnet.Network_TCP,
		},
		privateKey: key,
		addresses:  parsed,
		mtu:        DefaultMTU,
		cache:      make(map[string]resolved),
	}

	dialing := make(chan struct{})
	dialReturned := make(chan struct{})
	go func() {
		close(dialing)
		// Never returns quickly on its own; the point is that Close must not
		// wait for it, and that Close makes it give up.
		h.session(context.Background())
		close(dialReturned)
	}()
	<-dialing
	time.Sleep(200 * time.Millisecond) // let the dial get under way

	done := make(chan error, 1)
	go func() { done <- h.Close() }()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close blocked behind the in-flight dial; Ctrl+C would hang here")
	}

	// And the dial has to actually stop, not merely stop being waited for. On a
	// phone the core is stopped and started again constantly, so a dial left
	// running past Close would hold a socket and a goroutine into the next run.
	select {
	case <-dialReturned:
	case <-time.After(10 * time.Second):
		t.Error("the dial was still running 10s after Close; it should have been abandoned")
	}
}
