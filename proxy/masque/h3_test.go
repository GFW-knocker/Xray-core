package masque

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	gotls "crypto/tls"
	"encoding/hex"
	gonet "net"
	"net/http"
	"strings"
	"testing"
	"time"

	xnet "github.com/GFW-knocker/Xray-core/common/net"
	"github.com/GFW-knocker/Xray-core/transport/internet"
	"github.com/apernet/quic-go/http3"
)

func TestNewConnectRequest(t *testing.T) {
	request, err := newConnectRequest("cloudflareaccess.com", "/", "cf-connect-ip")
	if err != nil {
		t.Fatalf("newConnectRequest: %v", err)
	}
	if request.Method != http.MethodConnect {
		t.Errorf("method = %s, want CONNECT", request.Method)
	}
	// quic-go turns Proto into :protocol, which is what makes this extended.
	if request.Proto != "cf-connect-ip" {
		t.Errorf("proto = %q, want the connect protocol", request.Proto)
	}
	if request.Host != "cloudflareaccess.com" {
		t.Errorf("host = %q, want the authority", request.Host)
	}
	if got := request.URL.RequestURI(); got != "/" {
		t.Errorf("path = %q, want /", got)
	}
	if got := request.Header.Get(http3.CapsuleProtocolHeader); got != "?1" {
		t.Errorf("%s = %q, want ?1", http3.CapsuleProtocolHeader, got)
	}
	if got := request.Header["User-Agent"]; len(got) != 1 || got[0] != "" {
		t.Errorf("User-Agent = %v, want one empty value so quic-go omits it", got)
	}
}

func TestNewConnectRequestRejectsBadInput(t *testing.T) {
	for _, c := range []struct{ name, authority, path, protocol, want string }{
		{"no authority", "", "/", "cf-connect-ip", "authority"},
		{"no protocol", "host", "/", "", "connectProtocol"},
		{"relative path", "host", "tunnel", "cf-connect-ip", "start with /"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := newConnectRequest(c.authority, c.path, c.protocol); err == nil {
				t.Fatal("newConnectRequest succeeded, want an error")
			} else if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error is %q, want it to mention %q", err, c.want)
			}
		})
	}
}

// fakeEdge is an HTTP/3 server that answers extended CONNECT the way the real
// edge does, so the whole dial path can be exercised without leaving the machine.
type fakeEdge struct {
	port     int
	pin      string
	protocol string

	accepted chan *http.Request
}

func startFakeEdge(t *testing.T, protocol string) *fakeEdge {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	// The edge's own certificate is as bare as the client's; nothing builds a
	// chain through it, the client pins the key.
	certificate, err := SelfSignedCertificate(key)
	if err != nil {
		t.Fatalf("SelfSignedCertificate: %v", err)
	}
	pin := PublicKeySHA256(certificate.Leaf)

	conn, err := gonet.ListenUDP("udp", &gonet.UDPAddr{IP: gonet.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}

	edge := &fakeEdge{
		port:     conn.LocalAddr().(*gonet.UDPAddr).Port,
		pin:      hex.EncodeToString(pin[:]),
		protocol: protocol,
		accepted: make(chan *http.Request, 1),
	}

	server := &http3.Server{
		EnableDatagrams: true,
		TLSConfig: &gotls.Config{
			Certificates: []gotls.Certificate{certificate},
			NextProtos:   []string{"h3"},
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodConnect || r.Proto != edge.protocol {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			select {
			case edge.accepted <- r:
			default:
			}
			w.WriteHeader(http.StatusOK)

			streamer, ok := w.(http3.HTTPStreamer)
			if !ok {
				return
			}
			stream := streamer.HTTPStream()
			defer stream.Close()

			// Echo every packet back, which is all the pump needs from an edge.
			for {
				payload, err := stream.ReceiveDatagram(r.Context())
				if err != nil {
					return
				}
				if err := stream.SendDatagram(payload); err != nil {
					return
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

// handlerFor builds a Handler pointed at the fake edge, skipping NewClient so
// the test does not need a whole Xray instance behind it.
func handlerFor(t *testing.T, edge *fakeEdge) *Handler {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return &Handler{
		conf: &Config{
			Transport:                 Config_H3,
			Authority:                 "edge.invalid",
			Path:                      DefaultPath,
			ConnectProtocol:           edge.protocol,
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
		mtu:        DefaultMTU,
	}
}

func TestDialH3OpensATunnel(t *testing.T) {
	edge := startFakeEdge(t, DefaultConnectProtocol)
	handler := handlerFor(t, edge)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	tunnel, err := handler.dialH3(ctx)
	if err != nil {
		t.Fatalf("dialH3: %v", err)
	}
	defer tunnel.Close()

	select {
	case request := <-edge.accepted:
		if request.Proto != DefaultConnectProtocol {
			t.Errorf("the edge saw :protocol %q, want %q", request.Proto, DefaultConnectProtocol)
		}
		if request.Host != "edge.invalid" {
			t.Errorf("the edge saw :authority %q, want edge.invalid", request.Host)
		}
		if got := request.Header.Get(http3.CapsuleProtocolHeader); got != "?1" {
			t.Errorf("the edge saw %s %q, want ?1", http3.CapsuleProtocolHeader, got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the dial reported success but the edge never saw the CONNECT")
	}
}

// The packets are the datagrams, so a tunnel that cannot carry one is no tunnel.
func TestDialH3CarriesDatagrams(t *testing.T) {
	edge := startFakeEdge(t, DefaultConnectProtocol)
	handler := handlerFor(t, edge)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	tunnel, err := handler.dialH3(ctx)
	if err != nil {
		t.Fatalf("dialH3: %v", err)
	}
	defer tunnel.Close()

	packet := ipv4Packet(42)
	if err := tunnel.request.SendDatagram(appendH3Datagram(nil, packet)); err != nil {
		t.Fatalf("SendDatagram: %v", err)
	}

	received, cancelReceive := context.WithTimeout(ctx, 10*time.Second)
	defer cancelReceive()
	payload, err := tunnel.request.ReceiveDatagram(received)
	if err != nil {
		t.Fatalf("ReceiveDatagram: %v", err)
	}

	got, ok := stripDatagramContext(payload)
	if !ok {
		t.Fatalf("the echoed payload %x did not yield a packet", payload)
	}
	if string(got) != string(packet) {
		t.Errorf("packet came back as %x, want %x", got, packet)
	}
}

// The pin is the only thing standing in for chain validation, so a tunnel to an
// edge holding a different key has to fail rather than come up.
func TestDialH3RefusesAnUnpinnedEdge(t *testing.T) {
	edge := startFakeEdge(t, DefaultConnectProtocol)
	handler := handlerFor(t, edge)

	other := sha256.Sum256([]byte("not the edge's key"))
	handler.conf.PinnedPeerPublicKeySha256 = []string{hex.EncodeToString(other[:])}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	tunnel, err := handler.dialH3(ctx)
	if err == nil {
		tunnel.Close()
		t.Fatal("the dial succeeded against an edge whose key is not pinned")
	}
	if !strings.Contains(err.Error(), "matches none of the pins") {
		t.Errorf("error is %q, want it to name the pin mismatch", err)
	}
}

// An edge that does not recognise the protocol token refuses the request, and
// that refusal has to surface rather than look like a working tunnel.
func TestDialH3ReportsARefusedTunnel(t *testing.T) {
	edge := startFakeEdge(t, "some-other-protocol")
	handler := handlerFor(t, edge)
	handler.conf.ConnectProtocol = DefaultConnectProtocol

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	tunnel, err := handler.dialH3(ctx)
	if err == nil {
		tunnel.Close()
		t.Fatal("the dial succeeded although the edge refused the CONNECT")
	}
	if !strings.Contains(err.Error(), "refused the tunnel") {
		t.Errorf("error is %q, want it to say the edge refused", err)
	}
}
