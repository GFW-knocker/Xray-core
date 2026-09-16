package masque

import (
	"context"
	gotls "crypto/tls"
	"io"
	"net/http"
	"sync"

	"github.com/GFW-knocker/Xray-core/common/errors"
	"github.com/GFW-knocker/Xray-core/common/net"
	"github.com/GFW-knocker/Xray-core/transport/internet"
	xtls "github.com/GFW-knocker/Xray-core/transport/internet/tls"
	"golang.org/x/net/http2"
)

// h2Tunnel is one MASQUE tunnel riding HTTP/2.
//
// There are no datagrams here, so every packet travels as a DATAGRAM capsule on
// the request stream alongside the control capsules. That is TCP underneath, so
// a lost packet holds up everything behind it; this carrier is for paths where
// UDP does not survive, not a peer of the HTTP/3 one.
type h2Tunnel struct {
	conn     net.Conn
	request  *io.PipeWriter
	response io.ReadCloser

	// Capsules are written from the uplink goroutine, but Close can come from
	// any of them.
	writeMu sync.Mutex
	frame   []byte
}

// newH2ConnectRequest builds the extended CONNECT for the HTTP/2 carrier.
//
// RFC 8441 names the same :protocol pseudo-header RFC 9220 does, but where
// quic-go reads it off Proto, x/net/http2 reads it out of the header map, and
// the body is what the capsules are written into.
func newH2ConnectRequest(authority, path, protocol string, body io.ReadCloser) (*http.Request, error) {
	request, err := newConnectRequest(authority, path, protocol)
	if err != nil {
		return nil, err
	}
	// Assigned directly rather than through Set: a pseudo-header is not a valid
	// header name, and only direct assignment is guaranteed to leave it alone.
	request.Header[":protocol"] = []string{protocol}
	request.Body = body
	return request, nil
}

// dialTLSConn opens the TCP connection the HTTP/2 carrier rides on, through
// Xray's dialer so sockopt, dialerProxy chaining and the tcpmasks apply, and
// completes the TLS handshake on it.
func (h *Handler) dialTLSConn(ctx context.Context) (net.Conn, error) {
	tlsConfig, err := h.buildTLSConfig()
	if err != nil {
		return nil, err
	}

	if settings := xtls.ConfigFromStreamSettings(h.streamSettings); settings != nil && settings.Fingerprint != "" {
		// Xray's uTLS wrapper rebuilds the TLS config from a fixed list of
		// fields, and the client certificate is not one of them. Using it here
		// would drop the certificate the edge authenticates us by and the
		// handshake would fail for a reason nothing would explain.
		errors.LogWarning(ctx, `masque: ignoring "fingerprint" on the HTTP/2 carrier, `+
			"since the uTLS path cannot carry the client certificate this protocol needs")
	}

	raw, err := internet.DialSystem(ctx, h.endpoint, h.streamSettings.SocketSettings)
	if err != nil {
		return nil, errors.New("masque: failed to reach ", h.endpoint).Base(err)
	}

	conn := net.Conn(raw)
	if h.streamSettings.TcpmaskManager != nil {
		masked, err := h.streamSettings.TcpmaskManager.WrapConnClient(conn)
		if err != nil {
			conn.Close()
			return nil, errors.New("masque: failed to apply the tcp masks").Base(err)
		}
		conn = masked
	}

	tlsConn := gotls.Client(conn, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, errors.New("masque: the TLS handshake with ", h.endpoint, " failed").Base(err)
	}
	return tlsConn, nil
}

// dialH2 brings up the tunnel over HTTP/2.
func (h *Handler) dialH2(ctx context.Context) (*h2Tunnel, error) {
	conn, err := h.dialTLSConn(ctx)
	if err != nil {
		return nil, err
	}

	// The body is the uplink: everything written into this pipe leaves as DATA
	// frames on the request stream.
	body, capsules := io.Pipe()
	request, err := newH2ConnectRequest(h.conf.Authority, h.conf.Path, h.conf.ConnectProtocol, body)
	if err != nil {
		conn.Close()
		return nil, err
	}

	// Go's HTTP/2 client already opens wide flow-control windows of its own, so
	// unlike some clients this one does not need them raised to avoid a ceiling
	// of one window per round trip.
	transport := &http2.Transport{
		DialTLSContext: func(context.Context, string, string, *gotls.Config) (net.Conn, error) {
			return conn, nil
		},
		ReadIdleTimeout: net.ChromeH2KeepAlivePeriod,
	}

	response, err := transport.RoundTrip(request.WithContext(ctx))
	if err != nil {
		capsules.Close()
		conn.Close()
		return nil, errors.New("masque: the CONNECT over HTTP/2 failed").Base(err)
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		response.Body.Close()
		capsules.Close()
		conn.Close()
		return nil, errors.New("masque: the edge refused the tunnel with ", response.Status)
	}

	errors.LogInfo(ctx, "masque: tunnel open to ", h.endpoint, " over HTTP/2 as ", h.conf.ConnectProtocol, ", ", response.Status)
	return &h2Tunnel{conn: conn, request: capsules, response: response.Body}, nil
}

// sendPacket frames one packet as a DATAGRAM capsule and puts it on the stream.
//
// Every capsule is written on its own, which costs a DATA frame, a TLS record
// and its share of a TCP segment. Gathering packets that are already queued
// into one write would cut that, and is the obvious thing to measure first if
// this carrier turns out to be slower than the link underneath it.
func (t *h2Tunnel) sendPacket(packet []byte) error {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()

	t.frame = appendDatagramCapsule(t.frame[:0], packet)
	_, err := t.request.Write(t.frame)
	return err
}

// receivePacket is never called: packets arrive as capsules on the stream, and
// the tunnel only starts its datagram loop for a carrier that has datagrams.
func (t *h2Tunnel) receivePacket(context.Context) ([]byte, error) {
	return nil, errors.New("masque: the HTTP/2 carrier has no datagrams")
}

func (t *h2Tunnel) hasDatagrams() bool { return false }

func (t *h2Tunnel) stream() io.Reader { return t.response }

func (t *h2Tunnel) Close() error {
	// The request pipe first, so the edge sees the stream end rather than the
	// connection vanishing under it.
	if t.request != nil {
		t.request.Close()
	}
	if t.response != nil {
		t.response.Close()
	}
	if t.conn != nil {
		t.conn.Close()
	}
	return nil
}
