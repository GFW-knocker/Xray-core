package masque

import (
	"context"
	gotls "crypto/tls"
	"io"
	"net/http"
	"net/url"
	"sync"

	"github.com/GFW-knocker/Xray-core/common/errors"
	"github.com/GFW-knocker/Xray-core/common/net"
	"github.com/GFW-knocker/Xray-core/transport/internet"
	xtls "github.com/GFW-knocker/Xray-core/transport/internet/tls"
	"golang.org/x/net/http2"
)

// connectProtocolHeader carries on HTTP/2 what :protocol carries on HTTP/3.
//
// The two carriers really do differ, and not in a way that can be guessed from
// the RFCs. HTTP/3 gets an extended CONNECT (RFC 9220) with :protocol. HTTP/2
// gets an *ordinary* CONNECT -- no :protocol, no :path, no :scheme -- with the
// protocol named in this plain header instead.
//
// That is what the reference client sends (aether v2.0.0, masque_h2.rs), and it
// explains something that looks like a Cloudflare bug from the outside: the
// edge never advertises SETTINGS_ENABLE_CONNECT_PROTOCOL because on this
// carrier it does not use extended CONNECT at all. Sending one gets a 400.
const connectProtocolHeader = "cf-connect-proto"

// h2Tunnel is one MASQUE tunnel riding HTTP/2.
//
// There are no datagrams here, so every packet travels as a DATAGRAM capsule on
// the request stream alongside the control capsules. That is TCP underneath, so
// a lost packet holds up everything behind it; this carrier is for paths where
// UDP does not survive, not a peer of the HTTP/3 one.
type h2Tunnel struct {
	conn   net.Conn
	client *http2.ClientConn

	// The request body is the uplink and the response body is the downlink,
	// which is what an ordinary CONNECT gives instead of a single duplex stream.
	send    *io.PipeWriter
	receive io.ReadCloser

	// cancel ends the request, and with it the tunnel. See dialH2 for why the
	// request does not simply carry the context it was dialled from.
	cancel context.CancelFunc

	// Capsules are written from the uplink goroutine, but Close can come from
	// any of them.
	writeMu sync.Mutex
	frame   []byte
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

// connectAuthority is the :authority of an ordinary CONNECT, which names a host
// *and a port* rather than a host alone.
//
// The reference client sends "cloudflareaccess.com:443". A configuration that
// already names a port keeps the one it named.
func connectAuthority(authority string) string {
	if _, _, err := net.SplitHostPort(authority); err == nil {
		return authority
	}
	return net.JoinHostPort(authority, "443")
}

// newH2ConnectRequest builds the CONNECT that opens the tunnel.
//
// Leaving :protocol out is what keeps this an ordinary CONNECT, and it is load
// bearing twice over: it is what the edge wants, and it is also what lets this
// go through the stock transport at all. x/net/http2 refuses to send an
// extended CONNECT until the server has advertised
// SETTINGS_ENABLE_CONNECT_PROTOCOL, which this edge never does; an ordinary
// CONNECT has no such gate.
//
// "path" is unused here. There is nowhere in an ordinary CONNECT to put it.
func newH2ConnectRequest(ctx context.Context, authority, protocol string, body io.ReadCloser) *http.Request {
	target := connectAuthority(authority)
	request := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: target},
		Host:   target,
		Header: http.Header{},
		Body:   body,
		// The tunnel runs until it is closed, so the uplink has no length. This
		// is also what tells the transport there is a body to write at all.
		ContentLength: -1,
	}
	request.Header.Set(connectProtocolHeader, protocol)
	// Both of these are what the reference client sends. An empty User-Agent is
	// how the transport is told to leave the header out rather than fill in its
	// own.
	request.Header.Set("pq-enabled", "false")
	request.Header["User-Agent"] = []string{""}
	return request.WithContext(ctx)
}

// dialH2 brings up the tunnel over HTTP/2.
func (h *Handler) dialH2(ctx context.Context) (*h2Tunnel, error) {
	if h.conf.Authority == "" {
		return nil, errors.New(`masque: "authority" is required to open a tunnel`)
	}
	if h.conf.ConnectProtocol == "" {
		return nil, errors.New(`masque: "connectProtocol" is required to open a tunnel`)
	}

	conn, err := h.dialTLSConn(ctx)
	if err != nil {
		return nil, err
	}

	// The tunnel outlives the context it was dialled from: that one belongs to
	// whichever proxied connection happened to find the outbound down, and it
	// ends when that connection does. Binding the request to it would take the
	// tunnel with it, so the request gets a context of its own and Close ends it.
	requestCtx, cancel := context.WithCancel(context.Background())
	tunnel := &h2Tunnel{conn: conn, cancel: cancel}

	// DisableCompression only to keep "accept-encoding: gzip" off a request that
	// is not fetching anything. Nothing here would decompress.
	tunnel.client, err = (&http2.Transport{DisableCompression: true}).NewClientConn(conn)
	if err != nil {
		tunnel.Close()
		return nil, errors.New("masque: failed to start HTTP/2 with ", h.endpoint).Base(err)
	}

	body, send := io.Pipe()
	tunnel.send = send
	request := newH2ConnectRequest(requestCtx, h.conf.Authority, h.conf.ConnectProtocol, body)

	response, err := roundTrip(ctx, tunnel.client, request)
	if err != nil {
		tunnel.Close()
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		response.Body.Close()
		tunnel.Close()
		return nil, errors.New("masque: the edge refused the tunnel with ", response.Status)
	}
	tunnel.receive = response.Body

	errors.LogInfo(ctx, "masque: tunnel open to ", h.endpoint, " over HTTP/2 as ",
		h.conf.ConnectProtocol, ", ", response.Status)
	return tunnel, nil
}

// roundTrip sends the CONNECT and waits for the answer, giving up when ctx does.
//
// The wait is bounded from out here rather than by the request's own context,
// because that one is the tunnel's and has to outlast this call.
func roundTrip(ctx context.Context, client *http2.ClientConn, request *http.Request) (*http.Response, error) {
	type result struct {
		response *http.Response
		err      error
	}
	// Buffered, so the goroutine is not stranded on the timeout path. The
	// caller closes the tunnel there, which is what releases RoundTrip.
	out := make(chan result, 1)
	go func() {
		response, err := client.RoundTrip(request)
		out <- result{response, err}
	}()

	select {
	case r := <-out:
		if r.err != nil {
			return nil, errors.New("masque: no answer to the CONNECT").Base(r.err)
		}
		return r.response, nil
	case <-ctx.Done():
		return nil, errors.New("masque: no answer to the CONNECT").Base(ctx.Err())
	}
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
	_, err := t.send.Write(t.frame)
	return err
}

// receivePacket is never called: packets arrive as capsules on the stream, and
// the tunnel only starts its datagram loop for a carrier that has datagrams.
func (t *h2Tunnel) receivePacket(context.Context) ([]byte, error) {
	return nil, errors.New("masque: the HTTP/2 carrier has no datagrams")
}

func (t *h2Tunnel) hasDatagrams() bool { return false }

func (t *h2Tunnel) stream() io.Reader { return t.receive }

// Close tears the tunnel down from the top, so the edge sees the request end
// rather than the connection vanish. It is safe to call on a half-built tunnel,
// which is how the dial unwinds.
func (t *h2Tunnel) Close() error {
	if t.cancel != nil {
		t.cancel()
	}
	if t.send != nil {
		t.send.Close()
	}
	if t.receive != nil {
		t.receive.Close()
	}
	if t.client != nil {
		t.client.Close()
	}
	if t.conn != nil {
		t.conn.Close()
	}
	return nil
}
