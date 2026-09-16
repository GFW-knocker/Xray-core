package masque

import (
	"context"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/GFW-knocker/Xray-core/common/errors"
	"github.com/GFW-knocker/Xray-core/common/net"
	"github.com/GFW-knocker/Xray-core/common/net/cnc"
	"github.com/GFW-knocker/Xray-core/transport/internet"
	"github.com/GFW-knocker/Xray-core/transport/internet/hysteria/congestion"
	"github.com/GFW-knocker/Xray-core/transport/internet/hysteria/congestion/bbr"
	"github.com/GFW-knocker/Xray-core/transport/internet/quicdial"
	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
)

// h3Tunnel is one MASQUE tunnel riding HTTP/3. Packets travel as QUIC datagrams
// and the control capsules travel on the request stream, both of which the one
// RequestStream gives access to.
type h3Tunnel struct {
	stream  *http3.RequestStream
	conn    *quic.Conn
	quicTr  *quic.Transport
	pktConn net.PacketConn
}

// newConnectRequest builds the extended CONNECT (RFC 9220) that opens the
// tunnel. quic-go turns Proto into the :protocol pseudo-header, which is what
// makes this an extended CONNECT rather than an ordinary one.
func newConnectRequest(authority, path, protocol string) (*http.Request, error) {
	if authority == "" {
		return nil, errors.New(`masque: "authority" is required to open a tunnel`)
	}
	if protocol == "" {
		return nil, errors.New(`masque: "connectProtocol" is required to open a tunnel`)
	}
	if path == "" {
		path = DefaultPath
	}
	if !strings.HasPrefix(path, "/") {
		return nil, errors.New(`masque: "path" `, path, " has to start with /")
	}

	request := &http.Request{
		Method: http.MethodConnect,
		Proto:  protocol,
		URL:    &url.URL{Scheme: "https", Host: authority, Path: path},
		Host:   authority,
		Header: http.Header{},
	}
	// RFC 9297: a client that is going to send capsules says so up front.
	request.Header.Set(http3.CapsuleProtocolHeader, "?1")
	// The client this mimics sends no user agent. An empty value is how quic-go
	// is told to leave the header out rather than fill in its own.
	request.Header["User-Agent"] = []string{""}
	return request, nil
}

// dialPacketConn opens the socket the tunnel rides on, through Xray's own
// dialer so that sockopt, dialerProxy chaining and the udpmasks all apply.
func (h *Handler) dialPacketConn(ctx context.Context) (net.PacketConn, *net.UDPAddr, error) {
	raw, err := internet.DialSystem(ctx, h.endpoint, h.streamSettings.SocketSettings)
	if err != nil {
		return nil, nil, errors.New("masque: failed to reach ", h.endpoint).Base(err)
	}

	var pktConn net.PacketConn
	var remote *net.UDPAddr
	switch c := raw.(type) {
	case *internet.PacketConnWrapper:
		pktConn = c.PacketConn
		remote = raw.RemoteAddr().(*net.UDPAddr)
	case *cnc.Connection:
		// A chained dialer hands back a stream; QUIC rides it as a single flow.
		pktConn = &internet.FakePacketConn{Conn: c}
		addr := c.RemoteAddr().(*net.TCPAddr)
		remote = &net.UDPAddr{IP: addr.IP, Port: addr.Port}
	default:
		raw.Close()
		return nil, nil, errors.New("masque: the dialer returned a ", reflect.TypeOf(c), ", which cannot carry QUIC")
	}

	if h.streamSettings.UdpmaskManager != nil {
		masked, err := h.streamSettings.UdpmaskManager.WrapPacketConnClient(pktConn)
		if err != nil {
			pktConn.Close()
			return nil, nil, errors.New("masque: failed to apply the udp masks").Base(err)
		}
		pktConn = masked
	}
	return pktConn, remote, nil
}

func (h *Handler) quicConfig() (*quic.Config, *internet.QuicParams) {
	params := h.streamSettings.QuicParams
	if params == nil {
		params = &internet.QuicParams{BbrProfile: string(bbr.ProfileStandard)}
	}

	config := &quic.Config{
		// Not optional: the packets are the datagrams.
		EnableDatagrams:                true,
		InitialStreamReceiveWindow:     params.InitStreamReceiveWindow,
		MaxStreamReceiveWindow:         params.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: params.InitConnReceiveWindow,
		MaxConnectionReceiveWindow:     params.MaxConnReceiveWindow,
		MaxIdleTimeout:                 time.Duration(params.MaxIdleTimeout) * time.Second,
		KeepAlivePeriod:                time.Duration(params.KeepAlivePeriod) * time.Second,
		DisablePathMTUDiscovery:        params.DisablePathMtuDiscovery,
		ChromeParrot:                   !params.DisableChromeParrot,
	}
	if config.MaxIdleTimeout == 0 {
		config.MaxIdleTimeout = net.ConnIdleTimeout
	}
	if config.KeepAlivePeriod == 0 {
		// The tunnel is idle whenever nothing is being proxied, and an edge that
		// forgets it costs a full redial.
		config.KeepAlivePeriod = net.QuicgoH3KeepAlivePeriod
	}
	return config, params
}

// dialH3 brings up the tunnel: a QUIC connection to the edge, an HTTP/3
// connection on top of it, and one extended CONNECT that turns the request
// stream into an IP tunnel.
func (h *Handler) dialH3(ctx context.Context) (*h3Tunnel, error) {
	request, err := newConnectRequest(h.conf.Authority, h.conf.Path, h.conf.ConnectProtocol)
	if err != nil {
		return nil, err
	}
	tlsConfig, err := h.buildTLSConfig()
	if err != nil {
		return nil, err
	}

	pktConn, remote, err := h.dialPacketConn(ctx)
	if err != nil {
		return nil, err
	}

	config, params := h.quicConfig()
	quicTr := &quic.Transport{Conn: pktConn, DisableGSO: params.DisableGSO}
	if !params.DisableChromeParrot {
		quicTr.ConnectionIDGenerator = quic.ZeroLengthConnectionIDGenerator{}
		tlsConfig.GetCertificate = nil
	}

	// Prefer QUIC v2. Some networks drop v1 Initials outright, which looks
	// exactly like an unreachable edge; quicdial remembers what worked.
	conn, err := quicdial.Dial(ctx, config, quicdial.Plain, &h.quicVersion, func(cfg *quic.Config) (*quic.Conn, error) {
		return quicTr.DialEarly(ctx, remote, tlsConfig, cfg)
	})
	if err != nil {
		quicTr.Close()
		pktConn.Close()
		return nil, errors.New("masque: failed to open QUIC to ", h.endpoint).Base(err)
	}

	tunnel := &h3Tunnel{conn: conn, quicTr: quicTr, pktConn: pktConn}

	switch params.Congestion {
	case "reno":
	case "", "bbr":
		congestion.UseBBR(conn, bbr.Profile(params.BbrProfile))
	case "force-brutal":
		congestion.UseBrutal(conn, params.BrutalUp, params.BrutalDisableLossCompensation)
	default:
		tunnel.Close()
		return nil, errors.New("masque: unknown congestion control ", params.Congestion)
	}

	// NewClientConn rather than RoundTrip: the high-level path refuses an
	// extended CONNECT unless the server advertised SETTINGS_ENABLE_CONNECT_
	// PROTOCOL, and this edge is not a standards-following HTTP/3 server.
	client := (&http3.Transport{EnableDatagrams: true}).NewClientConn(conn)

	stream, err := client.OpenRequestStream(ctx)
	if err != nil {
		tunnel.Close()
		return nil, errors.New("masque: failed to open the request stream").Base(err)
	}
	tunnel.stream = stream

	if err := stream.SendRequestHeader(request); err != nil {
		tunnel.Close()
		return nil, errors.New("masque: failed to send the CONNECT").Base(err)
	}
	response, err := stream.ReadResponse()
	if err != nil {
		tunnel.Close()
		return nil, errors.New("masque: no answer to the CONNECT").Base(err)
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		tunnel.Close()
		return nil, errors.New("masque: the edge refused the tunnel with ", response.Status)
	}

	errors.LogInfo(ctx, "masque: tunnel open to ", h.endpoint, " as ", h.conf.ConnectProtocol, ", ", response.Status)
	return tunnel, nil
}

// Close tears the tunnel down from the top so the edge sees the stream end
// before the connection disappears.
func (t *h3Tunnel) Close() error {
	if t.stream != nil {
		t.stream.Close()
	}
	if t.conn != nil {
		t.conn.CloseWithError(0, "")
	}
	if t.quicTr != nil {
		t.quicTr.Close()
	}
	if t.pktConn != nil {
		t.pktConn.Close()
	}
	return nil
}
