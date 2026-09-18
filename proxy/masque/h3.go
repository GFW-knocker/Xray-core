package masque

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/GFW-knocker/Xray-core/common/errors"
	"github.com/GFW-knocker/Xray-core/common/net"
	"github.com/GFW-knocker/Xray-core/common/net/cnc"
	"github.com/GFW-knocker/Xray-core/features/stats"
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
	request *http3.RequestStream
	conn    *quic.Conn
	quicTr  *quic.Transport
	pktConn net.PacketConn

	// Reused by sendPacket, which only ever runs on the uplink goroutine.
	frame []byte
}

// dialCarrier opens whichever carrier the configuration asks for.
func (h *Handler) dialCarrier(ctx context.Context) (carrier, error) {
	if h.conf.Transport == Config_H2 {
		return h.dialH2(ctx)
	}
	return h.dialH3(ctx)
}

func (t *h3Tunnel) sendPacket(packet []byte) error {
	t.frame = appendH3Datagram(t.frame[:0], packet)
	return t.request.SendDatagram(t.frame)
}

func (t *h3Tunnel) receivePacket(ctx context.Context) ([]byte, error) {
	return t.request.ReceiveDatagram(ctx)
}

func (t *h3Tunnel) hasDatagrams() bool { return true }

func (t *h3Tunnel) stream() io.Reader { return t.request }

func (t *h3Tunnel) setReadDeadline(deadline time.Time) error {
	return t.request.SetReadDeadline(deadline)
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

	// Wrapped after the masks, matching the WireGuard outbound, so the figures
	// are the tunnel's own traffic rather than what the masks pad it out to.
	if h.uplinkCounter != nil || h.downlinkCounter != nil {
		pktConn = &countingPacketConn{
			PacketConn: pktConn,
			read:       h.downlinkCounter,
			write:      h.uplinkCounter,
		}
	}
	return pktConn, remote, nil
}

// countingPacketConn feeds the outbound's traffic counters. It measures the
// carrier, so the figures cover the tunnel itself, headers and keepalives
// included, not just the payload of the connections inside it.
type countingPacketConn struct {
	net.PacketConn
	read  stats.Counter
	write stats.Counter
}

func (c *countingPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	if err == nil && c.read != nil {
		c.read.Add(int64(n))
	}
	return n, addr, err
}

func (c *countingPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	n, err := c.PacketConn.WriteTo(p, addr)
	if err == nil && c.write != nil {
		c.write.Add(int64(n))
	}
	return n, err
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
		// ChromeParrot is deliberately left off, and unlike everything else here
		// it is not offered as a setting.
		//
		// The parrot replaces the ClientHello with a recorded Chrome one so the
		// handshake does not look like Go's. Chrome never authenticates itself to
		// a web server, so the recording has nothing in it for a client
		// certificate and the parrot cannot send one. Every MASQUE tunnel is
		// mutual TLS -- the certificate is the whole of the client's identity to
		// the edge -- so a parroted handshake is one the edge will not finish. It
		// does not fail loudly either: the edge simply stops answering, which is
		// indistinguishable from a blocked path. Measured against
		// 162.159.198.1:443, parrot on gave "handshake did not complete in time"
		// every time and parrot off connected in ~370 ms.
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

// masqueVersions is the order QUIC versions are tried in, and it is the
// opposite of quicdial's own preference on purpose.
//
// quicdial leads with v2 because some networks drop v1 Initials, and on a path
// where that is the only obstacle it is the right call. A MASQUE edge is not
// such a path. Cloudflare's does not implement v2 at all: a v2 Initial is
// answered with a Version Negotiation packet and nothing else, so leading with
// v2 cannot ever succeed here, it only costs a timeout.
//
// It costs more than a timeout, in fact, and that is the real reason for this
// list. The udp masks prime the flow once per destination on the first packet
// written, so the priming that carries the handshake past a v1-dropping filter
// is spent on the v2 attempt that was always going to fail. The v1 attempt that
// follows reuses the same socket, gets no priming, and is dropped. Leading with
// v1 spends the priming on the attempt that can work.
//
// v2 is kept as a fallback for an edge that is the other way around.
var masqueVersions = [][]quic.Version{
	{quic.Version1},
	{quic.Version2},
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

	// Before QUIC writes anything. This goes through the masked connection, so a
	// udpmask configured in streamSettings still wraps it and its own noise, if
	// it has any, still fires on this first write -- the two are additive rather
	// than alternatives.
	h.sendNoise(ctx, pktConn, remote)

	config, params := h.quicConfig()
	quicTr := &quic.Transport{Conn: pktConn, DisableGSO: params.DisableGSO}

	conn, err := quicdial.Dial(ctx, config, masqueVersions, &h.quicVersion, func(cfg *quic.Config) (*quic.Conn, error) {
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
	tunnel.request = stream

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
	if t.request != nil {
		t.request.Close()
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
