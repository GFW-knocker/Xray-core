package masque

import (
	"context"
	"crypto/ecdsa"
	gonet "net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/GFW-knocker/Xray-core/common"
	"github.com/GFW-knocker/Xray-core/common/buf"
	"github.com/GFW-knocker/Xray-core/common/dice"
	"github.com/GFW-knocker/Xray-core/common/errors"
	"github.com/GFW-knocker/Xray-core/common/net"
	"github.com/GFW-knocker/Xray-core/common/session"
	"github.com/GFW-knocker/Xray-core/common/signal"
	"github.com/GFW-knocker/Xray-core/common/task"
	"github.com/GFW-knocker/Xray-core/core"
	"github.com/GFW-knocker/Xray-core/features/dns"
	"github.com/GFW-knocker/Xray-core/features/policy"
	"github.com/GFW-knocker/Xray-core/features/stats"
	"github.com/GFW-knocker/Xray-core/transport"
	"github.com/GFW-knocker/Xray-core/transport/internet"
)

// Handler is the MASQUE outbound. It holds what the configuration settled at
// startup; the tunnel itself is brought up lazily, once there is traffic for it.
type Handler struct {
	conf           *Config
	policyManager  policy.Manager
	dns            dns.Client
	streamSettings *internet.MemoryStreamConfig

	uplinkCounter   stats.Counter
	downlinkCounter stats.Counter

	// Settled from conf at construction, so a bad configuration fails at startup
	// rather than on the first connection.
	endpoint   net.Destination
	privateKey *ecdsa.PrivateKey
	addresses  []netip.Addr
	dnsServers []netip.Addr
	mtu        int

	// Which quicdial attempt last connected to this edge, so the version
	// fallback is paid for once rather than on every dial.
	quicVersion atomic.Int32

	// The tunnel is shared by every connection and brought up on the first one.
	// quicConfig runs on every dial and from two callers, so the one warning it
	// can emit is a configuration mistake worth saying once, not once per dial.
	warnKeepAliveOnce sync.Once

	// dialMu serialises dials, so two connections arriving together do not each
	// open a tunnel. Close deliberately never takes it: a dial can block for a
	// very long time, and shutting down must not wait for one.
	dialMu sync.Mutex

	// done is closed by Close, and every dial derives its context from it, so a
	// dial still waiting on an address that will never answer is abandoned
	// rather than waited out. Created lazily because Handler is also built
	// directly in tests.
	done chan struct{}

	mu      sync.Mutex
	tunnel  *tunnel
	closed  bool
	cache   map[string]resolved
	cacheMu sync.Mutex
}

// resolved is one cached name lookup, held until its TTL runs out.
type resolved struct {
	got     []net.IP
	expires time.Time
}

func NewClient(ctx context.Context, conf *Config) (*Handler, error) {
	v := core.MustFromContext(ctx)
	p := v.GetFeature(policy.ManagerType()).(policy.Manager)
	d := v.GetFeature(dns.ClientType()).(dns.Client)

	// An outbound is always dispatched with stream settings, but asserting
	// blindly turns a missing one into a panic that takes the process down. An
	// empty one stands in so nothing downstream has to keep checking.
	streamSettings, _ := session.StreamSettingsFromContext(ctx).(*internet.MemoryStreamConfig)
	if streamSettings == nil {
		streamSettings = &internet.MemoryStreamConfig{}
	}

	h := &Handler{
		conf:           conf,
		policyManager:  p,
		dns:            d,
		streamSettings: streamSettings,
		cache:          make(map[string]resolved),
	}

	var err error
	if h.endpoint, err = parseEndpoint(conf.Endpoint, conf.Transport); err != nil {
		return nil, err
	}
	if h.privateKey, err = ParsePrivateKey(conf.PrivateKey); err != nil {
		return nil, err
	}
	if h.addresses, err = parseAddresses(conf.Address); err != nil {
		return nil, err
	}
	if h.dnsServers, err = parseDNSServers(conf.DNS); err != nil {
		return nil, err
	}
	h.mtu = int(conf.Mtu)

	tag := session.FullHandlerFromContext(ctx).Tag()
	if len(tag) > 0 && p.ForSystem().Stats.OutboundUplink {
		statsManager := v.GetFeature(stats.ManagerType()).(stats.Manager)
		if c, _ := statsManager.GetOrRegisterCounter("outbound>>>" + tag + ">>>traffic>>>uplink"); c != nil {
			h.uplinkCounter = c
		}
	}
	if len(tag) > 0 && p.ForSystem().Stats.OutboundDownlink {
		statsManager := v.GetFeature(stats.ManagerType()).(stats.Manager)
		if c, _ := statsManager.GetOrRegisterCounter("outbound>>>" + tag + ">>>traffic>>>downlink"); c != nil {
			h.downlinkCounter = c
		}
	}

	return h, nil
}

// parseEndpoint reads the edge address. The network follows the transport,
// because it decides what the dialer has to hand back: a packet conn for QUIC,
// a stream for HTTP/2.
func parseEndpoint(endpoint string, transport Config_Transport) (net.Destination, error) {
	if endpoint == "" {
		return net.Destination{}, errors.New(`"endpoint" is required`)
	}
	host, portText, err := net.SplitHostPort(endpoint)
	if err != nil {
		return net.Destination{}, errors.New(`"endpoint" `, endpoint, ` is not host:port`).Base(err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return net.Destination{}, errors.New(`"endpoint" `, endpoint, " has no usable port")
	}

	network := net.Network_UDP
	if transport == Config_H2 {
		network = net.Network_TCP
	}
	return net.Destination{
		Address: net.ParseAddress(host),
		Port:    net.Port(port),
		Network: network,
	}, nil
}

// parseAddresses reads the local tunnel addresses, accepting either a bare
// address or a prefix, since the registration API reports them both ways.
func parseAddresses(addresses []string) ([]netip.Addr, error) {
	parsed := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		if prefix, err := netip.ParsePrefix(address); err == nil {
			parsed = append(parsed, prefix.Addr())
			continue
		}
		addr, err := netip.ParseAddr(address)
		if err != nil {
			return nil, errors.New(`"address" entry `, address, " is neither an address nor a prefix")
		}
		parsed = append(parsed, addr)
	}
	return parsed, nil
}

func parseDNSServers(servers []string) ([]netip.Addr, error) {
	parsed := make([]netip.Addr, 0, len(servers))
	for _, server := range servers {
		addr, err := netip.ParseAddr(server)
		if err != nil {
			return nil, errors.New(`"remoteDNS" entry `, server, " is not an IP address")
		}
		parsed = append(parsed, addr)
	}
	return parsed, nil
}

// session returns the tunnel, bringing it up on the first connection and again
// whenever the previous one has died. The lock is held across the dial on
// purpose: a hundred connections arriving at once should cost one tunnel, not a
// hundred attempts at the edge.
func (h *Handler) session(ctx context.Context) (*tunnel, error) {
	if t, err := h.liveTunnel(ctx); t != nil || err != nil {
		return t, err
	}

	// The dial happens without h.mu held. Holding it here is what used to make
	// Ctrl+C hang: Close wants the same mutex, and a dial through another tunnel
	// to an address that never answers has nothing to refuse it, so the process
	// stayed up for as long as the dial did.
	h.dialMu.Lock()
	defer h.dialMu.Unlock()

	// Someone else may have brought one up while this connection waited its turn.
	if t, err := h.liveTunnel(ctx); t != nil || err != nil {
		return t, err
	}

	dialCtx, cancel := h.dialContext(ctx)
	defer cancel()

	t, err := h.startTunnel(dialCtx)
	if err != nil {
		return nil, err
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		// Closed while this dial was in flight, so nothing owns the tunnel now.
		t.Close()
		return nil, errors.New("masque: the outbound is closed")
	}
	h.tunnel = t
	return t, nil
}

// liveTunnel returns the tunnel currently in use, if there is one worth using.
// A nil tunnel and a nil error mean one has to be dialled.
func (h *Handler) liveTunnel(ctx context.Context) (*tunnel, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.closed {
		return nil, errors.New("masque: the outbound is closed")
	}
	if h.tunnel != nil {
		if h.tunnel.alive() {
			return h.tunnel, nil
		}
		errors.LogInfo(ctx, "masque: the tunnel is gone, opening another")
		h.tunnel = nil
	}
	return nil, nil
}

// dialContext ties a dial to the outbound's life as well as the caller's, so
// Close abandons it instead of waiting for whatever timeout it would otherwise
// run to.
func (h *Handler) dialContext(ctx context.Context) (context.Context, context.CancelFunc) {
	h.mu.Lock()
	if h.done == nil {
		h.done = make(chan struct{})
	}
	done := h.done
	h.mu.Unlock()

	dialCtx, cancel := context.WithCancel(ctx)
	go func() {
		select {
		case <-done:
			cancel()
		case <-dialCtx.Done():
		}
	}()
	return dialCtx, cancel
}

// Close implements common.Closable.
func (h *Handler) Close() error {
	h.mu.Lock()
	if h.done == nil {
		h.done = make(chan struct{})
	}
	if !h.closed {
		h.closed = true
		// Every dial in flight is watching this, and gives up as soon as it
		// closes. Guarded by h.closed so a second Close cannot close it twice.
		close(h.done)
	}
	tunnel := h.tunnel
	h.tunnel = nil
	h.mu.Unlock()

	// Outside the lock: tearing a tunnel down talks to the network, and nothing
	// else should be waiting on h.mu while it does.
	if tunnel != nil {
		tunnel.Close()
	}
	return nil
}

// resolveRemote turns a name into an address. With resolvers configured the
// lookup goes through the tunnel, which is the point of "remoteDNS"; without
// them it falls back to Xray's own DNS, which resolves outside the tunnel.
func (h *Handler) resolveRemote(host string) (net.IP, error) {
	lookup := func(host string) ([]net.IP, uint32, error) {
		return h.dns.LookupIP(host, dns.IPOption{IPv4Enable: true, IPv6Enable: true})
	}
	if len(h.dnsServers) > 0 {
		h.mu.Lock()
		t := h.tunnel
		h.mu.Unlock()
		if t != nil {
			lookup = t.tnet.LookupHost
		}
	}
	return h.resolveDomain(host, h.conf.DomainStrategy, lookup)
}

func (h *Handler) resolveDomain(host string, strategy Config_DomainStrategy, lookupIP func(string) ([]net.IP, uint32, error)) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return ip, nil
	}

	h.cacheMu.Lock()
	if entry, ok := h.cache[host]; ok {
		if time.Now().Before(entry.expires) {
			h.cacheMu.Unlock()
			return entry.got[dice.Roll(len(entry.got))], nil
		}
		delete(h.cache, host)
	}
	h.cacheMu.Unlock()

	ips, ttl, err := lookupIP(host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, dns.ErrEmptyResponse
	}

	var got4, got6 []net.IP
	for _, ip := range ips {
		if ip.To4() != nil {
			got4 = append(got4, ip)
		} else {
			got6 = append(got6, ip)
		}
	}

	var got []net.IP
	switch strategy {
	case Config_FORCE_IP:
		got = ips
	case Config_FORCE_IP4:
		got = got4
	case Config_FORCE_IP6:
		got = got6
	case Config_FORCE_IP46:
		got = got4
		if len(got) == 0 {
			got = got6
		}
	case Config_FORCE_IP64:
		got = got6
		if len(got) == 0 {
			got = got4
		}
	default:
		return nil, errors.New("masque: unknown domain strategy ", strategy)
	}
	if len(got) == 0 {
		return nil, dns.ErrEmptyResponse
	}

	h.cacheMu.Lock()
	h.cache[host] = resolved{got: got, expires: time.Now().Add(time.Duration(ttl) * time.Second)}
	h.cacheMu.Unlock()
	return got[dice.Roll(len(got))], nil
}

// Process implements proxy.Outbound.Process.
func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("target not specified")
	}
	ob.Name = "masque"
	ob.CanSpliceCopy = 3
	dialer.SetOutboundGateway(ctx, ob)

	tunnel, err := h.session(ctx)
	if err != nil {
		return err
	}

	var addr netip.Addr
	if ob.Target.Address.Family().IsDomain() {
		ip, err := h.resolveRemote(ob.Target.Address.String())
		if err != nil {
			return errors.New("masque: failed to resolve ", ob.Target.Address).Base(err)
		}
		addr, _ = netip.AddrFromSlice(ip)
	} else {
		addr, _ = netip.AddrFromSlice(ob.Target.Address.IP())
	}
	addr = addr.Unmap()

	addrPort := netip.AddrPortFrom(addr, ob.Target.Port.Value())
	if !addrPort.IsValid() {
		return errors.New("masque: invalid target ", ob.Target)
	}

	var newCtx context.Context
	var newCancel context.CancelFunc
	if session.TimeoutOnlyFromContext(ctx) {
		newCtx, newCancel = context.WithCancel(context.Background())
	}

	sessionPolicy := h.policyManager.ForLevel(0)
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, func() {
		cancel()
		if newCancel != nil {
			newCancel()
		}
	}, sessionPolicy.Timeouts.ConnectionIdle)
	if newCtx != nil {
		ctx = newCtx
	}

	var reader buf.Reader
	var writer buf.Writer

	switch ob.Target.Network {
	case net.Network_TCP:
		var conn net.Conn
		var err error
		if sessionPolicy.Timeouts.Handshake != 0 {
			handshakeCtx, handshakeCancel := context.WithTimeout(ctx, sessionPolicy.Timeouts.Handshake)
			conn, err = tunnel.tnet.DialContextTCPAddrPort(handshakeCtx, addrPort)
			handshakeCancel()
		} else {
			conn, err = tunnel.tnet.DialContextTCPAddrPort(ctx, addrPort)
		}
		if err != nil {
			return errors.New("masque: failed to open TCP to ", addrPort).Base(err)
		}
		defer conn.Close()
		reader = buf.NewReader(conn)
		writer = buf.NewWriter(conn)

	case net.Network_UDP:
		conn, err := tunnel.tnet.DialUDPAddrPort(netip.AddrPort{}, addrPort)
		if err != nil {
			return errors.New("masque: failed to open UDP to ", addrPort).Base(err)
		}
		defer conn.Close()
		packets := &udpConn{
			PacketConn: conn.(*internet.PacketConnWrapper).PacketConn,
			resolve:    h.resolveRemote,
			dest:       gonet.UDPAddrFromAddrPort(addrPort),
		}
		reader = packets
		writer = packets

	default:
		return errors.New("masque: cannot carry ", ob.Target.Network)
	}

	request := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)
		return buf.Copy(link.Reader, writer, buf.UpdateActivity(timer))
	}
	response := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)
		return buf.Copy(reader, link.Writer, buf.UpdateActivity(timer))
	}

	if err := task.Run(ctx, request, task.OnSuccess(response, task.Close(link.Writer))); err != nil {
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
		return errors.New("masque: connection ends").Base(err)
	}
	return nil
}

// udpConn adapts a netstack UDP socket to Xray's buffer interfaces, keeping the
// per-packet destination that a UDP session carries.
type udpConn struct {
	net.PacketConn
	resolve func(host string) (net.IP, error)
	dest    *gonet.UDPAddr
}

func (c *udpConn) ReadMultiBuffer() (buf.MultiBuffer, error) {
	b := buf.New()
	b.Resize(0, buf.Size)
	n, addr, err := c.PacketConn.ReadFrom(b.Bytes())
	if err != nil {
		b.Release()
		return nil, err
	}
	b.Resize(0, int32(n))

	from := addr.(*gonet.UDPAddr)
	b.UDP = &net.Destination{
		Address: net.IPAddress(from.IP),
		Port:    net.Port(from.Port),
		Network: net.Network_UDP,
	}
	return buf.MultiBuffer{b}, nil
}

func (c *udpConn) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for i, b := range mb {
		dest := c.dest
		if b.UDP != nil {
			if b.UDP.Address.Family().IsDomain() {
				ip, err := c.resolve(b.UDP.Address.String())
				if err != nil {
					errors.LogErrorInner(context.Background(), err,
						"masque: dropped a ", b.Len(), " byte packet to ", b.UDP)
					b.Release()
					continue
				}
				dest = &gonet.UDPAddr{IP: ip, Port: int(b.UDP.Port)}
			} else {
				dest = b.UDP.RawNetAddr().(*gonet.UDPAddr)
			}
		}
		if _, err := c.PacketConn.WriteTo(b.Bytes(), dest); err != nil {
			buf.ReleaseMulti(mb[i:])
			return err
		}
		b.Release()
	}
	return nil
}
