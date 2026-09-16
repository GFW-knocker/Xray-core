package masque

import (
	"context"
	"crypto/ecdsa"
	"net/netip"
	"strconv"
	"sync/atomic"

	"github.com/GFW-knocker/Xray-core/common/errors"
	"github.com/GFW-knocker/Xray-core/common/net"
	"github.com/GFW-knocker/Xray-core/common/session"
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

	return errors.New("masque: the tunnel is not implemented yet")
}
