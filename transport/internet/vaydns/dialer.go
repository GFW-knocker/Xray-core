package vaydns

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/GFW-knocker/Xray-core/common"
	"github.com/GFW-knocker/Xray-core/common/errors"
	"github.com/GFW-knocker/Xray-core/common/net"
	"github.com/GFW-knocker/Xray-core/transport/internet"
	"github.com/GFW-knocker/Xray-core/transport/internet/stat"
	vaydns "github.com/net2share/vaydns/client"
)

var globalTunnel *vaydns.Tunnel = nil

// Dial dials a vaydns connection to the given destination.
func Dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	errors.LogInfo(ctx, "creating connection to ", dest)

	conn, err := dialVaydns(ctx, dest, streamSettings)
	if err != nil {
		return nil, errors.New("failed to dial vaydns").Base(err)
	}

	return stat.Connection(conn), nil
}

func dialVaydns(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	if globalTunnel == nil {
		if err := establishTunnel(ctx, dest, streamSettings); err != nil {
			return nil, fmt.Errorf("failed to establish vaydns tunnel: %w", err)
		}
	}

	stream, err := globalTunnel.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("failed to open stream: %w", err)
	}

	return stream, nil
}

func establishTunnel(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) error {
	cfg := streamSettings.ProtocolSettings.(*Config)
	errors.LogInfo(ctx, "creating vaydns tunnel to ", dest)

	// Build resolver. Only UDP is supported for now.
	resolverAddr := fmt.Sprintf("%s:%d", dest.Address.String(), dest.Port.Value())
	r, err := vaydns.NewResolver(vaydns.ResolverTypeUDP, resolverAddr)
	if err != nil {
		return fmt.Errorf("invalid resolver address: %w", err)
	}

	// Apply UDP transport settings.
	if cfg.UdpWorkers > 0 {
		r.UDPWorkers = int(cfg.UdpWorkers)
	}
	if cfg.UdpTimeout != "" {
		if d, err := time.ParseDuration(cfg.UdpTimeout); err == nil {
			r.UDPTimeout = d
		}
	}
	r.UDPSharedSocket = cfg.UdpSharedSocket
	r.UDPAcceptErrors = cfg.UdpAcceptErrors

	// Build tunnel server config.
	ts, err := vaydns.NewTunnelServer(cfg.ServerAddress, cfg.ServerPublicKey)
	if err != nil {
		return fmt.Errorf("invalid tunnel server: %w", err)
	}
	ts.DnsttCompat = cfg.DnsttCompat
	if cfg.ClientidSize > 0 {
		ts.ClientIDSize = int(cfg.ClientidSize)
	}
	if cfg.MaxQnameLen > 0 {
		ts.MaxQnameLen = int(cfg.MaxQnameLen)
	}
	if cfg.MaxNumLabels > 0 {
		ts.MaxNumLabels = int(cfg.MaxNumLabels)
	}
	ts.RPS = cfg.Rps

	// Build tunnel.
	tunnel, err := vaydns.NewTunnel(r, ts)
	if err != nil {
		return fmt.Errorf("failed to create tunnel: %w", err)
	}

	// Apply session settings.
	if cfg.IdleTimeout != "" {
		if d, err := time.ParseDuration(cfg.IdleTimeout); err == nil {
			tunnel.IdleTimeout = d
		}
	}
	if cfg.Keepalive != "" {
		if d, err := time.ParseDuration(cfg.Keepalive); err == nil {
			tunnel.KeepAlive = d
		}
	}
	if cfg.MaxStreams > 0 {
		tunnel.MaxStreams = int(cfg.MaxStreams)
	}

	// Step-by-step tunnel initialization.
	if err := tunnel.InitiateResolverConnection(); err != nil {
		return fmt.Errorf("failed to initiate resolver connection: %w", err)
	}

	if err := tunnel.InitiateDNSPacketConn(ts.Addr); err != nil {
		return fmt.Errorf("failed to initiate DNS packet connection: %w", err)
	}

	log.Printf("vaydns: effective MTU %d", ts.MTU)

	if err := tunnel.InitiateKCPConn(0); err != nil {
		return fmt.Errorf("failed to initiate KCP connection: %w", err)
	}

	log.Printf("vaydns: established KCP conn")

	if err := tunnel.InitiateNoiseChannel(); err != nil {
		return fmt.Errorf("failed to initiate Noise channel: %w", err)
	}

	log.Printf("vaydns: established Noise channel")

	if err := tunnel.InitiateSmuxSession(); err != nil {
		return fmt.Errorf("failed to initiate smux session: %w", err)
	}

	log.Printf("vaydns: established smux session")

	globalTunnel = tunnel
	return nil
}

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
}
