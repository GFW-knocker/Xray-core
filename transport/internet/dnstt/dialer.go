package dnstt

import (
	"context"
	_ "embed"
	"fmt"
	"log"

	"github.com/GFW-knocker/Xray-core/common"
	"github.com/GFW-knocker/Xray-core/common/errors"
	"github.com/GFW-knocker/Xray-core/common/net"
	"github.com/GFW-knocker/Xray-core/transport/internet"
	"github.com/GFW-knocker/Xray-core/transport/internet/stat"
	dnstt "github.com/mahsanet/dnstt/client"
)

var globalTunnel *dnstt.Tunnel = nil

// Dial dials a dnstt connection to the given destination.
func Dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	errors.LogInfo(ctx, "creating connection to ", dest)
	var conn net.Conn

	var err error
	if conn, err = dialDnstt(ctx, dest, streamSettings); err != nil {
		return nil, errors.New("failed to dial dnstt").Base(err)
	}

	return stat.Connection(conn), nil
}

func dialDnstt(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	if globalTunnel == nil {
		if err := establishDnsttTunnel(ctx, dest, streamSettings); err != nil {
			return nil, fmt.Errorf("failed to establish dnstt tunnel: %w", err)
		}
	}

	stream, err := globalTunnel.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("failed to open stream: %w", err)
	}

	return stream, nil
}

func establishDnsttTunnel(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) error {
	dnsttConfig := streamSettings.ProtocolSettings.(*Config)
	errors.LogInfo(ctx, "creating dnstt connection to ", dest)

	r, err := dnstt.NewResolver(dnstt.ResolverTypeUDP, fmt.Sprintf("%s:%s", dest.Address.String(), dest.Port.String()))
	if err != nil {
		return fmt.Errorf("invalid -udp address: %w", err)
	}
	resolvers := []dnstt.Resolver{r}

	tServer, err := dnstt.NewTunnelServer(dnsttConfig.ServerAddress, dnsttConfig.ServerPublicKey)
	if err != nil {
		return fmt.Errorf("invalid tunnel server: %w", err)
	}

	tunnelServers := []dnstt.TunnelServer{tServer}

	resolver := resolvers[0]
	tunnelServer := tunnelServers[0]

	tunnel, err := dnstt.NewTunnel(resolver, tunnelServer)
	if err != nil {
		return fmt.Errorf("failed to create tunnel: %w", err)
	}

	if err := tunnel.InitiateResolverConnection(); err != nil {
		return fmt.Errorf("failed to initiate connection to resolver: %w", err)
	}

	if err := tunnel.InitiateDNSPacketConn(tunnelServer.Addr); err != nil {
		return fmt.Errorf("failed to initiate DNS packet connection: %w", err)
	}

	log.Printf("effective MTU %d", tunnelServer.MTU)

	if err := tunnel.InitiateKCPConn(tunnelServer.MTU); err != nil {
		return fmt.Errorf("failed to initiate KCP connection: %w", err)
	}

	log.Printf("established KCP conn")

	if err := tunnel.InitiateNoiseChannel(); err != nil {
		log.Printf("failed to establish Noise channel: %v", err)
		return fmt.Errorf("failed to initiate Noise channel: %w", err)
	}

	log.Printf("established Noise channel")

	if err := tunnel.InitiateSmuxSession(); err != nil {
		return fmt.Errorf("failed to initiate smux session: %w", err)
	}

	globalTunnel = tunnel

	log.Printf("established smux session")

	return nil
}

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
}
