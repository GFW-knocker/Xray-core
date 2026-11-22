package tcplane

import (
	"github.com/GFW-knocker/Xray-core/common/net"
	"github.com/GFW-knocker/Xray-core/transport/internet/finalmask"
)

// HandleDial and HandleListen: tcplane replaces the UDP socket, so it must be
// the last udp mask in the config (the one nearest the wire).
func (c *Config) HandleDial() {}

func (c *Config) HandleListen() {}

func (c *Config) WrapPacketConnClient(conn net.PacketConn, dest *net.Destination, dialer *finalmask.Dialer) (net.PacketConn, error) {
	return newClientConn(c, dest, dialer)
}

func (c *Config) WrapPacketConnServer(conn net.PacketConn, addr net.Addr, lc *finalmask.ListenConfig) (net.PacketConn, error) {
	return newServerConn(c, addr, lc)
}
