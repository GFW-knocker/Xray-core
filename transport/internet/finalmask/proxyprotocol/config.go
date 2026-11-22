package proxyprotocol

import (
	"github.com/GFW-knocker/Xray-core/common/errors"
	"github.com/GFW-knocker/Xray-core/common/net"
	"github.com/GFW-knocker/Xray-core/transport/internet/finalmask"
	"github.com/pires/go-proxyproto"
)

func (c *Config) WrapConnClient(conn net.Conn, dest *net.Destination, dialer *finalmask.Dialer) (net.Conn, error) {
	version := c.Version
	if version == 0 {
		version = 2
	}
	if version != 1 && version != 2 {
		return nil, errors.New("PROXY protocol version must be 1 or 2")
	}
	source := conn.LocalAddr()
	if dialer != nil && dialer.Source != nil {
		source = dialer.Source
	}
	header := proxyproto.HeaderProxyFromAddrs(byte(version), source, conn.RemoteAddr())
	if _, err := header.WriteTo(conn); err != nil {
		return nil, errors.New("failed to write PROXY protocol header").Base(err)
	}
	return conn, nil
}

func (c *Config) WrapConnServer(conn net.Conn) (net.Conn, error) {
	return proxyproto.NewConn(conn, proxyproto.WithPolicy(proxyproto.REQUIRE)), nil
}
