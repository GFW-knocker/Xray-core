package udphop

import (
	"net"

	"github.com/GFW-knocker/Xray-core/common/errors"
	"github.com/GFW-knocker/Xray-core/transport/internet"
)

func (c *Config) WrapPacketConnClient(raw net.PacketConn, level int, levelCount int) (net.PacketConn, error) {
	_, ok1 := raw.(*internet.FakePacketConn)
	if level != 0 || ok1 {
		return nil, errors.New("udphop requires being at the outermost level")
	}
	return NewUDPHopConn(c, raw)
}

func (c *Config) WrapPacketConnServer(raw net.PacketConn, level int, levelCount int) (net.PacketConn, error) {
	return nil, errors.New("udphop: client only")
}
