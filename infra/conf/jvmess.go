package conf

import (
	"github.com/GFW-knocker/Xray-core/proxy/jvmess/outbound"
	vmessoutbound "github.com/GFW-knocker/Xray-core/proxy/vmess/outbound"
	"google.golang.org/protobuf/proto"
)

// JVMessOutboundConfig takes the same settings as the vmess outbound.
type JVMessOutboundConfig struct {
	VMessOutboundConfig
}

// Build implements Buildable
func (c *JVMessOutboundConfig) Build() (proto.Message, error) {
	m, err := c.VMessOutboundConfig.Build()
	if err != nil {
		return nil, err
	}
	return &outbound.Config{Receiver: m.(*vmessoutbound.Config).Receiver}, nil
}
