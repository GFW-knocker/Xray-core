package conf

import (
	"github.com/GFW-knocker/Xray-core/proxy/jvless/outbound"
	vlessoutbound "github.com/GFW-knocker/Xray-core/proxy/vless/outbound"
	"google.golang.org/protobuf/proto"
)

// JVLessOutboundConfig takes the same settings as the vless outbound.
type JVLessOutboundConfig struct {
	VLessOutboundConfig
}

// Build implements Buildable
func (c *JVLessOutboundConfig) Build() (proto.Message, error) {
	m, err := c.VLessOutboundConfig.Build()
	if err != nil {
		return nil, err
	}
	return &outbound.Config{Vnext: m.(*vlessoutbound.Config).Vnext}, nil
}
