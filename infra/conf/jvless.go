package conf

import (
	"github.com/GFW-knocker/Xray-core/proxy/jvless/outbound"
	vlessoutbound "github.com/GFW-knocker/Xray-core/proxy/vless/outbound"
	"google.golang.org/protobuf/proto"
)

// JVLessOutboundConfig reads the vless outbound settings. The handler turns down
// flow, encryption and reverse.
type JVLessOutboundConfig struct {
	VLessOutboundConfig
}

// Build reuses the vless builder. The jvless config type is what makes core pick our handler.
func (c *JVLessOutboundConfig) Build() (proto.Message, error) {
	m, err := c.VLessOutboundConfig.Build()
	if err != nil {
		return nil, err
	}
	return &outbound.Config{Vnext: m.(*vlessoutbound.Config).Vnext}, nil
}
