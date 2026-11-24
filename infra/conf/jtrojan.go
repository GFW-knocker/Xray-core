package conf

import (
	"github.com/GFW-knocker/Xray-core/common/serial"
	"github.com/GFW-knocker/Xray-core/proxy/jtrojan"
	"github.com/GFW-knocker/Xray-core/proxy/trojan"
	"google.golang.org/protobuf/proto"
)

// JTrojanClientConfig reads the trojan outbound settings.
type JTrojanClientConfig struct {
	TrojanClientConfig
}

// Build reuses the trojan builder and only swaps the account type, so the stock
// trojan client runs with the jtrojan key.
func (c *JTrojanClientConfig) Build() (proto.Message, error) {
	m, err := c.TrojanClientConfig.Build()
	if err != nil {
		return nil, err
	}
	user := m.(*trojan.ClientConfig).Server.User
	user.Account = serial.ToTypedMessage(&jtrojan.Account{Password: c.Servers[0].Password})
	return m, nil
}
