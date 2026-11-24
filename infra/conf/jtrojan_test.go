package conf_test

import (
	"encoding/json"
	"testing"

	"github.com/GFW-knocker/Xray-core/common"
	"github.com/GFW-knocker/Xray-core/common/net"
	"github.com/GFW-knocker/Xray-core/common/protocol"
	"github.com/GFW-knocker/Xray-core/common/serial"
	. "github.com/GFW-knocker/Xray-core/infra/conf"
	"github.com/GFW-knocker/Xray-core/proxy/jtrojan"
	"github.com/GFW-knocker/Xray-core/proxy/trojan"
)

func TestJTrojanOutbound(t *testing.T) {
	creator := func() Buildable {
		return new(JTrojanClientConfig)
	}

	want := &trojan.ClientConfig{
		Server: &protocol.ServerEndpoint{
			Address: &net.IPOrDomain{
				Address: &net.IPOrDomain_Ip{
					Ip: []byte{1, 2, 3, 4},
				},
			},
			Port: 443,
			User: &protocol.User{
				Email: "love@example.com",
				Level: 1,
				Account: serial.ToTypedMessage(&jtrojan.Account{
					Password: "21078987-1334-4000-0005-000000000001",
				}),
			},
		},
	}

	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"servers": [{
					"address": "1.2.3.4",
					"port": 443,
					"password": "21078987-1334-4000-0005-000000000001",
					"email": "love@example.com",
					"level": 1
				}]
			}`,
			Parser: loadJSON(creator),
			Output: want,
		},
		{
			Input: `{
				"address": "1.2.3.4",
				"port": 443,
				"password": "21078987-1334-4000-0005-000000000001",
				"email": "love@example.com",
				"level": 1
			}`,
			Parser: loadJSON(creator),
			Output: want,
		},
	})
}

// Plain ws with no TLS, the way these servers run.
func TestJTrojanOutboundDetour(t *testing.T) {
	c := new(OutboundDetourConfig)
	common.Must(json.Unmarshal([]byte(`{
		"protocol": "jtrojan",
		"settings": {
			"address": "1.2.3.4",
			"port": 80,
			"password": "21078987-1334-4000-0005-000000000001"
		},
		"streamSettings": {"network": "ws", "security": "none", "wsSettings": {"path": "/x"}}
	}`), c))
	h, err := c.Build()
	common.Must(err)
	settings := common.Must2(h.ProxySettings.GetInstance()).(*trojan.ClientConfig)

	// the stock trojan client resolves the account the same way
	user := common.Must2(settings.Server.User.ToMemoryUser())
	if key := user.Account.(*trojan.MemoryAccount).Key; string(key[:2]) != "\x21\x07" {
		t.Fatalf("key starts with %q, want the raw UUID bytes", key[:2])
	}
}
