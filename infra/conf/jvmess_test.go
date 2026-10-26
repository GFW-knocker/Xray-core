package conf_test

import (
	"testing"

	"github.com/GFW-knocker/Xray-core/common/net"
	"github.com/GFW-knocker/Xray-core/common/protocol"
	"github.com/GFW-knocker/Xray-core/common/serial"
	. "github.com/GFW-knocker/Xray-core/infra/conf"
	"github.com/GFW-knocker/Xray-core/proxy/jvmess"
	"github.com/GFW-knocker/Xray-core/proxy/jvmess/outbound"
)

func TestJVMessOutbound(t *testing.T) {
	creator := func() Buildable {
		return new(JVMessOutboundConfig)
	}

	want := &outbound.Config{
		Receiver: &protocol.ServerEndpoint{
			Address: &net.IPOrDomain{
				Address: &net.IPOrDomain_Ip{
					Ip: []byte{127, 0, 0, 1},
				},
			},
			Port: 80,
			User: &protocol.User{
				Email: "love@example.com",
				Level: 255,
				Account: serial.ToTypedMessage(&jvmess.Account{
					Id: "e641f5ad-9397-41e3-bf1a-e8740dfed019",
					SecuritySettings: &protocol.SecurityConfig{
						Type: protocol.SecurityType_AUTO,
					},
				}),
			},
		},
	}

	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"vnext": [{
					"address": "127.0.0.1",
					"port": 80,
					"users": [
						{
							"id": "e641f5ad-9397-41e3-bf1a-e8740dfed019",
							"email": "love@example.com",
							"level": 255
						}
					]
				}]
			}`,
			Parser: loadJSON(creator),
			Output: want,
		},
		{
			Input: `{
				"address": "127.0.0.1",
				"port": 80,
				"id": "e641f5ad-9397-41e3-bf1a-e8740dfed019",
				"email": "love@example.com",
				"level": 255
			}`,
			Parser: loadJSON(creator),
			Output: want,
		},
	})
}
