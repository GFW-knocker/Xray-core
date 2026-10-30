package conf_test

import (
	"encoding/json"
	"testing"

	"github.com/GFW-knocker/Xray-core/common"
	"github.com/GFW-knocker/Xray-core/common/net"
	"github.com/GFW-knocker/Xray-core/common/protocol"
	"github.com/GFW-knocker/Xray-core/common/serial"
	core "github.com/GFW-knocker/Xray-core/core"
	. "github.com/GFW-knocker/Xray-core/infra/conf"
	"github.com/GFW-knocker/Xray-core/proxy/jvless/outbound"
	"github.com/GFW-knocker/Xray-core/proxy/vless"
	vlessoutbound "github.com/GFW-knocker/Xray-core/proxy/vless/outbound"
	"google.golang.org/protobuf/proto"
)

func TestJVLessOutbound(t *testing.T) {
	creator := func() Buildable {
		return new(JVLessOutboundConfig)
	}

	want := &outbound.Config{
		Vnext: &protocol.ServerEndpoint{
			Address: &net.IPOrDomain{
				Address: &net.IPOrDomain_Domain{
					Domain: "example.com",
				},
			},
			Port: 443,
			User: &protocol.User{
				Email: "love@example.com",
				Level: 1,
				Account: serial.ToTypedMessage(&vless.Account{
					Id:         "27848739-7e62-4138-9fd3-098a63964b6b",
					Flow:       "xtls-rprx-vision",
					Encryption: "none",
				}),
			},
		},
	}

	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"vnext": [{
					"address": "example.com",
					"port": 443,
					"users": [
						{
							"id": "27848739-7e62-4138-9fd3-098a63964b6b",
							"flow": "xtls-rprx-vision",
							"encryption": "none",
							"email": "love@example.com",
							"level": 1
						}
					]
				}]
			}`,
			Parser: loadJSON(creator),
			Output: want,
		},
		{
			Input: `{
				"address": "example.com",
				"port": 443,
				"id": "27848739-7e62-4138-9fd3-098a63964b6b",
				"flow": "xtls-rprx-vision",
				"encryption": "none",
				"email": "love@example.com",
				"level": 1
			}`,
			Parser: loadJSON(creator),
			Output: want,
		},
	})
}

// Only the protocol name changes: settings and transport build the same as VLESS.
func TestJVLessOutboundDetour(t *testing.T) {
	build := func(name, stream string) *core.OutboundHandlerConfig {
		c := new(OutboundDetourConfig)
		common.Must(json.Unmarshal([]byte(`{
			"protocol": "`+name+`",
			"settings": {
				"address": "example.com",
				"port": 443,
				"id": "27848739-7e62-4138-9fd3-098a63964b6b",
				"encryption": "none"
			},
			"streamSettings": `+stream+`
		}`), c))
		h, err := c.Build()
		common.Must(err)
		return h
	}

	for _, stream := range []string{
		`{"network": "grpc", "security": "tls", "tlsSettings": {"serverName": "example.com"}, "grpcSettings": {"serviceName": "svc"}}`,
		`{"network": "httpupgrade", "security": "tls", "tlsSettings": {"serverName": "example.com"}, "httpupgradeSettings": {"path": "/up"}}`,
	} {
		v, jv := build("vless", stream), build("jvless", stream)
		if jv.ProxySettings.Type != "xray.proxy.jvless.outbound.Config" {
			t.Fatalf("jvless built %q", jv.ProxySettings.Type)
		}
		vSettings, err := v.ProxySettings.GetInstance()
		common.Must(err)
		jvSettings, err := jv.ProxySettings.GetInstance()
		common.Must(err)
		if !proto.Equal(jvSettings.(*outbound.Config).Vnext, vSettings.(*vlessoutbound.Config).Vnext) {
			t.Fatalf("settings differ from vless:\n%v\n%v", jvSettings, vSettings)
		}
		if !proto.Equal(jv.SenderSettings, v.SenderSettings) {
			t.Fatalf("stream settings differ from vless:\n%v\n%v", jv.SenderSettings, v.SenderSettings)
		}

		wire, err := proto.Marshal(jv)
		common.Must(err)
		decoded := new(core.OutboundHandlerConfig)
		common.Must(proto.Unmarshal(wire, decoded))
		if !proto.Equal(decoded, jv) {
			t.Fatalf("round trip changed the handler config:\n%v\n%v", decoded, jv)
		}
	}
}
