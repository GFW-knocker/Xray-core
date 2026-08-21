package conf

import (
	"encoding/json"
	"strings"

	"github.com/GFW-knocker/Xray-core/common/errors"
	"github.com/GFW-knocker/Xray-core/common/protocol"
	"github.com/GFW-knocker/Xray-core/common/serial"
	"github.com/GFW-knocker/Xray-core/transport/internet/dnstt"
	"github.com/GFW-knocker/Xray-core/transport/internet/headers/dns"
	"github.com/GFW-knocker/Xray-core/transport/internet/headers/noop"
	"github.com/GFW-knocker/Xray-core/transport/internet/headers/srtp"
	"github.com/GFW-knocker/Xray-core/transport/internet/headers/tls"
	"github.com/GFW-knocker/Xray-core/transport/internet/headers/utp"
	"github.com/GFW-knocker/Xray-core/transport/internet/headers/wechat"
	"github.com/GFW-knocker/Xray-core/transport/internet/headers/wireguard"
	"github.com/GFW-knocker/Xray-core/transport/internet/quic"
	"google.golang.org/protobuf/proto"
)

// GFW-knocker: transports upstream removed but this fork keeps alive (QUIC, DNSTT).
// Kept in a dedicated file so future upstream syncs do not conflict with it.

// kcpHeaderLoader resolves the legacy packet-header types in
// transport/internet/headers, which the revived QUIC transport still uses.
var kcpHeaderLoader = NewJSONConfigLoader(ConfigCreatorCache{
	"none":         func() interface{} { return new(NoOpAuthenticator) },
	"srtp":         func() interface{} { return new(SRTPAuthenticator) },
	"utp":          func() interface{} { return new(UTPAuthenticator) },
	"wechat-video": func() interface{} { return new(WechatVideoAuthenticator) },
	"dtls":         func() interface{} { return new(DTLSAuthenticator) },
	"wireguard":    func() interface{} { return new(WireguardAuthenticator) },
	"dns":          func() interface{} { return new(DNSAuthenticator) },
}, "type", "")

type QUICConfig struct {
	Header   json.RawMessage `json:"header"`
	Security string          `json:"security"`
	Key      string          `json:"key"`
}

// Build implements Buildable.
func (c *QUICConfig) Build() (proto.Message, error) {
	config := &quic.Config{
		Key: c.Key,
	}

	if len(c.Header) > 0 {
		headerConfig, _, err := kcpHeaderLoader.Load(c.Header)
		if err != nil {
			return nil, errors.New("invalid QUIC header config.").Base(err).AtError()
		}
		ts, err := headerConfig.(Buildable).Build()
		if err != nil {
			return nil, errors.New("invalid QUIC header config").Base(err).AtError()
		}
		config.Header = serial.ToTypedMessage(ts)
	}

	var st protocol.SecurityType
	switch strings.ToLower(c.Security) {
	case "aes-128-gcm":
		st = protocol.SecurityType_AES128_GCM
	case "chacha20-poly1305":
		st = protocol.SecurityType_CHACHA20_POLY1305
	default:
		st = protocol.SecurityType_NONE
	}

	config.Security = &protocol.SecurityConfig{
		Type: st,
	}

	return config, nil
}

type DNSTTConfig struct {
	ServerPublicKey string `json:"serverPublicKey"`
	ServerAddress   string `json:"serverAddress"`
}

// Build implements Buildable.
func (c *DNSTTConfig) Build() (proto.Message, error) {
	config := &dnstt.Config{
		ServerPublicKey: c.ServerPublicKey,
		ServerAddress:   c.ServerAddress,
	}
	return config, nil
}

// The legacy mKCP/QUIC packet-header authenticators. Upstream dropped these when
// it moved header handling to finalmask/mkcp/header; this fork keeps them because
// the revived QUIC transport resolves headers through internet.CreatePacketHeader.

type NoOpAuthenticator struct{}

func (NoOpAuthenticator) Build() (proto.Message, error) {
	return new(noop.Config), nil
}

type SRTPAuthenticator struct{}

func (SRTPAuthenticator) Build() (proto.Message, error) {
	return new(srtp.Config), nil
}

type UTPAuthenticator struct{}

func (UTPAuthenticator) Build() (proto.Message, error) {
	return new(utp.Config), nil
}

type WechatVideoAuthenticator struct{}

func (WechatVideoAuthenticator) Build() (proto.Message, error) {
	return new(wechat.VideoConfig), nil
}

type WireguardAuthenticator struct{}

func (WireguardAuthenticator) Build() (proto.Message, error) {
	return new(wireguard.WireguardConfig), nil
}

type DNSAuthenticator struct {
	Domain string `json:"domain"`
}

func (v *DNSAuthenticator) Build() (proto.Message, error) {
	config := new(dns.Config)
	config.Domain = "www.baidu.com"
	if len(v.Domain) > 0 {
		config.Domain = v.Domain
	}
	return config, nil
}

type DTLSAuthenticator struct{}

func (DTLSAuthenticator) Build() (proto.Message, error) {
	return new(tls.PacketConfig), nil
}
