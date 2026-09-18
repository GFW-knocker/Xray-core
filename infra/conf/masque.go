package conf

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/GFW-knocker/Xray-core/common/errors"
	"github.com/GFW-knocker/Xray-core/proxy/masque"
	"google.golang.org/protobuf/proto"
)

type MasqueConfig struct {
	Endpoint        string   `json:"endpoint"`
	Address         []string `json:"address"`
	PrivateKey      string   `json:"privateKey"`
	Certificate     string   `json:"certificate"`
	Transport       string   `json:"transport"`
	Authority       string   `json:"authority"`
	Path            string   `json:"path"`
	ConnectProtocol string   `json:"connectProtocol"`
	MTU             int32    `json:"mtu"`
	DNS             []string `json:"remoteDNS"`
	DomainStrategy  string   `json:"domainStrategy"`

	// Seconds. KeepAlivePeriod covers both carriers: it is the HTTP/2 PING
	// interval, and on HTTP/3 it overrides quicSettings' keepAlivePeriod.
	// KeepAliveTimeout is HTTP/2 only; HTTP/3's equivalent is quicSettings'
	// maxIdleTimeout.
	KeepAlivePeriod  int32 `json:"keepAlivePeriod"`
	KeepAliveTimeout int32 `json:"keepAliveTimeout"`

	// Built-in noise ahead of the QUIC handshake, HTTP/3 only. Same names and
	// meanings as the WireGuard outbound's, and additive with any udpmask.
	Wnoise       string `json:"wnoise"`
	Wnoisecount  string `json:"wnoisecount"`
	Wnoisedelay  string `json:"wnoisedelay"`
	Wpayloadsize string `json:"wpayloadsize"`

	PinnedPeerPublicKeySha256 []string `json:"pinnedPeerPublicKeySha256"`
}

func (c *MasqueConfig) Build() (proto.Message, error) {
	config := new(masque.Config)

	if c.Endpoint == "" {
		return nil, errors.New(`MASQUE "endpoint" is required`)
	}
	config.Endpoint = c.Endpoint

	if c.PrivateKey == "" {
		return nil, errors.New(`MASQUE "privateKey" is required`)
	}
	// Parsed here as well as in the outbound so a typo is reported while the
	// configuration is being read, with the rest of the config errors.
	if _, err := masque.ParsePrivateKey(c.PrivateKey); err != nil {
		return nil, errors.New(`invalid MASQUE "privateKey"`).Base(err)
	}
	config.PrivateKey = c.PrivateKey
	config.Certificate = c.Certificate

	switch strings.ToLower(c.Transport) {
	case "h3", "":
		config.Transport = masque.Config_H3
	case "h2":
		config.Transport = masque.Config_H2
	default:
		return nil, errors.New(`unsupported MASQUE "transport": `, c.Transport, ` (want "h3" or "h2")`)
	}

	config.Address = c.Address

	config.Authority = c.Authority
	if config.Authority == "" {
		config.Authority = masque.DefaultAuthority
	}
	config.Path = c.Path
	if config.Path == "" {
		config.Path = masque.DefaultPath
	}
	config.ConnectProtocol = c.ConnectProtocol
	if config.ConnectProtocol == "" {
		config.ConnectProtocol = masque.DefaultConnectProtocol
	}

	config.Mtu = c.MTU
	if config.Mtu == 0 {
		config.Mtu = masque.DefaultMTU
	}
	config.Wnoise = c.Wnoise
	config.Wnoisecount = c.Wnoisecount
	config.Wnoisedelay = c.Wnoisedelay
	config.Wpayloadsize = c.Wpayloadsize

	config.KeepAlivePeriod = c.KeepAlivePeriod
	config.KeepAliveTimeout = c.KeepAliveTimeout
	// A negative period is the documented way to ask for no ping. A negative
	// timeout means nothing, and silently reading it as "use the default" would
	// hide a typo in the one setting whose job is noticing a dead tunnel.
	if config.KeepAliveTimeout < 0 {
		return nil, errors.New(`MASQUE "keepAliveTimeout" cannot be negative: `, config.KeepAliveTimeout)
	}
	if config.KeepAlivePeriod > 0 && config.KeepAliveTimeout > 0 &&
		config.KeepAliveTimeout < config.KeepAlivePeriod {
		return nil, errors.New(`MASQUE "keepAliveTimeout" (`, config.KeepAliveTimeout,
			`s) is shorter than "keepAlivePeriod" (`, config.KeepAlivePeriod,
			`s), so every ping would time out before the next one is due`)
	}

	if config.Mtu < 576 || config.Mtu > 65535 {
		return nil, errors.New(`MASQUE "mtu" is out of range: `, config.Mtu)
	}

	config.DNS = c.DNS

	// Checked here so a mistyped pin is reported with the rest of the config
	// errors rather than as a handshake failure much later.
	for _, pin := range c.PinnedPeerPublicKeySha256 {
		raw, err := hex.DecodeString(pin)
		if err != nil {
			return nil, errors.New(`MASQUE "pinnedPeerPublicKeySha256" entry `, pin, " is not hex").Base(err)
		}
		if len(raw) != sha256.Size {
			return nil, errors.New(
				`MASQUE "pinnedPeerPublicKeySha256" entry `, pin, " is ", len(raw), " bytes, want ", sha256.Size,
			)
		}
	}
	config.PinnedPeerPublicKeySha256 = c.PinnedPeerPublicKeySha256

	switch strings.ToLower(c.DomainStrategy) {
	case "forceip", "":
		config.DomainStrategy = masque.Config_FORCE_IP
	case "forceipv4":
		config.DomainStrategy = masque.Config_FORCE_IP4
	case "forceipv6":
		config.DomainStrategy = masque.Config_FORCE_IP6
	case "forceipv4v6":
		config.DomainStrategy = masque.Config_FORCE_IP46
	case "forceipv6v4":
		config.DomainStrategy = masque.Config_FORCE_IP64
	default:
		return nil, errors.New("unsupported domain strategy: ", c.DomainStrategy)
	}

	return config, nil
}
