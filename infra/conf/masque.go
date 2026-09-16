package conf

import (
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
	if config.Mtu < 576 || config.Mtu > 65535 {
		return nil, errors.New(`MASQUE "mtu" is out of range: `, config.Mtu)
	}

	config.DNS = c.DNS

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
