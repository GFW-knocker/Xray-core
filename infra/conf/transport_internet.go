package conf

import (
	"context"
	"slices"
	"strings"

	"github.com/GFW-knocker/Xray-core/common/errors"
	"github.com/GFW-knocker/Xray-core/common/serial"
	"github.com/GFW-knocker/Xray-core/transport/internet"
	"github.com/GFW-knocker/Xray-core/transport/internet/tls"
	utls "github.com/refraction-networking/utls"
)

type TransportProtocol string

// Build implements Buildable.
func (p TransportProtocol) Build() (string, error) {
	switch strings.ToLower(string(p)) {
	case "raw", "tcp":
		return "tcp", nil
	case "xhttp", "splithttp":
		return "splithttp", nil
	case "kcp", "mkcp":
		return "mkcp", nil
	case "grpc":
		errors.PrintNonRemovalDeprecatedFeatureWarning("gRPC transport (with unnecessary costs, etc.)", "XHTTP stream-up H2")
		return "grpc", nil
	case "ws", "websocket":
		errors.PrintNonRemovalDeprecatedFeatureWarning("WebSocket transport (with ALPN http/1.1, etc.)", "XHTTP H2 & H3")
		return "websocket", nil
	case "httpupgrade":
		errors.PrintNonRemovalDeprecatedFeatureWarning("HTTPUpgrade transport (with ALPN http/1.1, etc.)", "XHTTP H2 & H3")
		return "httpupgrade", nil
	case "h2", "h3", "http":
		return "", errors.PrintRemovedFeatureError("HTTP transport (without header padding, etc.)", "XHTTP stream-one H2 & H3")
	case "quic":
		// GFW-knocker: QUIC transport kept alive; warn but still accept it.
		errors.PrintRemovedFeatureError("QUIC transport (without web service, etc.)", "XHTTP stream-one H3")
		return "quic", nil
	case "dnstt":
		return "dnstt", nil
	case "hysteria":
		return "hysteria", nil
	case "xdrive":
		return "xdrive", nil
	default:
		return "", errors.New("Config: unknown transport protocol: ", p)
	}
}

type StreamConfig struct {
	Address             *Address           `json:"address"`
	Port                uint16             `json:"port"`
	Method              *TransportProtocol `json:"method"`
	Network             *TransportProtocol `json:"network"`
	Security            string             `json:"security"`
	FinalMask           *FinalMask         `json:"finalmask"`
	TLSSettings         *TLSConfig         `json:"tlsSettings"`
	REALITYSettings     *REALITYConfig     `json:"realitySettings"`
	RAWSettings         *TCPConfig         `json:"rawSettings"`
	TCPSettings         *TCPConfig         `json:"tcpSettings"`
	XHTTPSettings       *SplitHTTPConfig   `json:"xhttpSettings"`
	SplitHTTPSettings   *SplitHTTPConfig   `json:"splithttpSettings"`
	KCPSettings         *KCPConfig         `json:"kcpSettings"`
	QUICSettings        *QUICConfig        `json:"quicSettings"`
	QUICTCPSettings     *QUICTCPConfig     `json:"quictcpSettings"`
	HYTCPSettings       *HYTCPConfig       `json:"hytcpSettings"`
	GRPCSettings        *GRPCConfig        `json:"grpcSettings"`
	WSSettings          *WebSocketConfig   `json:"wsSettings"`
	HTTPUPGRADESettings *HttpUpgradeConfig `json:"httpupgradeSettings"`
	HysteriaSettings    *HysteriaConfig    `json:"hysteriaSettings"`
	DNSTTSettings       *DNSTTConfig       `json:"dnsttSettings"`
	XDRIVESettings      *XDriveConfig      `json:"xdriveSettings"`
	SocketSettings      *SocketConfig      `json:"sockopt"`
}

// Build implements Buildable.
func (c *StreamConfig) Build() (*internet.StreamConfig, error) {
	config := &internet.StreamConfig{
		Port:         uint32(c.Port),
		ProtocolName: "tcp",
	}
	if c.Address != nil {
		config.Address = c.Address.Build()
	}
	if c.Method != nil {
		c.Network = c.Method
	}
	// "quictcp" and "hytcp" are the quic and hysteria transports carried by a
	// "tcplane" udp mask, which is added below as the last udp mask.
	laneNet := ""
	if c.Network != nil {
		switch n := strings.ToLower(string(*c.Network)); n {
		case "quictcp":
			laneNet = n
			config.ProtocolName = "quic"
		case "hytcp":
			laneNet = n
			config.ProtocolName = "hysteria"
		default:
			protocol, err := c.Network.Build()
			if err != nil {
				return nil, err
			}
			config.ProtocolName = protocol
		}
	}
	quicTCP, hyTCP := laneNet == "quictcp", laneNet == "hytcp"
	if c.QUICTCPSettings != nil && !quicTCP {
		return nil, errors.New(`"quictcpSettings" needs "network": "quictcp"`)
	}
	if c.HYTCPSettings != nil && !hyTCP {
		return nil, errors.New(`"hytcpSettings" needs "network": "hytcp"`)
	}

	var xdriveH3 bool
	switch strings.ToLower(c.Security) {
	case "", "none":
	case "tls":
		tlsSettings := c.TLSSettings
		if tlsSettings == nil {
			tlsSettings = &TLSConfig{}
		}
		ts, err := tlsSettings.Build()
		if err != nil {
			return nil, errors.New("Failed to build TLS config.").Base(err)
		}
		tm := serial.ToTypedMessage(ts)
		config.SecuritySettings = append(config.SecuritySettings, tm)
		config.SecurityType = tm.Type
		xdriveH3 = config.ProtocolName == "xdrive" && tlsSettings.ALPN != nil && slices.Equal(*tlsSettings.ALPN, StringList{"h3"})
		if config.ProtocolName == "xdrive" && tlsSettings.ALPN != nil && slices.Equal(*tlsSettings.ALPN, StringList{"http/1.1"}) && tlsSettings.ECHConfigList == "" {
			// a fingerprint puts its own ALPN into the hello, except Go TLS and the
			// randomized ones, which take it from the config or send none
			if fp := tls.GetFingerprint(strings.ToLower(tlsSettings.Fingerprint)); fp != nil && fp.Client != utls.HelloGolang.Client &&
				!strings.HasPrefix(fp.Client, utls.HelloRandomized.Client) {
				errors.LogWarning(context.Background(), `XDRIVE: "alpn" ["http/1.1"] reaches the wire only inside ECH, without "echConfigList" the hello carries the ALPN of the fingerprint and the server may pick h2`)
			}
		}
	case "reality":
		if config.ProtocolName != "tcp" && config.ProtocolName != "splithttp" && config.ProtocolName != "grpc" {
			return nil, errors.New("REALITY only supports RAW, XHTTP and gRPC for now.")
		}
		if c.REALITYSettings == nil {
			return nil, errors.New(`REALITY: Empty "realitySettings".`)
		}
		ts, err := c.REALITYSettings.Build()
		if err != nil {
			return nil, errors.New("Failed to build REALITY config.").Base(err)
		}
		tm := serial.ToTypedMessage(ts)
		config.SecuritySettings = append(config.SecuritySettings, tm)
		config.SecurityType = tm.Type
	case "xtls":
		return nil, errors.PrintRemovedFeatureError(`Legacy XTLS`, `xtls-rprx-vision with TLS or REALITY`)
	default:
		return nil, errors.New(`Unknown security "` + c.Security + `".`)
	}

	if c.RAWSettings != nil {
		c.TCPSettings = c.RAWSettings
	}
	if c.TCPSettings != nil {
		ts, err := c.TCPSettings.Build()
		if err != nil {
			return nil, errors.New("Failed to build RAW config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "tcp",
			Settings:     serial.ToTypedMessage(ts),
		})
	}
	if c.XHTTPSettings != nil {
		c.SplitHTTPSettings = c.XHTTPSettings
	}
	if c.SplitHTTPSettings != nil {
		hs, err := c.SplitHTTPSettings.Build()
		if err != nil {
			return nil, errors.New("Failed to build XHTTP config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "splithttp",
			Settings:     serial.ToTypedMessage(hs),
		})
	}
	if c.KCPSettings != nil {
		ts, err := c.KCPSettings.Build()
		if err != nil {
			return nil, errors.New("Failed to build mKCP config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "mkcp",
			Settings:     serial.ToTypedMessage(ts),
		})
	}
	if quicTCP {
		if c.QUICSettings != nil {
			return nil, errors.New(`"network": "quictcp" takes "quictcpSettings", not "quicSettings"`)
		}
		settings := c.QUICTCPSettings
		if settings == nil {
			settings = &QUICTCPConfig{}
		}
		qs, err := settings.QUICConfig.Build()
		if err != nil {
			return nil, errors.New("Failed to build QUICTCP config").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "quic",
			Settings:     serial.ToTypedMessage(qs),
		})
	}
	if c.QUICSettings != nil {
		qs, err := c.QUICSettings.Build()
		if err != nil {
			return nil, errors.New("Failed to build QUIC config").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "quic",
			Settings:     serial.ToTypedMessage(qs),
		})
	}
	if c.GRPCSettings != nil {
		gs, err := c.GRPCSettings.Build()
		if err != nil {
			return nil, errors.New("Failed to build gRPC config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "grpc",
			Settings:     serial.ToTypedMessage(gs),
		})
	}
	if c.WSSettings != nil {
		ts, err := c.WSSettings.Build()
		if err != nil {
			return nil, errors.New("Failed to build WebSocket config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "websocket",
			Settings:     serial.ToTypedMessage(ts),
		})
	}
	if c.HTTPUPGRADESettings != nil {
		hs, err := c.HTTPUPGRADESettings.Build()
		if err != nil {
			return nil, errors.New("Failed to build HTTPUpgrade config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "httpupgrade",
			Settings:     serial.ToTypedMessage(hs),
		})
	}
	if hyTCP {
		if c.HysteriaSettings != nil {
			return nil, errors.New(`"network": "hytcp" takes "hytcpSettings", not "hysteriaSettings"`)
		}
		settings := c.HYTCPSettings
		if settings == nil {
			settings = &HYTCPConfig{}
		}
		hc := settings.HysteriaConfig
		if hc.Version == 0 {
			hc.Version = 2
		}
		hs, err := hc.Build()
		if err != nil {
			return nil, errors.New("Failed to build HYTCP config").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "hysteria",
			Settings:     serial.ToTypedMessage(hs),
		})
	}
	if c.HysteriaSettings != nil {
		hs, err := c.HysteriaSettings.Build()
		if err != nil {
			return nil, errors.New("Failed to build Hysteria config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "hysteria",
			Settings:     serial.ToTypedMessage(hs),
		})
	}
	if c.DNSTTSettings != nil {
		ds, err := c.DNSTTSettings.Build()
		if err != nil {
			return nil, errors.New("Failed to build DNSTT config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "dnstt",
			Settings:     serial.ToTypedMessage(ds),
		})
	}
	if c.XDRIVESettings != nil {
		c.XDRIVESettings.h3 = xdriveH3
		xs, err := c.XDRIVESettings.Build()
		if err != nil {
			return nil, errors.New("Failed to build XDRIVE config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "xdrive",
			Settings:     serial.ToTypedMessage(xs),
		})
	}
	if c.SocketSettings != nil {
		ss, err := c.SocketSettings.Build()
		if err != nil {
			return nil, errors.New("Failed to build sockopt.").Base(err)
		}
		config.SocketSettings = ss
	}

	if c.FinalMask != nil {
		for _, mask := range c.FinalMask.Tcp {
			proto, err := mask.Build(true)
			if err != nil {
				return nil, errors.New("failed to build mask with type ", mask.Type).Base(err)
			}
			config.Tcpmasks = append(config.Tcpmasks, serial.ToTypedMessage(proto))
		}
		for _, mask := range c.FinalMask.Udp {
			proto, err := mask.Build(false)
			if err != nil {
				return nil, errors.New("failed to build mask with type ", mask.Type).Base(err)
			}
			config.Udpmasks = append(config.Udpmasks, serial.ToTypedMessage(proto))
		}
		if c.FinalMask.QuicParams != nil {
			proto, err := c.FinalMask.QuicParams.Build()
			if err != nil {
				return nil, err
			}
			config.QuicParams = proto.(*internet.QuicParams)
		}
	}
	if laneNet != "" {
		if c.FinalMask != nil {
			for _, mask := range c.FinalMask.Udp {
				if strings.EqualFold(mask.Type, "tcplane") {
					return nil, errors.New(`"network": "`, laneNet, `" already carries a tcplane mask; set its options in "`, laneNet, `Settings"`)
				}
			}
		}
		var laneCfg TCPLane
		if quicTCP && c.QUICTCPSettings != nil {
			laneCfg = c.QUICTCPSettings.TCPLane
		}
		if hyTCP && c.HYTCPSettings != nil {
			laneCfg = c.HYTCPSettings.TCPLane
		}
		lane, err := laneCfg.Build()
		if err != nil {
			return nil, errors.New("Failed to build ", laneNet, " lane config").Base(err)
		}
		config.Udpmasks = append(config.Udpmasks, serial.ToTypedMessage(lane))
		// lanes reorder datagrams, which loss-based congestion control takes
		// for loss: BBR unless "quicParams" names another (for hytcp this
		// also replaces hysteria's default, Brutal at the announced rates,
		// which over lanes queues up whenever the rate is set too high)
		if config.QuicParams == nil {
			config.QuicParams = &internet.QuicParams{Congestion: "bbr", BbrProfile: "standard"}
		} else if config.QuicParams.Congestion == "" {
			config.QuicParams.Congestion = "bbr"
		}
	}

	if xdriveH3 && c.FinalMask != nil {
		if c.XDRIVESettings != nil && c.XDRIVESettings.Service == "google-drive" {
			// noise only sends datagrams of its own ahead of the QUIC ones, the
			// other masks change those or need a peer that undoes them
			for _, mask := range c.FinalMask.Udp {
				if strings.ToLower(mask.Type) != "noise" {
					return nil, errors.New(`XDRIVE: over h3 to Google Drive the only "udp" mask that works is "noise", not "`, mask.Type, `"`)
				}
			}
		}
		if config.QuicParams != nil && (config.QuicParams.Congestion == "brutal" || config.QuicParams.Congestion == "force-brutal") {
			return nil, errors.New(`XDRIVE: brutal is for Hysteria servers, over h3 "congestion" is "bbr" or "reno", not "`, config.QuicParams.Congestion, `"`)
		}
	}

	return config, nil
}
