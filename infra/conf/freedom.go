package conf

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"net"
	"strconv"
	"strings"

	"github.com/GFW-knocker/Xray-core/common/errors"
	"github.com/GFW-knocker/Xray-core/common/geodata"
	xnet "github.com/GFW-knocker/Xray-core/common/net"
	"github.com/GFW-knocker/Xray-core/common/protocol"
	"github.com/GFW-knocker/Xray-core/proxy/freedom"
	"github.com/GFW-knocker/Xray-core/transport/internet"
	"google.golang.org/protobuf/proto"
)

type FreedomConfig struct {
	TargetStrategy string                    `json:"targetStrategy"`
	DomainStrategy string                    `json:"domainStrategy"`
	Redirect       string                    `json:"redirect"`
	UserLevel      uint32                    `json:"userLevel"`
	Fragment       *Fragment                 `json:"fragment"`
	Noise          *Noise                    `json:"noise"`
	Noises         []*Noise                  `json:"noises"`
	NoiseKeepAlive uint32                    `json:"noiseKeepAlive"`
	ProxyProtocol  uint32                    `json:"proxyProtocol"`
	IPsBlocked     *StringList               `json:"ipsBlocked"`
	FinalRules     []*FreedomFinalRuleConfig `json:"finalRules"`
}

// Upper bounds for the "fragment" ranges. These exist because the values are
// parsed as uint64 but used as int64 in proxy/freedom: a value above 2^63 wraps
// negative there, which panics on the slice bounds (length, packets) or
// silently skips the delay (interval).
const (
	// A TLS record's length field is two bytes, so a fragment can never
	// usefully be longer -- and a batch can never hold more records than a
	// maximum-size record can be split into.
	maxFragmentLength  = 65535
	maxFragmentBatch   = 65535
	maxFragmentPackets = 65535
	// Milliseconds. An hour is far past any real use and keeps the
	// time.Duration multiplication in proxy/freedom in range.
	maxFragmentInterval = 3600000
)

type Fragment struct {
	Packets      string      `json:"packets"`
	Length       string      `json:"length"`
	Interval     string      `json:"interval"`
	Batch        string      `json:"batch"`
	Host1_header string      `json:"host1_header"`
	Host1_domain string      `json:"host1_domain"`
	Host2_header string      `json:"host2_header"`
	Host2_domain string      `json:"host2_domain"`
	MaxSplit     *Int32Range `json:"maxSplit"`
}

type Noise struct {
	Type    string      `json:"type"`
	Packet  string      `json:"packet"`
	Delay   *Int32Range `json:"delay"`
	Count   *Int32Range `json:"count"`
	ApplyTo string      `json:"applyTo"`
}

type FreedomFinalRuleConfig struct {
	Action     string       `json:"action"`
	Network    *NetworkList `json:"network"`
	Port       *PortList    `json:"port"`
	IP         *StringList  `json:"ip"`
	BlockDelay *Int32Range  `json:"blockDelay"`
}

// Build implements Buildable
func (c *FreedomConfig) Build() (proto.Message, error) {
	if c.IPsBlocked != nil {
		// todo: remove legacy
		errors.LogWarning(context.Background(), `The feature "ipsBlocked" has been removed and migrated to "finalRules". Please update your config(s) according to release note and documentation.`)
	}

	config := new(freedom.Config)
	targetStrategy := c.TargetStrategy
	if targetStrategy == "" {
		targetStrategy = c.DomainStrategy
	}
	switch strings.ToLower(targetStrategy) {
	case "asis", "":
		config.DomainStrategy = internet.DomainStrategy_AS_IS
	case "useip":
		config.DomainStrategy = internet.DomainStrategy_USE_IP
	case "useipv4":
		config.DomainStrategy = internet.DomainStrategy_USE_IP4
	case "useipv6":
		config.DomainStrategy = internet.DomainStrategy_USE_IP6
	case "useipv4v6":
		config.DomainStrategy = internet.DomainStrategy_USE_IP46
	case "useipv6v4":
		config.DomainStrategy = internet.DomainStrategy_USE_IP64
	case "forceip":
		config.DomainStrategy = internet.DomainStrategy_FORCE_IP
	case "forceipv4":
		config.DomainStrategy = internet.DomainStrategy_FORCE_IP4
	case "forceipv6":
		config.DomainStrategy = internet.DomainStrategy_FORCE_IP6
	case "forceipv4v6":
		config.DomainStrategy = internet.DomainStrategy_FORCE_IP46
	case "forceipv6v4":
		config.DomainStrategy = internet.DomainStrategy_FORCE_IP64
	default:
		return nil, errors.New("unsupported domain strategy: ", targetStrategy)
	}

	if c.Fragment != nil {
		config.Fragment = new(freedom.Fragment)
		var err, err2 error

		config.Fragment.FakeHost = false

		switch strings.ToLower(c.Fragment.Packets) {
		case "tlshello":
			// TLS Hello Fragmentation (into multiple handshake messages)
			config.Fragment.PacketsFrom = 0
			config.Fragment.PacketsTo = 1
		case "fakehost":
			// fake host header with no fragmentation
			config.Fragment.PacketsFrom = 1
			config.Fragment.PacketsTo = 1
			config.Fragment.FakeHost = true
		case "":
			// TCP Segmentation (all packets)
			config.Fragment.PacketsFrom = 0
			config.Fragment.PacketsTo = 0
		default:
			// TCP Segmentation (range)
			packetsFromTo := strings.Split(c.Fragment.Packets, "-")
			if len(packetsFromTo) == 2 {
				config.Fragment.PacketsFrom, err = strconv.ParseUint(packetsFromTo[0], 10, 64)
				config.Fragment.PacketsTo, err2 = strconv.ParseUint(packetsFromTo[1], 10, 64)
			} else {
				config.Fragment.PacketsFrom, err = strconv.ParseUint(packetsFromTo[0], 10, 64)
				config.Fragment.PacketsTo = config.Fragment.PacketsFrom
			}
			if err != nil {
				return nil, errors.New("Invalid PacketsFrom").Base(err)
			}
			if err2 != nil {
				return nil, errors.New("Invalid PacketsTo").Base(err2)
			}
			if config.Fragment.PacketsFrom > config.Fragment.PacketsTo {
				config.Fragment.PacketsFrom, config.Fragment.PacketsTo = config.Fragment.PacketsTo, config.Fragment.PacketsFrom
			}
			if config.Fragment.PacketsFrom == 0 {
				return nil, errors.New("PacketsFrom can't be 0")
			}
			if config.Fragment.PacketsTo > maxFragmentPackets {
				return nil, errors.New("PacketsTo can't be greater than ", maxFragmentPackets)
			}
		}

		{
			if c.Fragment.Length == "" {
				return nil, errors.New("Length can't be empty")
			}
			lengthMinMax := strings.Split(c.Fragment.Length, "-")
			if len(lengthMinMax) == 2 {
				config.Fragment.LengthMin, err = strconv.ParseUint(lengthMinMax[0], 10, 64)
				config.Fragment.LengthMax, err2 = strconv.ParseUint(lengthMinMax[1], 10, 64)
			} else {
				config.Fragment.LengthMin, err = strconv.ParseUint(lengthMinMax[0], 10, 64)
				config.Fragment.LengthMax = config.Fragment.LengthMin
			}
			if err != nil {
				return nil, errors.New("Invalid LengthMin").Base(err)
			}
			if err2 != nil {
				return nil, errors.New("Invalid LengthMax").Base(err2)
			}
			if config.Fragment.LengthMin > config.Fragment.LengthMax {
				config.Fragment.LengthMin, config.Fragment.LengthMax = config.Fragment.LengthMax, config.Fragment.LengthMin
			}
			if config.Fragment.LengthMin == 0 {
				return nil, errors.New("LengthMin can't be 0")
			}
			if config.Fragment.LengthMax > maxFragmentLength {
				return nil, errors.New("LengthMax can't be greater than ", maxFragmentLength)
			}
		}

		{
			if c.Fragment.Interval == "" {
				return nil, errors.New("Interval can't be empty")
			}
			intervalMinMax := strings.Split(c.Fragment.Interval, "-")
			if len(intervalMinMax) == 2 {
				config.Fragment.IntervalMin, err = strconv.ParseUint(intervalMinMax[0], 10, 64)
				config.Fragment.IntervalMax, err2 = strconv.ParseUint(intervalMinMax[1], 10, 64)
			} else {
				config.Fragment.IntervalMin, err = strconv.ParseUint(intervalMinMax[0], 10, 64)
				config.Fragment.IntervalMax = config.Fragment.IntervalMin
			}
			if err != nil {
				return nil, errors.New("Invalid IntervalMin").Base(err)
			}
			if err2 != nil {
				return nil, errors.New("Invalid IntervalMax").Base(err2)
			}
			if config.Fragment.IntervalMin > config.Fragment.IntervalMax {
				config.Fragment.IntervalMin, config.Fragment.IntervalMax = config.Fragment.IntervalMax, config.Fragment.IntervalMin
			}
			if config.Fragment.IntervalMax > maxFragmentInterval {
				return nil, errors.New("IntervalMax can't be greater than ", maxFragmentInterval, " ms")
			}
		}

		{
			// How many TLS records are batched into one write before sleeping
			// for "interval". Absent means 10-20, which is what was hardcoded
			// before this became configurable.
			if c.Fragment.Batch == "" {
				config.Fragment.BatchMin = 10
				config.Fragment.BatchMax = 20
			} else {
				batchMinMax := strings.Split(c.Fragment.Batch, "-")
				if len(batchMinMax) == 2 {
					config.Fragment.BatchMin, err = strconv.ParseUint(batchMinMax[0], 10, 64)
					config.Fragment.BatchMax, err2 = strconv.ParseUint(batchMinMax[1], 10, 64)
				} else {
					config.Fragment.BatchMin, err = strconv.ParseUint(batchMinMax[0], 10, 64)
					config.Fragment.BatchMax = config.Fragment.BatchMin
				}
				if err != nil {
					return nil, errors.New("Invalid BatchMin").Base(err)
				}
				if err2 != nil {
					return nil, errors.New("Invalid BatchMax").Base(err2)
				}
				if config.Fragment.BatchMin > config.Fragment.BatchMax {
					config.Fragment.BatchMin, config.Fragment.BatchMax = config.Fragment.BatchMax, config.Fragment.BatchMin
				}
				if config.Fragment.BatchMax > maxFragmentBatch {
					return nil, errors.New("BatchMax can't be greater than ", maxFragmentBatch)
				}
			}
		}

		{
			if c.Fragment.Host1_header == "" {
				config.Fragment.Host1Header = "Host : "
			} else {
				config.Fragment.Host1Header = c.Fragment.Host1_header
			}

			if c.Fragment.Host1_domain == "" {
				config.Fragment.Host1Domain = "cloudflare.com"
			} else {
				config.Fragment.Host1Domain = c.Fragment.Host1_domain
			}

			if c.Fragment.Host2_header == "" {
				config.Fragment.Host2Header = "Host:   "
			} else {
				config.Fragment.Host2Header = c.Fragment.Host2_header
			}

			if c.Fragment.Host2_domain == "" {
				config.Fragment.Host2Domain = "cloudflare.com"
			} else {
				config.Fragment.Host2Domain = c.Fragment.Host2_domain
			}

			if c.Fragment.MaxSplit != nil {
				config.Fragment.MaxSplitMin = uint64(c.Fragment.MaxSplit.From)
				config.Fragment.MaxSplitMax = uint64(c.Fragment.MaxSplit.To)
			}

		}

	}

	if c.Noise != nil {
		return nil, errors.PrintRemovedFeatureError("noise = { ... }", "noises = [ { ... } ]")
	}

	if c.Noises != nil {
		for _, n := range c.Noises {
			NConfig, err := ParseNoise(n)
			if err != nil {
				return nil, err
			}
			config.Noises = append(config.Noises, NConfig)
		}
	}

	// nosekeepalive keep repeating noise every n sec
	// if not defined in json, default is zero which is disable
	config.NoiseKeepAlive = c.NoiseKeepAlive

	config.UserLevel = c.UserLevel

	if len(c.Redirect) > 0 {
		host, portStr, err := net.SplitHostPort(c.Redirect)
		if err != nil {
			return nil, errors.New("invalid redirect address: ", c.Redirect, ": ", err).Base(err)
		}
		port, err := xnet.PortFromString(portStr)
		if err != nil {
			return nil, errors.New("invalid redirect port: ", c.Redirect, ": ", err).Base(err)
		}
		config.DestinationOverride = &freedom.DestinationOverride{
			Server: &protocol.ServerEndpoint{
				Port: uint32(port),
			},
		}

		if len(host) > 0 {
			config.DestinationOverride.Server.Address = xnet.NewIPOrDomain(xnet.ParseAddress(host))
		}
	}

	if c.ProxyProtocol > 0 && c.ProxyProtocol <= 2 {
		config.ProxyProtocol = c.ProxyProtocol
	}

	for _, r := range c.FinalRules {
		rule, err := r.Build()
		if err != nil {
			return nil, err
		}
		config.FinalRules = append(config.FinalRules, rule)
	}

	return config, nil
}

func ParseNoise(noise *Noise) (*freedom.Noise, error) {
	var err error
	NConfig := new(freedom.Noise)
	noise.Packet = strings.TrimSpace(noise.Packet)

	switch noise.Type {
	case "rand":
		min, max, err := ParseRangeString(noise.Packet)
		if err != nil {
			return nil, errors.New("invalid value for rand Length").Base(err)
		}
		NConfig.LengthMin = uint64(min)
		NConfig.LengthMax = uint64(max)
		if NConfig.LengthMin == 0 {
			return nil, errors.New("rand lengthMin or lengthMax cannot be 0")
		}

	case "str":
		// user input string
		NConfig.Packet = []byte(noise.Packet)

	case "hex":
		// user input hex
		NConfig.Packet, err = hex.DecodeString(noise.Packet)
		if err != nil {
			return nil, errors.New("Invalid hex string").Base(err)
		}

	case "base64":
		// user input base64
		NConfig.Packet, err = base64.RawURLEncoding.DecodeString(strings.NewReplacer("+", "-", "/", "_", "=", "").Replace(noise.Packet))
		if err != nil {
			return nil, errors.New("Invalid base64 string").Base(err)
		}

	default:
		return nil, errors.New("Invalid packet, only rand/str/hex/base64 are supported")
	}

	if noise.Delay != nil {
		NConfig.DelayMin = uint64(noise.Delay.From)
		NConfig.DelayMax = uint64(noise.Delay.To)
	}

	if noise.Count != nil {
		NConfig.CountMin = uint64(noise.Count.From)
		NConfig.CountMax = uint64(noise.Count.To)
	}

	switch strings.ToLower(noise.ApplyTo) {
	case "", "ip", "all":
		NConfig.ApplyTo = "ip"
	case "ipv4":
		NConfig.ApplyTo = "ipv4"
	case "ipv6":
		NConfig.ApplyTo = "ipv6"
	default:
		return nil, errors.New("Invalid applyTo, only ip/ipv4/ipv6 are supported")
	}
	return NConfig, nil
}

func (c *FreedomFinalRuleConfig) Build() (*freedom.FinalRuleConfig, error) {
	rule := &freedom.FinalRuleConfig{}

	switch strings.ToLower(c.Action) {
	case "allow":
		rule.Action = freedom.RuleAction_Allow
	case "block":
		rule.Action = freedom.RuleAction_Block
	default:
		return nil, errors.New("unknown action: ", c.Action)
	}

	if c.Network != nil {
		rule.Networks = c.Network.Build()
	}

	if c.Port != nil {
		rule.PortList = c.Port.Build()
	}

	if c.IP != nil {
		rules, err := geodata.ParseIPRules(*c.IP)
		if err != nil {
			return nil, err
		}
		rule.Ip = rules
	}

	if c.BlockDelay != nil {
		rule.BlockDelay = &freedom.Range{
			Min: uint64(c.BlockDelay.From),
			Max: uint64(c.BlockDelay.To),
		}
	}

	return rule, nil
}
