package conf

import (
	"context"

	"github.com/GFW-knocker/Xray-core/common/errors"
	"github.com/GFW-knocker/Xray-core/transport/internet/finalmask/tcplane"
	"google.golang.org/protobuf/proto"
)

// TCPLane is the "tcplane" udp mask: the transport's datagrams go over many
// short TCP connections instead of a UDP socket. Both ends need it, and it
// must be the last udp mask.
type TCPLane struct {
	Packets       Int32Range `json:"packets"`
	LifeMs        Int32Range `json:"lifeMs"`
	Bytes         Int32Range `json:"bytes"`
	Lanes         int32      `json:"lanes"`
	MaxRate       *int32     `json:"maxRate"`
	Ports         PortList   `json:"ports"`
	Password      string     `json:"password"`
	GraceMs       *int32     `json:"graceMs"`
	IdleMs        *int32     `json:"idleMs"`
	MaxLifeMs     *int32     `json:"maxLifeMs"`
	Sndbuf        int32      `json:"sndbuf"`
	MaxLanesPerIP *int32     `json:"maxLanesPerIP"`
	DownLifeMs    *int32     `json:"downLifeMs"`
	FlushMs       *int32     `json:"flushMs"`
}

// tcpLaneMaxPorts bounds "ports": the server opens one listener per port.
const tcpLaneMaxPorts = 1024

func orDefault(v *int32, def int32) int32 {
	if v == nil {
		return def
	}
	return *v
}

func (c *TCPLane) Build() (proto.Message, error) {
	// Defaults from measurements behind a firewall that drops a TCP
	// connection's upstream after ~11-30 client packets (its down lanes'
	// client packets are only TCP ACKs, ~1 per 2.2 KB), where 25-30 new
	// lanes/s was the most a path took.
	packets := c.Packets
	if packets.From == 0 && packets.To == 0 {
		packets.From, packets.To = 8, 12
	}
	if packets.From < 1 {
		return nil, errors.New("tcplane: packets must be at least 1")
	}
	life := c.LifeMs
	if life.From == 0 && life.To == 0 {
		life.From, life.To = 800, 1200
	}
	if life.From < 1 {
		return nil, errors.New("tcplane: lifeMs must be at least 1")
	}
	// 2026-11-22: down lanes were cut after a median 15 client packets
	// (p10 12), at ~23 KB; 12-16 KB is ~3 + 6 packets
	bytes := c.Bytes
	if bytes.From == 0 && bytes.To == 0 {
		bytes.From, bytes.To = 12288, 16384
	}
	if bytes.From < 0 {
		// "bytes": -1 turns the received-bytes budget off
		bytes.From, bytes.To = 0, 0
	}
	lanes := c.Lanes
	if lanes == 0 {
		// a down lane takes ~2 RTT to open, fill and end, so this many keep
		// ~16/(2*RTT) lanes/s going, up to maxRate
		lanes = 24
	}
	if lanes < 1 || lanes > 64 {
		return nil, errors.New("tcplane: lanes must be 1-64")
	}
	// 2026-11-22: 50 lanes/s ran clean (1050 of 1051 down lanes connected)
	// and gave 435 KB/s; 30 capped it at ~310 KB/s
	maxRate := orDefault(c.MaxRate, 50)
	if maxRate < 0 {
		return nil, errors.New("tcplane: maxRate must not be negative (0 = no limit)")
	}
	grace := orDefault(c.GraceMs, 2000)
	idle := orDefault(c.IdleMs, 20000)
	maxLife := orDefault(c.MaxLifeMs, 60000)
	downLife := orDefault(c.DownLifeMs, 3000)
	flush := orDefault(c.FlushMs, 10)
	if grace < 0 || idle < 0 || maxLife < 0 || downLife < 0 || flush < 0 {
		return nil, errors.New("tcplane: graceMs, idleMs, maxLifeMs, downLifeMs and flushMs must not be negative")
	}
	if maxLife > 0 && idle > 0 && idle >= maxLife {
		errors.LogWarning(context.Background(), "tcplane: idleMs ", idle, " is not below the server's maxLifeMs ", maxLife, "; ready lanes may be closed before use")
	}
	ports := c.Ports.Build().Ports()
	if len(ports) > tcpLaneMaxPorts {
		return nil, errors.New("tcplane: at most ", tcpLaneMaxPorts, " ports")
	}
	if c.Sndbuf < 0 {
		return nil, errors.New("tcplane: sndbuf must not be negative")
	}
	return &tcplane.Config{
		PacketsMin:    int64(packets.From),
		PacketsMax:    int64(packets.To),
		LifeMin:       int64(life.From),
		LifeMax:       int64(life.To),
		BytesMin:      int64(bytes.From),
		BytesMax:      int64(bytes.To),
		Lanes:         lanes,
		MaxRate:       maxRate,
		Ports:         ports,
		Password:      c.Password,
		Grace:         int64(grace),
		Idle:          int64(idle),
		MaxLife:       int64(maxLife),
		Sndbuf:        c.Sndbuf,
		MaxLanesPerIp: orDefault(c.MaxLanesPerIP, 1024),
		DownLife:      int64(downLife),
		Flush:         int64(flush),
	}, nil
}

// QUICTCPConfig is "quictcpSettings": the quic transport's own settings plus
// the tcplane options, in one object.
type QUICTCPConfig struct {
	QUICConfig
	TCPLane
}
