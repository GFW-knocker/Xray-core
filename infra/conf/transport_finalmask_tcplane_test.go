package conf

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/GFW-knocker/Xray-core/transport/internet/finalmask/salamander"
	"github.com/GFW-knocker/Xray-core/transport/internet/finalmask/tcplane"
	"github.com/GFW-knocker/Xray-core/transport/internet/hysteria"
	"github.com/GFW-knocker/Xray-core/transport/internet/quic"
)

func buildStream(t *testing.T, raw string) (*StreamConfigResult, error) {
	t.Helper()
	sc := new(StreamConfig)
	if err := json.Unmarshal([]byte(raw), sc); err != nil {
		t.Fatalf("unmarshal %s: %v", raw, err)
	}
	built, err := sc.Build()
	if err != nil {
		return nil, err
	}
	res := &StreamConfigResult{Protocol: built.ProtocolName}
	for _, ts := range built.TransportSettings {
		res.Transports = append(res.Transports, ts.ProtocolName)
		if ts.ProtocolName == "quic" {
			inst, err := ts.Settings.GetInstance()
			if err != nil {
				t.Fatal(err)
			}
			res.Quic = inst.(*quic.Config)
		}
	}
	for _, m := range built.Udpmasks {
		inst, err := m.GetInstance()
		if err != nil {
			t.Fatal(err)
		}
		res.UDPMasks = append(res.UDPMasks, inst)
	}
	return res, nil
}

type StreamConfigResult struct {
	Protocol   string
	Transports []string
	Quic       *quic.Config
	UDPMasks   []any
}

func TestQUICTCPBuildsQuicWithTCPLane(t *testing.T) {
	res, err := buildStream(t, `{
		"network": "quictcp",
		"quictcpSettings": {"key": "k", "security": "chacha20-poly1305", "packets": "4-6", "lifeMs": 700, "ports": "3000-3002", "password": "p"},
		"finalmask": {"udp": [{"type": "salamander", "settings": {"password": "s"}}]}
	}`)
	if err != nil {
		t.Fatal(err)
	}
	if res.Protocol != "quic" || len(res.Transports) != 1 || res.Transports[0] != "quic" {
		t.Fatalf("protocol %q transports %v, want quic", res.Protocol, res.Transports)
	}
	if res.Quic.Key != "k" {
		t.Errorf("quic key %q, want k", res.Quic.Key)
	}
	if len(res.UDPMasks) != 2 {
		t.Fatalf("%d udp masks, want salamander then tcplane", len(res.UDPMasks))
	}
	if _, ok := res.UDPMasks[0].(*salamander.Config); !ok {
		t.Errorf("first mask %T, want the user's salamander", res.UDPMasks[0])
	}
	lane, ok := res.UDPMasks[1].(*tcplane.Config)
	if !ok {
		t.Fatalf("last mask %T, want tcplane", res.UDPMasks[1])
	}
	if lane.PacketsMin != 4 || lane.PacketsMax != 6 || lane.LifeMin != 700 || lane.LifeMax != 700 ||
		len(lane.Ports) != 3 || lane.Password != "p" {
		t.Errorf("tcplane settings not carried over: %+v", lane)
	}
}

func TestQUICTCPDefaults(t *testing.T) {
	res, err := buildStream(t, `{"network": "quictcp"}`)
	if err != nil {
		t.Fatal(err)
	}
	lane := res.UDPMasks[0].(*tcplane.Config)
	if lane.PacketsMin != 8 || lane.PacketsMax != 12 || lane.LifeMin != 800 || lane.LifeMax != 1200 ||
		lane.BytesMin != 12288 || lane.BytesMax != 16384 || lane.Lanes != 24 || lane.MaxRate != 50 ||
		lane.Grace != 2000 || lane.Idle != 20000 || lane.MaxLife != 60000 || lane.MaxLanesPerIp != 1024 ||
		lane.DownLife != 3000 || lane.Flush != 10 {
		t.Errorf("defaults: %+v", lane)
	}
}

func TestQUICTCPUsesBBR(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{`{"network": "quictcp"}`, "bbr"},
		{`{"network": "quictcp", "finalmask": {"quicParams": {"congestion": "reno"}}}`, "reno"},
		{`{"network": "quictcp", "finalmask": {"quicParams": {"brutalUp": "10 mbps"}}}`, "bbr"},
	} {
		sc := new(StreamConfig)
		if err := json.Unmarshal([]byte(tc.raw), sc); err != nil {
			t.Fatal(err)
		}
		built, err := sc.Build()
		if err != nil {
			t.Fatal(err)
		}
		if built.QuicParams == nil || built.QuicParams.Congestion != tc.want {
			t.Errorf("%s: quicParams %+v, want congestion %s", tc.raw, built.QuicParams, tc.want)
		}
	}
	// plain quic is left alone
	sc := new(StreamConfig)
	json.Unmarshal([]byte(`{"network": "quic"}`), sc)
	built, err := sc.Build()
	if err != nil || built.QuicParams != nil {
		t.Errorf("plain quic: quicParams %+v err %v, want none", built.QuicParams, err)
	}
}

func TestQUICTCPRejects(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{`{"network": "quictcp", "quicSettings": {}}`, "quicSettings"},
		{`{"network": "quic", "quictcpSettings": {}}`, "quictcpSettings"},
		{`{"network": "quictcp", "finalmask": {"udp": [{"type": "tcplane"}]}}`, "already carries"},
		{`{"network": "quictcp", "quictcpSettings": {"packets": 0, "lanes": 100}}`, "lanes"},
	} {
		_, err := buildStream(t, tc.raw)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err %v, want one mentioning %q", tc.raw, err, tc.want)
		}
	}
}

// Old configs are untouched: plain quic gets no mask, and a tcplane mask is
// only there when asked for.
func TestPlainQuicHasNoLaneMask(t *testing.T) {
	res, err := buildStream(t, `{"network": "quic", "quicSettings": {"key": "k"}}`)
	if err != nil {
		t.Fatal(err)
	}
	if res.Protocol != "quic" || len(res.UDPMasks) != 0 {
		t.Fatalf("protocol %q masks %v", res.Protocol, res.UDPMasks)
	}
	res, err = buildStream(t, `{"network": "hysteria", "finalmask": {"udp": [{"type": "tcplane", "settings": {"bytes": -1}}]}}`)
	if err != nil {
		t.Fatal(err)
	}
	lane := res.UDPMasks[0].(*tcplane.Config)
	if res.Protocol != "hysteria" || lane.BytesMin != 0 || lane.BytesMax != 0 {
		t.Fatalf("hysteria with tcplane: protocol %q lane %+v", res.Protocol, lane)
	}
}

func TestHYTCPBuildsHysteriaWithTCPLane(t *testing.T) {
	sc := new(StreamConfig)
	raw := `{
		"network": "hytcp",
		"security": "tls",
		"hytcpSettings": {"auth": "pw", "udpIdleTimeout": 60, "lanes": 12, "bytes": "8000-9000", "ports": "4000-4003", "password": "lp"},
		"finalmask": {"udp": [{"type": "salamander", "settings": {"password": "s"}}]}
	}`
	if err := json.Unmarshal([]byte(raw), sc); err != nil {
		t.Fatal(err)
	}
	built, err := sc.Build()
	if err != nil {
		t.Fatal(err)
	}
	if built.ProtocolName != "hysteria" || len(built.TransportSettings) != 1 || built.TransportSettings[0].ProtocolName != "hysteria" {
		t.Fatalf("protocol %q transports %v, want hysteria", built.ProtocolName, built.TransportSettings)
	}
	inst, err := built.TransportSettings[0].Settings.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	hc := inst.(*hysteria.Config)
	if hc.Auth != "pw" || hc.UdpIdleTimeout != 60 {
		t.Errorf("hysteria settings not carried over: %+v", hc)
	}
	if len(built.Udpmasks) != 2 {
		t.Fatalf("%d udp masks, want salamander then tcplane", len(built.Udpmasks))
	}
	m0, _ := built.Udpmasks[0].GetInstance()
	m1, _ := built.Udpmasks[1].GetInstance()
	if _, ok := m0.(*salamander.Config); !ok {
		t.Errorf("first mask %T, want salamander", m0)
	}
	lane, ok := m1.(*tcplane.Config)
	if !ok {
		t.Fatalf("last mask %T, want tcplane", m1)
	}
	if lane.Lanes != 12 || lane.BytesMin != 8000 || lane.BytesMax != 9000 || len(lane.Ports) != 4 || lane.Password != "lp" {
		t.Errorf("lane settings not carried over: %+v", lane)
	}
	if built.QuicParams == nil || built.QuicParams.Congestion != "bbr" {
		t.Errorf("quicParams %+v, want congestion bbr", built.QuicParams)
	}
}

func TestHYTCPRejectsAndKeepsHysteria(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{`{"network": "hytcp", "hysteriaSettings": {"version": 2}}`, "hytcpSettings"},
		{`{"network": "hysteria", "hytcpSettings": {}}`, "hytcpSettings"},
		{`{"network": "hytcp", "finalmask": {"udp": [{"type": "tcplane"}]}}`, "already carries"},
		{`{"network": "hytcp", "hytcpSettings": {"version": 1}}`, "version"},
	} {
		_, err := buildStream(t, tc.raw)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err %v, want one mentioning %q", tc.raw, err, tc.want)
		}
	}
	// plain hysteria: no lane mask and hysteria's own congestion default
	sc := new(StreamConfig)
	json.Unmarshal([]byte(`{"network": "hysteria", "hysteriaSettings": {"version": 2}}`), sc)
	built, err := sc.Build()
	if err != nil || built.ProtocolName != "hysteria" || len(built.Udpmasks) != 0 || built.QuicParams != nil {
		t.Errorf("plain hysteria changed: %+v err %v", built, err)
	}
	// an explicit congestion choice is kept
	sc = new(StreamConfig)
	json.Unmarshal([]byte(`{"network": "hytcp", "finalmask": {"quicParams": {"congestion": "force-brutal", "brutalUp": "1 mbps"}}}`), sc)
	built, err = sc.Build()
	if err != nil || built.QuicParams.Congestion != "force-brutal" {
		t.Errorf("hytcp with force-brutal: %+v err %v", built.QuicParams, err)
	}
}
