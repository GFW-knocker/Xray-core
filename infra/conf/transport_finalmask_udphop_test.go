package conf

import (
	"encoding/json"
	"testing"

	"github.com/GFW-knocker/Xray-core/transport/internet/finalmask/udphop"
)

func buildUDPHop(t *testing.T, raw string) (*udphop.Config, error) {
	t.Helper()
	hop := new(UDPHop)
	if err := json.Unmarshal([]byte(raw), hop); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	built, err := hop.Build()
	if err != nil {
		return nil, err
	}
	return built.(*udphop.Config), nil
}

func TestUDPHopPacketLocal(t *testing.T) {
	for _, tc := range []struct {
		raw      string
		min, max int64
	}{
		{`{"mode": "packetLocal"}`, 6, 10},
		{`{"mode": "packetLocal", "packets": 8}`, 8, 8},
		{`{"mode": "packetLocal", "packets": "4-12"}`, 4, 12},
		{`{"mode": "packetLocal,intervalRemote", "remotePorts": "2000-2010"}`, 6, 10},
	} {
		c, err := buildUDPHop(t, tc.raw)
		if err != nil {
			t.Fatalf("%s: %v", tc.raw, err)
		}
		if !c.PacketLocal || c.Local || c.PacketsMin != tc.min || c.PacketsMax != tc.max {
			t.Errorf("%s: got packetLocal=%v local=%v packets=%d-%d, want true false %d-%d",
				tc.raw, c.PacketLocal, c.Local, c.PacketsMin, c.PacketsMax, tc.min, tc.max)
		}
		// the interval keeps its default, so NewUDPHopConn's check still passes
		if c.IntervalMin < 5 || c.IntervalMax < 5 {
			t.Errorf("%s: interval %d-%d", tc.raw, c.IntervalMin, c.IntervalMax)
		}
	}
}

func TestUDPHopPacketLocalRejected(t *testing.T) {
	for _, raw := range []string{
		`{"mode": "packetLocal,intervalLocal"}`,
		`{"mode": "packetLocal", "packets": "0-5"}`,
		`{"mode": "intervalLocal", "packets": 8}`,
	} {
		if _, err := buildUDPHop(t, raw); err == nil {
			t.Errorf("%s: built, want an error", raw)
		}
	}
}

// The existing modes must build exactly as before.
func TestUDPHopIntervalUnchanged(t *testing.T) {
	c, err := buildUDPHop(t, `{"mode": "intervalLocal"}`)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Local || c.PacketLocal || c.PacketsMin != 0 || c.PacketsMax != 0 || c.IntervalMin != 30 || c.IntervalMax != 30 {
		t.Errorf("got %+v", c)
	}
}
