package conf

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/GFW-knocker/Xray-core/transport/internet/finalmask/noise"
)

func buildNoise(t *testing.T, raw string) (*noise.Config, error) {
	t.Helper()
	mask := new(NoiseMask)
	if err := json.Unmarshal([]byte(raw), mask); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	built, err := mask.Build()
	if err != nil {
		return nil, err
	}
	return built.(*noise.Config), nil
}

func TestNoiseGenBuild(t *testing.T) {
	config, err := buildNoise(t, `{
		"reset": "60-120",
		"noise": [
			{ "gen": "quicinit", "delay": 5 },
			{ "gen": "quic", "rand": "5-10" },
			{ "gen": "quicv1" }
		]
	}`)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(config.Items) != 3 {
		t.Fatalf("got %d items, want 3", len(config.Items))
	}
	if config.Items[0].Gen != noise.GenQUICInit || config.Items[0].DelayMin != 5 {
		t.Errorf("item 0 = %+v", config.Items[0])
	}
	if config.Items[1].Gen != noise.GenQUIC || config.Items[1].RandMin != 5 || config.Items[1].RandMax != 10 {
		t.Errorf("item 1 = %+v", config.Items[1])
	}
	if config.Items[2].Gen != noise.GenQUICv1 {
		t.Errorf("item 2 = %+v", config.Items[2])
	}
	// A generator fills the head of the datagram, so no literal comes with it.
	for i, item := range config.Items {
		if len(item.Packet) != 0 {
			t.Errorf("item %d carries a packet alongside gen: %x", i, item.Packet)
		}
	}
}

func TestNoiseGenRejections(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want string
	}{
		{
			"unknown gen",
			`{"noise": [{"gen": "quicv3"}]}`,
			"unknown gen",
		},
		{
			"gen with packet",
			`{"noise": [{"gen": "quic", "type": "hex", "packet": "d0"}]}`,
			"mutually exclusive",
		},
		{
			// quicinit is only a prime because it is 1200 bytes; appending to
			// it destroys the property, so it must not be accepted quietly.
			"quicinit with rand",
			`{"noise": [{"gen": "quicinit", "rand": "5-10"}]}`,
			"fixed size",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := buildNoise(t, tc.raw)
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestNoiseLiteralAndRandStillBuild(t *testing.T) {
	// The two pre-generator shapes must be unchanged, and packet+rand -- which
	// used to be rejected outright -- now means literal head plus payload.
	config, err := buildNoise(t, `{
		"noise": [
			{ "rand": 18 },
			{ "type": "hex", "packet": "d06b3343cf" },
			{ "type": "hex", "packet": "d06b3343cf", "rand": "5-10" }
		]
	}`)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if config.Items[0].RandMin != 18 || config.Items[0].RandMax != 18 || len(config.Items[0].Packet) != 0 {
		t.Errorf("item 0 = %+v", config.Items[0])
	}
	if got := config.Items[1]; len(got.Packet) != 5 || got.Packet[0] != 0xd0 || got.RandMax != 0 {
		t.Errorf("item 1 = %+v", got)
	}
	if got := config.Items[2]; len(got.Packet) != 5 || got.RandMin != 5 || got.RandMax != 10 {
		t.Errorf("item 2 = %+v", got)
	}
	// randRange defaults to the full byte range for every shape.
	for i, item := range config.Items {
		if item.RandRangeMin != 0 || item.RandRangeMax != 255 {
			t.Errorf("item %d randRange = %d-%d, want 0-255", i, item.RandRangeMin, item.RandRangeMax)
		}
	}
}

func TestNoiseMaskThroughUDPLoader(t *testing.T) {
	// The mask is reachable as finalmask.udp[].type == "noise", so a gen config
	// has to survive the real loader, not just NoiseMask.Build directly.
	var mask Mask
	if err := json.Unmarshal([]byte(`{
		"type": "noise",
		"settings": { "noise": [{ "gen": "quicinit" }] }
	}`), &mask); err != nil {
		t.Fatalf("unmarshal mask: %v", err)
	}
	built, err := mask.Build(false)
	if err != nil {
		t.Fatalf("build udp mask: %v", err)
	}
	config, ok := built.(*noise.Config)
	if !ok {
		t.Fatalf("settings are %T, want *noise.Config", built)
	}
	if len(config.Items) != 1 || config.Items[0].Gen != noise.GenQUICInit {
		t.Fatalf("items = %+v", config.Items)
	}

	// noise is registered in udpmaskLoader only; it is not a TCP mask.
	if _, err := mask.Build(true); err == nil {
		t.Error("noise built as a TCP mask, want an error")
	}
}
