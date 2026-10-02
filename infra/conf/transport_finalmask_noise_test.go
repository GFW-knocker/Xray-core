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

// Noise "exp" (upstream #6862), adapted to the fork's rules: "rand" may
// follow the pattern, "gen" may not.

func expPacket(exp string) json.RawMessage {
	b, _ := json.Marshal(exp)
	return b
}

func buildNoiseExp(exp string) (*noise.Config, error) {
	msg, err := (&NoiseMask{Noise: []NoiseItem{{Type: "exp", Packet: expPacket(exp)}}}).Build()
	if err != nil {
		return nil, err
	}
	return msg.(*noise.Config), nil
}

func TestNoiseExp(t *testing.T) {
	cfg, err := buildNoiseExp("<b 0d0a0d0a><t><r 24><rc 20-40><rd 8><c><n>")
	if err != nil {
		t.Fatal(err)
	}
	segments := cfg.Items[0].Segments
	if len(segments) != 7 {
		t.Fatalf("got %d segments, want 7", len(segments))
	}
	want := []struct {
		kind     noise.Segment_Kind
		bytes    []byte
		min, max int64
	}{
		{noise.Segment_BYTES, []byte{0x0d, 0x0a, 0x0d, 0x0a}, 0, 0},
		{noise.Segment_TIMESTAMP, nil, 0, 0},
		{noise.Segment_RANDOM, nil, 24, 24},
		{noise.Segment_RANDOM_ASCII, nil, 20, 40},
		{noise.Segment_RANDOM_DIGIT, nil, 8, 8},
		{noise.Segment_COUNTER, nil, 0, 0},
		{noise.Segment_NONCE, nil, 0, 0},
	}
	for i, w := range want {
		s := segments[i]
		if s.Kind != w.kind || s.MinSize != w.min || s.MaxSize != w.max || string(s.Bytes) != string(w.bytes) {
			t.Errorf("segment %d = %+v, want %+v", i, s, w)
		}
	}
}

func TestNoiseExpStripsHexPrefix(t *testing.T) {
	cfg, err := buildNoiseExp("<b 0x16030100>")
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Items[0].Segments[0].Bytes; string(got) != string([]byte{0x16, 0x03, 0x01, 0x00}) {
		t.Errorf("got %x", got)
	}
}

func TestNoiseExpWhitespace(t *testing.T) {
	if _, err := buildNoiseExp("  <b 00>  <t>  "); err != nil {
		t.Errorf("surrounding whitespace should be allowed: %v", err)
	}
	cfg, err := buildNoiseExp("<b 0d 0a 0d 0a>")
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Items[0].Segments[0].Bytes; string(got) != "\r\n\r\n" {
		t.Errorf("got %x", got)
	}
}

func TestNoiseExpRejects(t *testing.T) {
	for _, exp := range []string{
		"<x 1>",
		"<b>",
		"<b zz>",
		"<b 0d0>",
		"<r>",
		"<r -1>",
		"<r 40-20>",
		"<r 70000>",
		"<t 5>",
		"<n 5>",
		"garbage<t>",
		"<t> tail",
		"<t><b>",
	} {
		if _, err := buildNoiseExp(exp); err == nil {
			t.Errorf("expected an error for %q", exp)
		}
	}
}

func TestNoiseExpConflicts(t *testing.T) {
	// GFW-knocker: unlike upstream, "rand" may follow an exp pattern, the same
	// way it follows "packet" or "gen"
	msg, err := (&NoiseMask{Noise: []NoiseItem{{Type: "exp", Packet: expPacket("<t>"), Rand: Int32Range{From: 10, To: 20}}}}).Build()
	if err != nil {
		t.Fatal("exp with rand should be accepted: ", err)
	}
	if item := msg.(*noise.Config).Items[0]; len(item.Segments) != 1 || item.RandMin != 10 || item.RandMax != 20 || len(item.Packet) != 0 {
		t.Errorf("exp with rand = %+v", item)
	}
	// "gen" is a head of its own, like the pattern
	if _, err := (&NoiseMask{Noise: []NoiseItem{{Type: "exp", Packet: expPacket("<t>"), Gen: noise.GenQUIC}}}).Build(); err == nil {
		t.Error("exp with gen should be rejected")
	}
	for _, packet := range []string{``, `[1, 2]`, `5`} {
		if _, err := (&NoiseMask{Noise: []NoiseItem{{Type: "exp", Packet: json.RawMessage(packet)}}}).Build(); err == nil {
			t.Errorf("expected an error for packet %q", packet)
		}
	}
}

func TestNoiseExpFromJSON(t *testing.T) {
	var mask NoiseMask
	if err := json.Unmarshal([]byte(`{"noise": [
		{"type": "exp", "packet": "<b 504f5354><rd 10-20>", "delay": "1-3"},
		{"type": "EXP", "packet": "<t>"},
		{"type": "str", "packet": "<t>"},
		{"rand": "10-20"}
	]}`), &mask); err != nil {
		t.Fatal(err)
	}
	msg, err := mask.Build()
	if err != nil {
		t.Fatal(err)
	}
	items := msg.(*noise.Config).Items
	if len(items[0].Segments) != 2 || items[0].DelayMin != 1 || items[0].DelayMax != 3 {
		t.Errorf("item 0 = %+v", items[0])
	}
	if len(items[1].Segments) != 1 || items[1].Segments[0].Kind != noise.Segment_TIMESTAMP {
		t.Errorf("item 1 = %+v", items[1])
	}
	if len(items[2].Segments) != 0 || string(items[2].Packet) != "<t>" {
		t.Errorf("item 2 = %+v", items[2])
	}
	if len(items[3].Segments) != 0 || items[3].RandMin != 10 || items[3].RandMax != 20 {
		t.Errorf("item 3 = %+v", items[3])
	}
}
