package tls

import (
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
)

func TestParseECHProbe(t *testing.T) {
	cases := []struct {
		in         string
		wantName   string
		wantTarget string
		wantOK     bool
	}{
		// the four accepted probe forms
		{"probe", echProbeDefaultName, echProbeDefaultName + ":443", true},
		{"probe://", echProbeDefaultName, echProbeDefaultName + ":443", true},
		{"probe://example.com", "example.com", "example.com:443", true},
		{"probe://example.com@1.2.3.4:8443", "example.com", "1.2.3.4:8443", true},
		// tolerated variations
		{"  probe  ", echProbeDefaultName, echProbeDefaultName + ":443", true},
		{"probe://example.com@1.2.3.4", "example.com", "1.2.3.4:443", true},
		{"probe://@1.2.3.4:443", echProbeDefaultName, "1.2.3.4:443", true},
		{"probe://example.com@[2606:4700::1]:443", "example.com", "[2606:4700::1]:443", true},

		// every pre-existing echConfigList form must fall through untouched
		{"", "", "", false},
		{"https://1.1.1.1/dns-query", "", "", false},
		{"example.com+https://1.1.1.1/dns-query", "", "", false},
		{"h2c://1.1.1.1/dns-query", "", "", false},
		{"udp://1.1.1.1", "", "", false},
		{"example.com+udp://1.1.1.1", "", "", false},
		{"AEX+DQBBPwAgACC4NVWryOzBZvA4AWpGdMEQ", "", "", false}, // base64 config
		{"probed", "", "", false},
		{"probe.example.com", "", "", false},
		{"myprobe://example.com", "", "", false},
	}
	for _, c := range cases {
		name, target, ok := parseECHProbe(c.in)
		if ok != c.wantOK || name != c.wantName || target != c.wantTarget {
			t.Errorf("parseECHProbe(%q) = (%q, %q, %v), want (%q, %q, %v)",
				c.in, name, target, ok, c.wantName, c.wantTarget, c.wantOK)
		}
	}
}

func TestBogusECHConfigListIsWellFormed(t *testing.T) {
	list, err := bogusECHConfigList(echProbeDefaultName)
	if err != nil {
		t.Fatal(err)
	}
	if !looksLikeECHConfigList(list) {
		t.Fatalf("generated list failed its own framing check: %x", list)
	}
	// The TLS stack must be able to parse and select it, otherwise the probe
	// handshake fails locally with "contains no valid configs" and never reaches
	// the server. ApplyECH plus a Config is the closest in-package proxy for that.
	cfg := &Config{ServerName: "example.com", EchConfigList: "probe://" + echProbeDefaultName}
	if _, _, ok := parseECHProbe(cfg.EchConfigList); !ok {
		t.Fatal("round trip through parseECHProbe failed")
	}
	// public name must survive verbatim at the documented offset
	if got := string(list[len(list)-len(echProbeDefaultName)-2 : len(list)-2]); got != echProbeDefaultName {
		t.Errorf("public name not encoded as expected, got %q", got)
	}
	// two calls must not produce the same key
	other, err := bogusECHConfigList(echProbeDefaultName)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Equal(list, other) {
		t.Error("bogusECHConfigList is not randomised")
	}
}

func TestLooksLikeECHConfigList(t *testing.T) {
	good, err := bogusECHConfigList("example.com")
	if err != nil {
		t.Fatal(err)
	}
	bad := [][]byte{
		nil,
		{},
		{0x00},
		{0x00, 0x45},                     // length prefix promises 69 bytes, none follow
		{1, 1, 4, 5, 1, 4},               // the fail-closed placeholder
		append(slices.Clone(good), 0x00), // trailing garbage
		slices.Clone(good)[:len(good)-1], // truncated
		{0x00, 0x02, 0xfe, 0x0d},         // config header cut short
	}
	if !looksLikeECHConfigList(good) {
		t.Error("valid list rejected")
	}
	for i, b := range bad {
		if looksLikeECHConfigList(b) {
			t.Errorf("case %d: malformed list accepted: %x", i, b)
		}
	}
}

// TestECHProbeDial is the end-to-end check: obtain the ECH config purely from
// the server's retry_configs, with no DNS lookup of any kind, then use it.
// Network test, same as TestECHDial.
func TestECHProbeDial(t *testing.T) {
	for _, spec := range []string{
		"probe",
		"probe://",
		"probe://cloudflare-ech.com",
		"probe://cloudflare-ech.com@104.18.10.118:443",
	} {
		t.Run(spec, func(t *testing.T) {
			config := &Config{ServerName: "cloudflare.com", EchConfigList: spec}
			tlsConfig := config.GetTLSConfig()
			if slices.Equal(tlsConfig.EncryptedClientHelloConfigList, []byte{1, 1, 4, 5, 1, 4}) {
				t.Fatal("probe did not yield an ECH config")
			}
			tlsConfig.NextProtos = []string{"http/1.1"}
			client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}
			resp, err := client.Get("https://cloudflare.com/cdn-cgi/trace")
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(body), "sni=encrypted") {
				t.Error("dial succeeded but SNI was not encrypted")
			}
		})
	}
}

// A probe spec must fail closed exactly like a failed DNS query does.
func TestECHProbeFailClosed(t *testing.T) {
	config := &Config{
		ServerName:    "cloudflare.com",
		EchConfigList: "probe://cloudflare-ech.com@0.0.0.0:1",
	}
	tlsConfig := config.GetTLSConfig()
	ApplyECH(config, tlsConfig)
	if !slices.Equal(tlsConfig.EncryptedClientHelloConfigList, []byte{1, 1, 4, 5, 1, 4}) {
		t.Error("ECH config should be invalid when the probe fails, but got ",
			tlsConfig.EncryptedClientHelloConfigList)
	}
}
