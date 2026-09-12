package conf_test

import (
	"encoding/json"
	"testing"

	. "github.com/GFW-knocker/Xray-core/infra/conf"
	"github.com/GFW-knocker/Xray-core/transport/internet/reality"
	"github.com/GFW-knocker/Xray-core/transport/internet/tls"
	utls "github.com/refraction-networking/utls"
)

func buildRealityClient(t *testing.T, fingerprint string) *reality.Config {
	t.Helper()
	raw := `{"show":false,"fingerprint":"` + fingerprint + `",` +
		`"serverName":"www.google.com",` +
		`"publicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",` +
		`"shortId":"0123456789abcdef","spiderX":"/"}`
	c := new(REALITYConfig)
	if err := json.Unmarshal([]byte(raw), c); err != nil {
		t.Fatalf("%s: unmarshal: %v", fingerprint, err)
	}
	m, err := c.Build()
	if err != nil {
		t.Fatalf("%s: build: %v", fingerprint, err)
	}
	return m.(*reality.Config)
}

// A fingerprint a current REALITY server can never verify is replaced.
func TestREALITYFingerprintFallback(t *testing.T) {
	for _, fp := range []string{"ios", "edge", "qq", "android", "360"} {
		if got := buildRealityClient(t, fp).Fingerprint; got != "chrome" {
			t.Errorf("%s: got %q, want %q", fp, got, "chrome")
		}
	}
}

// A usable fingerprint is left exactly as configured -- including the version
// pins and aliases outside the chrome/firefox/safari shortlist.
func TestREALITYFingerprintKeptWhenUsable(t *testing.T) {
	for _, fp := range []string{
		"chrome", "firefox", "safari",
		"hellochrome_131", "hellochrome_133", "hellofirefox_148", "hellosafari_26_3",
		"hellochrome_auto", "hellofirefox_auto", "hellosafari_auto",
	} {
		if got := buildRealityClient(t, fp).Fingerprint; got != fp {
			t.Errorf("%s: rewritten to %q, want it left alone", fp, got)
		}
	}
}

// Whatever survives Build must be usable, for every fingerprint name REALITY
// accepts. This is what pins down "random", which is drawn from
// ModernFingerprints at init and can otherwise differ between restarts.
func TestREALITYFingerprintAlwaysUsable(t *testing.T) {
	maps := []map[string]*utls.ClientHelloID{
		tls.PresetFingerprints, tls.ModernFingerprints, tls.OtherFingerprints,
	}
	for _, m := range maps {
		for name := range m {
			if name == "unsafe" || name == "hellogolang" {
				continue // REALITY rejects these outright
			}
			got := buildRealityClient(t, name).Fingerprint
			id := tls.GetFingerprint(got)
			if id == nil {
				t.Errorf("%s: resolved to unknown fingerprint %q", name, got)
				continue
			}
			if !tls.GuaranteesX25519MLKEM768(id) {
				t.Errorf("%s: resolved to %q, which cannot guarantee an X25519MLKEM768 key share", name, got)
			}
		}
	}
}
