package tls

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	gonet "net"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"
)

func echTestConfig(list []byte, cacheKey string) *tls.Config {
	c := &tls.Config{EncryptedClientHelloConfigList: list}
	c.Rand = &RandCarrier{Config: c, ECHCacheKey: cacheKey}
	return c
}

func TestEchPublicNameFromConfigList(t *testing.T) {
	for _, name := range []string{"cloudflare-ech.com", "a.io", strings.Repeat("x", 200) + ".com"} {
		list, err := bogusECHConfigList(name)
		if err != nil {
			t.Fatal(err)
		}
		if got := echPublicNameFromConfigList(list); got != name {
			t.Errorf("got %q, want %q", got, name)
		}
	}
	for _, bad := range [][]byte{nil, {}, {0x00, 0x04, 0xfe, 0x0d}, failClosedECHConfig} {
		if got := echPublicNameFromConfigList(bad); got != "" {
			t.Errorf("malformed list yielded %q", got)
		}
	}
}

func TestRefineECHErrorPassthrough(t *testing.T) {
	boring := errors.New("connection reset by peer")
	list, _ := bogusECHConfigList("cloudflare-ech.com")

	// nil error, no ECH, and unrelated failures must all come back untouched.
	if got := RefineECHError(echTestConfig(list, "k"), nil, nil); got != nil {
		t.Error("nil error was rewritten")
	}
	if got := RefineECHError(&tls.Config{}, nil, boring); got != boring {
		t.Error("non-ECH config had its error rewritten")
	}
	if got := RefineECHError(nil, nil, boring); got != boring {
		t.Error("nil config had its error rewritten")
	}
	if got := RefineECHError(echTestConfig(list, "k"), nil, boring); got != boring {
		t.Error("unrelated error was rewritten")
	}
}

func TestRefineECHErrorFailClosed(t *testing.T) {
	cfg := echTestConfig(failClosedECHConfig, "")
	got := RefineECHError(cfg, nil, errors.New("tls: malformed ECHConfigList"))
	if !strings.Contains(got.Error(), "no ECH config could be obtained") {
		t.Errorf("placeholder not explained, got: %v", got)
	}
}

func TestRefineECHErrorRejectionInvalidatesCache(t *testing.T) {
	const key = "probe://test.invalid:443|test.invalid|test"
	cache := &ECHConfigCache{}
	cache.configRecord.Store(&echConfigRecord{
		config: []byte("stale"),
		expire: time.Now().Add(time.Hour),
	})
	GlobalECHConfigCache.Store(key, cache)
	defer GlobalECHConfigCache.Delete(key)

	list, _ := bogusECHConfigList("cloudflare-ech.com")
	cfg := echTestConfig(list, key)
	got := RefineECHError(cfg, nil, &tls.ECHRejectionError{RetryConfigList: list})

	if !strings.Contains(got.Error(), "ECH rejected") {
		t.Errorf("rejection not explained, got: %v", got)
	}
	if !strings.Contains(got.Error(), "offered replacement keys") {
		t.Errorf("retry_configs not mentioned, got: %v", got)
	}
	if rec := cache.configRecord.Load(); !rec.expire.IsZero() {
		t.Error("cache entry was not invalidated, so the next dial would reuse the stale config")
	}
}

// The two stack bugs that hide a rejection behind a different error.
func TestRefineECHErrorRecognisesMaskedRejections(t *testing.T) {
	const key = "probe://masked.invalid:443|masked.invalid|test"
	list, _ := bogusECHConfigList("cloudflare-ech.com")

	masked := []error{
		// uTLS validates the rejection cert against the inner name
		&tls.CertificateVerificationError{Err: errors.New(
			"x509: certificate is valid for cloudflare-ech.com, *.cloudflare-ech.com, not example.com")},
		// ALPN negotiated from the wider outer hello (ws/httpupgrade)
		errors.New("tls: server selected unadvertised ALPN protocol"),
		errors.New("tls: server advertised unrequested ALPN extension"),
	}
	for _, err := range masked {
		cache := &ECHConfigCache{}
		cache.configRecord.Store(&echConfigRecord{config: []byte("stale"), expire: time.Now().Add(time.Hour)})
		GlobalECHConfigCache.Store(key, cache)

		got := RefineECHError(echTestConfig(list, key), nil, err)
		if !strings.Contains(got.Error(), "ECH rejected") {
			t.Errorf("masked rejection %v not recognised, got: %v", err, got)
		}
		if rec := cache.configRecord.Load(); !rec.expire.IsZero() {
			t.Errorf("cache not invalidated for %v", err)
		}
		GlobalECHConfigCache.Delete(key)
	}
}

// A real certificate problem on an ECH-accepted connection must stay itself.
func TestRefineECHErrorKeepsGenuineCertErrors(t *testing.T) {
	list, _ := bogusECHConfigList("cloudflare-ech.com")
	genuine := &tls.CertificateVerificationError{Err: errors.New(
		"x509: certificate has expired or is not yet valid")}
	if got := RefineECHError(echTestConfig(list, "k"), nil, genuine); got != error(genuine) {
		t.Errorf("genuine certificate error was misreported as an ECH rejection: %v", got)
	}
}

func TestRefineECHErrorPinnedConfigCannotRefresh(t *testing.T) {
	list, _ := bogusECHConfigList("cloudflare-ech.com")
	got := RefineECHError(echTestConfig(list, ""), nil, &tls.ECHRejectionError{})
	if !strings.Contains(got.Error(), "cannot refresh itself") {
		t.Errorf("pinned-config case not explained, got: %v", got)
	}
}

// TestECHSelfHealAgainstLiveServer exercises the whole loop on a real server:
// poison the cache with a config the server will refuse, dial, and confirm the
// error is recognised through the real uTLS stack, the entry is dropped, and the
// next dial re-probes and succeeds. Network test, same as TestECHDial.
func TestECHSelfHealAgainstLiveServer(t *testing.T) {
	const spec = "probe://cloudflare-ech.com"
	cfg := &Config{ServerName: "cloudflare.com", EchConfigList: spec}

	// 1. cold probe populates the cache
	good := cfg.GetTLSConfig(WithNextProto("h2", "http/1.1"))
	if isFailClosedECHConfig(good.EncryptedClientHelloConfigList) {
		t.Fatal("initial probe failed")
	}
	key := echCacheKeyOf(good)
	if key == "" {
		t.Fatal("no cache key recorded on the tls.Config")
	}
	cache, ok := GlobalECHConfigCache.Load(key)
	if !ok {
		t.Fatalf("cache entry %q missing", key)
	}

	// 2. poison it with a config the server cannot decrypt, as a rotation would
	stale, err := bogusECHConfigList("cloudflare-ech.com")
	if err != nil {
		t.Fatal(err)
	}
	cache.configRecord.Store(&echConfigRecord{config: stale, expire: time.Now().Add(time.Hour)})

	// 3. dial with the poisoned config through the same path a transport uses
	poisoned := cfg.GetTLSConfig(WithNextProto("h2", "http/1.1"))
	raw, err := (&gonet.Dialer{Timeout: 10 * time.Second}).Dial("tcp", "cloudflare.com:443")
	if err != nil {
		t.Skip("no network: ", err)
	}
	raw.SetDeadline(time.Now().Add(15 * time.Second))
	uc := UClient(raw, poisoned, GetFingerprint("chrome")).(*UConn)
	hsErr := uc.HandshakeContext(context.Background())
	raw.Close()
	if hsErr == nil {
		t.Fatal("handshake unexpectedly succeeded with a bogus ECH key")
	}
	t.Logf("raw stack error: %v", hsErr)

	refined := RefineECHError(poisoned, uc, hsErr)
	t.Logf("refined error:   %v", refined)
	if !strings.Contains(refined.Error(), "ECH rejected") {
		t.Errorf("real-world rejection not recognised: %v", refined)
	}

	// 4. the entry must be gone, and the next dial must re-probe and work
	if rec := cache.configRecord.Load(); !rec.expire.IsZero() {
		t.Fatal("cache was not invalidated")
	}
	healed := cfg.GetTLSConfig(WithNextProto("h2", "http/1.1"))
	if isFailClosedECHConfig(healed.EncryptedClientHelloConfigList) {
		t.Fatal("re-probe after invalidation failed")
	}
	if slices.Equal(healed.EncryptedClientHelloConfigList, stale) {
		t.Fatal("re-probe returned the poisoned config")
	}

	// plain http.Transport does not speak h2, so keep the negotiation to 1.1
	healed.NextProtos = []string{"http/1.1"}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: healed}}
	resp, err := client.Get("https://cloudflare.com/cdn-cgi/trace")
	if err != nil {
		t.Fatal("dial after self-heal failed: ", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "sni=encrypted") {
		t.Error("healed connection did not use ECH")
	}
}

// fakeECHConn reports a fixed ECH acceptance state, standing in for a TLS
// connection whose handshake has already failed.
type fakeECHConn struct {
	gonet.Conn
	accepted bool
}

func (f fakeECHConn) ECHAccepted() bool { return f.accepted }

// Asking the connection is exact where matching the error text was a guess.
func TestRefineECHErrorUsesConnectionState(t *testing.T) {
	list, _ := bogusECHConfigList("cover.example")
	// A self-signed server produces this, and it names nothing we could match on.
	unknownCA := &tls.CertificateVerificationError{Err: errors.New(
		"x509: certificate signed by unknown authority")}

	// ECH refused: recognised, even though the message mentions no name.
	got := RefineECHError(echTestConfig(list, ""), fakeECHConn{accepted: false}, unknownCA)
	if !strings.Contains(got.Error(), "ECH rejected") {
		t.Errorf("rejection with an unknown-authority error not recognised: %v", got)
	}

	// ECH accepted: the very same error is a real certificate problem.
	got = RefineECHError(echTestConfig(list, ""), fakeECHConn{accepted: true}, unknownCA)
	if got != error(unknownCA) {
		t.Errorf("genuine certificate error on an ECH-accepted connection was rewritten: %v", got)
	}

	// Without a connection the old text matching still applies, and this
	// message does not mention our public name, so it stays untouched.
	if got := RefineECHError(echTestConfig(list, ""), nil, unknownCA); got != error(unknownCA) {
		t.Errorf("no-connection fallback misfired: %v", got)
	}
}

// A failure before the server was even heard from must never be blamed on ECH,
// even though ECHAccepted is false for it too.
func TestRefineECHErrorIgnoresEarlyFailures(t *testing.T) {
	list, _ := bogusECHConfigList("cover.example")
	for _, err := range []error{
		errors.New("connection reset by peer"),
		errors.New("i/o timeout"),
		errors.New("EOF"),
	} {
		if got := RefineECHError(echTestConfig(list, ""), fakeECHConn{accepted: false}, err); got != err {
			t.Errorf("early failure %v was misreported as an ECH rejection: %v", err, got)
		}
	}
}
