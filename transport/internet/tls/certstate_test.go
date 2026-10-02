package tls

import (
	gotls "crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
	"weak"

	"github.com/GFW-knocker/Xray-core/common/protocol/tls/cert"
)

func countCertStates() int {
	n := 0
	certStates.Range(func(_, _ any) bool {
		n++
		return true
	})
	return n
}

// waitGoroutines waits for the goroutine count to drop to at most want.
func waitGoroutines(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		runtime.GC()
		if n := runtime.NumGoroutine(); n <= want {
			return
		}
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<20)
			t.Fatalf("goroutines: %d, want at most %d\n%s", runtime.NumGoroutine(), want, buf[:runtime.Stack(buf, true)])
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func generateLeaf(t *testing.T, name string) *cert.Certificate {
	t.Helper()
	ct, err := cert.Generate(nil, cert.DNSNames(name), cert.CommonName(name))
	if err != nil {
		t.Fatal(err)
	}
	return ct
}

func writePEM(t *testing.T, dir string, c *cert.Certificate) (certPath, keyPath string) {
	t.Helper()
	certPEM, keyPEM := c.ToPEM()
	certPath, keyPath = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func servedName(t *testing.T, tlsConfig *gotls.Config, sni string) string {
	t.Helper()
	c, err := tlsConfig.GetCertificate(&gotls.ClientHelloInfo{ServerName: sni})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf.Subject.CommonName
}

// GetTLSConfig runs on every dial. It used to start a reload goroutine (and
// re-parse the key pair) per call, so a config with a certificate leaked one
// goroutine per connection.
func TestCertStateNoGoroutinePerDial(t *testing.T) {
	c := &Config{Certificate: []*Certificate{ParseCertificate(generateLeaf(t, "a.example"))}}
	waitGoroutines(t, runtime.NumGoroutine())
	before := runtime.NumGoroutine()

	for i := 0; i < 1000; i++ {
		tlsConfig := c.GetTLSConfig()
		if i == 0 {
			if got := servedName(t, tlsConfig, "a.example"); got != "a.example" {
				t.Fatal("served ", got)
			}
		}
	}
	// one reload goroutine for the one entry, however many dials
	if n := runtime.NumGoroutine(); n > before+1 {
		t.Fatalf("goroutines grew from %d to %d over 1000 GetTLSConfig calls", before, n)
	}
	runtime.KeepAlive(c)
}

// The shared state must not outlive its config: across core restarts (and
// every delay test builds a core) the state would otherwise grow forever.
func TestCertStateEndsWithConfig(t *testing.T) {
	waitGoroutines(t, runtime.NumGoroutine())
	baseline := runtime.NumGoroutine()
	statesBefore := countCertStates()

	func() {
		for i := 0; i < 20; i++ {
			c := &Config{Certificate: []*Certificate{ParseCertificate(generateLeaf(t, "gone.example"))}}
			servedName(t, c.GetTLSConfig(), "gone.example")
		}
	}()

	waitGoroutines(t, baseline)
	deadline := time.Now().Add(5 * time.Second)
	for countCertStates() > statesBefore {
		if time.Now().After(deadline) {
			t.Fatalf("certStates kept %d entries for collected configs", countCertStates()-statesBefore)
		}
		runtime.GC()
		time.Sleep(20 * time.Millisecond)
	}
}

// Hot reload still picks up a changed file, and handshakes running meanwhile
// only ever see a complete old or new certificate.
func TestCertStateHotReload(t *testing.T) {
	dir := t.TempDir()
	certA := generateLeaf(t, "a.example")
	certPath, keyPath := writePEM(t, dir, certA)
	entry := ParseCertificate(certA)
	entry.CertificatePath, entry.KeyPath = certPath, keyPath
	// the reload interval is OcspStapling when set; the OCSP lookup itself
	// fails harmlessly, as the test certificates name no responder
	entry.OcspStapling = 1
	c := &Config{Certificate: []*Certificate{entry}}

	tlsConfig := c.GetTLSConfig()
	if got := servedName(t, tlsConfig, "a.example"); got != "a.example" {
		t.Fatal("served ", got)
	}
	published, _ := tlsConfig.GetCertificate(&gotls.ClientHelloInfo{ServerName: "a.example"})
	publishedDER := published.Certificate[0]

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				got, err := tlsConfig.GetCertificate(&gotls.ClientHelloInfo{ServerName: "a.example"})
				if err != nil || got == nil || got.Leaf == nil || len(got.Certificate) == 0 {
					t.Error("handshake got an incomplete certificate: ", err)
					return
				}
			}
		}()
	}

	// let the reload goroutine make its first pass over the unchanged files,
	// so the change below can only be seen by a later tick
	time.Sleep(300 * time.Millisecond)
	start := time.Now()
	writePEM(t, dir, generateLeaf(t, "b.example"))
	deadline := time.Now().Add(5 * time.Second)
	for servedName(t, tlsConfig, "b.example") != "b.example" {
		if time.Now().After(deadline) {
			t.Fatal("the changed certificate file was not picked up")
		}
		time.Sleep(50 * time.Millisecond)
	}
	close(stop)
	wg.Wait()
	t.Logf("reloaded %v after the files changed", time.Since(start).Round(10*time.Millisecond))

	// the certificate handshakes were given before is untouched
	if string(published.Certificate[0]) != string(publishedDER) {
		t.Fatal("a published certificate was modified in place")
	}
	// a tls.Config built later serves the new one too, and so does the trust
	// pool, which reads the entry through currentPEM
	if got := servedName(t, c.GetTLSConfig(), "b.example"); got != "b.example" {
		t.Fatal("new GetTLSConfig served ", got)
	}
	if certPEM, _ := currentPEM(entry); string(certPEM) == string(entry.Certificate) {
		t.Fatal("currentPEM still returns the old certificate")
	}
}

// A CA used to issue certificates ("issue" usage) is hot reloaded the same
// way: certificates issued after the change come from the new CA.
func TestCertStateCAHotReload(t *testing.T) {
	newCA := func(name string) *cert.Certificate {
		ca, err := cert.Generate(nil, cert.Authority(true), cert.KeyUsage(x509.KeyUsageCertSign), cert.CommonName(name))
		if err != nil {
			t.Fatal(err)
		}
		return ca
	}
	dir := t.TempDir()
	ca1 := newCA("ca one")
	certPath, keyPath := writePEM(t, dir, ca1)
	entry := ParseCertificate(ca1)
	entry.Usage = Certificate_AUTHORITY_ISSUE
	entry.CertificatePath, entry.KeyPath = certPath, keyPath
	entry.OcspStapling = 1
	c := &Config{Certificate: []*Certificate{entry}}

	issuer := func(sni string) string {
		got, err := c.GetTLSConfig().GetCertificate(&gotls.ClientHelloInfo{ServerName: sni})
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := x509.ParseCertificate(got.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		return leaf.Issuer.CommonName
	}

	if got := issuer("one.example"); got != "ca one" {
		t.Fatal("issued by ", got)
	}
	writePEM(t, dir, newCA("ca two"))
	deadline := time.Now().Add(5 * time.Second)
	for i := 0; issuer("two.example"+string(rune('a'+i%26))) != "ca two"; i++ {
		if time.Now().After(deadline) {
			t.Fatal("the changed CA file was not picked up")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// One state per entry, shared by every config built from it.
func TestCertStateSharedPerEntry(t *testing.T) {
	entry := ParseCertificate(generateLeaf(t, "shared.example"))
	entry.OneTimeLoading = true
	a := stateOf(entry)
	b := stateOf(entry)
	if a != b {
		t.Fatal("two states for one entry")
	}
	if _, ok := certStates.Load(weak.Make(entry)); !ok {
		t.Fatal("state not registered")
	}
	// OneTimeLoading: no reload goroutine, so stop is never needed
	select {
	case <-a.stop:
		t.Fatal("stop closed while the entry is alive")
	default:
	}
	runtime.KeepAlive(entry)
}
