package tls

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	gonet "net"
	"strings"
	"testing"
	"time"
)

// echKeyBufferForTest builds the "echServerKeys" blob `xray tls ech` emits:
// uint16 len(privateKey) || privateKey || uint16 len(config) || config.
func echKeyBufferForTest(t *testing.T, publicName string) (keyBuffer []byte, configList []byte) {
	t.Helper()
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		t.Fatal(err)
	}
	sk, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	list, err := echConfigListForTest(sk.PublicKey().Bytes(), 0x11, publicName)
	if err != nil {
		t.Fatal(err)
	}
	config := list[2:] // strip the ECHConfigList length prefix

	keyBuffer = append(keyBuffer, byte(len(priv)>>8), byte(len(priv)))
	keyBuffer = append(keyBuffer, priv...)
	keyBuffer = append(keyBuffer, byte(len(config)>>8), byte(len(config)))
	keyBuffer = append(keyBuffer, config...)
	return keyBuffer, list
}

// echConfigListForTest mirrors bogusECHConfigList but takes a real public key.
func echConfigListForTest(pub []byte, id byte, publicName string) ([]byte, error) {
	u16 := func(v int) []byte { return []byte{byte(v >> 8), byte(v)} }
	var in []byte
	in = append(in, id)
	in = append(in, u16(int(echKemX25519))...)
	in = append(in, u16(len(pub))...)
	in = append(in, pub...)
	cs := append(u16(int(echKdfSHA256)), u16(int(echAeadAES128))...)
	in = append(in, u16(len(cs))...)
	in = append(in, cs...)
	in = append(in, 0, byte(len(publicName)))
	in = append(in, []byte(publicName)...)
	in = append(in, u16(0)...)
	cfg := append(u16(int(echConfigVersion)), u16(len(in))...)
	cfg = append(cfg, in...)
	return append(u16(len(cfg)), cfg...), nil
}

func selfSignedForTest(t *testing.T, names ...string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// startSelfHostedECHServer runs a TLS server configured exactly the way an Xray
// inbound with "echServerKeys" is, including going through ConvertToGoECHKeys.
func startSelfHostedECHServer(t *testing.T, publicName, innerName string) (addr string, configList []byte) {
	t.Helper()
	keyBuffer, list := echKeyBufferForTest(t, publicName)
	keys, err := ConvertToGoECHKeys(keyBuffer)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates:             []tls.Certificate{selfSignedForTest(t, innerName)},
		EncryptedClientHelloKeys: keys,
		MinVersion:               tls.VersionTLS13,
		NextProtos:               []string{"h2", "http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				c.(*tls.Conn).HandshakeContext(context.Background())
				time.Sleep(20 * time.Millisecond)
				c.Close()
			}()
		}
	}()
	return ln.Addr().String(), list
}

// Change A: an Xray ECH server must mark its keys so a client with a stale
// config is told the current one, instead of being refused in silence.
func TestConvertToGoECHKeysSendsRetryConfigs(t *testing.T) {
	keyBuffer, _ := echKeyBufferForTest(t, "cover.example")
	keys, err := ConvertToGoECHKeys(keyBuffer)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("got %d keys, want 1", len(keys))
	}
	if !keys[0].SendAsRetry {
		t.Error("SendAsRetry is not set, so this server would never tell a client its key is stale")
	}
}

// Changes A and B end to end: probe a self-hosted server with a self-signed
// certificate and confirm the current key comes back.
func TestECHProbeAgainstSelfHostedServer(t *testing.T) {
	const publicName, innerName = "cover.example", "secret.example"
	addr, wantList := startSelfHostedECHServer(t, publicName, innerName)
	host, port, _ := gonet.SplitHostPort(addr)
	hostPort := gonet.JoinHostPort(host, port)

	// allowInsecure off: the self-signed certificate must stop the probe.
	if _, _, err := echProbe(context.Background(), hostPort, publicName, nil,
		GetFingerprint("chrome"), nil, false); err == nil {
		t.Error("probe accepted a self-signed certificate with allowInsecure off")
	} else if !strings.Contains(err.Error(), "certificate") {
		t.Errorf("expected a certificate failure, got: %v", err)
	}

	// allowInsecure on: the probe proceeds and harvests the retry config.
	for _, fp := range []string{"chrome", "unsafe"} { // uTLS path and crypto/tls path
		got, ttl, err := echProbe(context.Background(), hostPort, publicName, nil,
			GetFingerprint(fp), nil, true)
		if err != nil {
			t.Fatalf("fingerprint %q: probe failed: %v", fp, err)
		}
		if ttl != echProbeTTL {
			t.Errorf("fingerprint %q: ttl = %d, want %d", fp, ttl, echProbeTTL)
		}
		if string(got) != string(wantList) {
			t.Errorf("fingerprint %q: retry config does not match the server key\n got %x\nwant %x", fp, got, wantList)
		}
	}
}

// The probed key must then actually work, and the cleartext outer SNI must be
// the cover name the operator chose -- not the real one.
func TestECHProbeResultConnects(t *testing.T) {
	const publicName, innerName = "cover.example", "secret.example"
	addr, _ := startSelfHostedECHServer(t, publicName, innerName)
	host, port, _ := gonet.SplitHostPort(addr)

	probed, _, err := echProbe(context.Background(), gonet.JoinHostPort(host, port), publicName, nil,
		GetFingerprint("chrome"), nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if name := echPublicNameFromConfigList(probed); name != publicName {
		t.Errorf("probed config carries public name %q, want %q", name, publicName)
	}

	cfg := &Config{ServerName: innerName, AllowInsecure: true}
	tlsConfig := cfg.GetTLSConfig()
	tlsConfig.EncryptedClientHelloConfigList = probed

	raw, err := gonet.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(10 * time.Second))
	c := UClient(raw, tlsConfig, GetFingerprint("chrome")).(*UConn)
	if err := c.HandshakeContext(context.Background()); err != nil {
		t.Fatalf("connecting with the probed key failed: %v", RefineECHError(tlsConfig, c, err))
	}
	if !c.ECHAccepted() {
		t.Error("handshake succeeded but ECH was not accepted")
	}
}
