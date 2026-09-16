package conf_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/GFW-knocker/Xray-core/infra/conf"
	"github.com/GFW-knocker/Xray-core/proxy/masque"
)

func pkcs8PEM(t *testing.T, key any) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func p256PEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pkcs8PEM(t, key)
}

// A configuration that names only what it must gets Cloudflare's parameters,
// because that is the service this outbound is built against.
func TestMasqueConfigFillsInTheCloudflareDefaults(t *testing.T) {
	c := &conf.MasqueConfig{
		Endpoint:   "162.159.192.1:443",
		PrivateKey: p256PEM(t),
	}
	message, err := c.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	built := message.(*masque.Config)

	if got, want := built.Authority, masque.DefaultAuthority; got != want {
		t.Errorf("authority = %q, want %q", got, want)
	}
	if got, want := built.Path, masque.DefaultPath; got != want {
		t.Errorf("path = %q, want %q", got, want)
	}
	if got, want := built.ConnectProtocol, masque.DefaultConnectProtocol; got != want {
		t.Errorf("connectProtocol = %q, want %q", got, want)
	}
	if got, want := built.Mtu, int32(masque.DefaultMTU); got != want {
		t.Errorf("mtu = %d, want %d", got, want)
	}
	if got, want := built.Transport, masque.Config_H3; got != want {
		t.Errorf("transport = %v, want %v", got, want)
	}
	if got, want := built.DomainStrategy, masque.Config_FORCE_IP; got != want {
		t.Errorf("domainStrategy = %v, want %v", got, want)
	}
}

func TestMasqueConfigCarriesWhatWasAskedFor(t *testing.T) {
	key := p256PEM(t)
	c := &conf.MasqueConfig{
		Endpoint:        "[2606:4700:d0::a29f:c001]:443",
		Address:         []string{"172.16.0.2/32", "2606:4700:110:8a1b::1"},
		PrivateKey:      key,
		Transport:       "H2",
		Authority:       "example.invalid",
		Path:            "/tunnel",
		ConnectProtocol: "connect-ip",
		MTU:             1400,
		DNS:             []string{"1.1.1.1"},
		DomainStrategy:  "ForceIPv6",
	}
	message, err := c.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	built := message.(*masque.Config)

	if built.Endpoint != c.Endpoint {
		t.Errorf("endpoint = %q, want %q", built.Endpoint, c.Endpoint)
	}
	if len(built.Address) != 2 {
		t.Errorf("address = %v, want 2 entries", built.Address)
	}
	if built.Transport != masque.Config_H2 {
		t.Errorf("transport = %v, want H2 (case-insensitive)", built.Transport)
	}
	if built.Authority != "example.invalid" || built.Path != "/tunnel" {
		t.Errorf("authority/path = %q %q, defaults were not meant to win", built.Authority, built.Path)
	}
	if built.ConnectProtocol != "connect-ip" {
		t.Errorf("connectProtocol = %q, want the RFC token that was asked for", built.ConnectProtocol)
	}
	if built.Mtu != 1400 {
		t.Errorf("mtu = %d, want 1400", built.Mtu)
	}
	if built.DomainStrategy != masque.Config_FORCE_IP6 {
		t.Errorf("domainStrategy = %v, want FORCE_IP6", built.DomainStrategy)
	}
}

func TestMasqueConfigRejectsBadInput(t *testing.T) {
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey P-384: %v", err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey RSA: %v", err)
	}
	good := p256PEM(t)

	cases := []struct {
		name   string
		config *conf.MasqueConfig
		want   string
	}{
		{"no endpoint", &conf.MasqueConfig{PrivateKey: good}, "endpoint"},
		{"no private key", &conf.MasqueConfig{Endpoint: "1.2.3.4:443"}, "privateKey"},
		{"private key is not PEM", &conf.MasqueConfig{Endpoint: "1.2.3.4:443", PrivateKey: "hunter2"}, "PEM"},
		{"private key is on P-384", &conf.MasqueConfig{Endpoint: "1.2.3.4:443", PrivateKey: pkcs8PEM(t, p384)}, "P-256"},
		{"private key is RSA", &conf.MasqueConfig{Endpoint: "1.2.3.4:443", PrivateKey: pkcs8PEM(t, rsaKey)}, "ECDSA"},
		{"unknown transport", &conf.MasqueConfig{Endpoint: "1.2.3.4:443", PrivateKey: good, Transport: "h1"}, "transport"},
		{"mtu too small", &conf.MasqueConfig{Endpoint: "1.2.3.4:443", PrivateKey: good, MTU: 100}, "mtu"},
		{"mtu too large", &conf.MasqueConfig{Endpoint: "1.2.3.4:443", PrivateKey: good, MTU: 70000}, "mtu"},
		{"unknown domain strategy", &conf.MasqueConfig{Endpoint: "1.2.3.4:443", PrivateKey: good, DomainStrategy: "nope"}, "domain strategy"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := c.config.Build()
			if err == nil {
				t.Fatalf("Build succeeded, want an error mentioning %q", c.want)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error is %q, want it to mention %q", err.Error(), c.want)
			}
		})
	}
}

// The point of this one is the registration: an outbound whose protocol is
// "masque" has to resolve through the outbound config loader, and it has to
// accept the same streamSettings every other outbound does, since that is where
// sockopt chaining and the masks come from.
func TestMasqueOutboundIsRegisteredAndTakesStreamSettings(t *testing.T) {
	settings := json.RawMessage(`{
		"endpoint": "162.159.192.1:443",
		"privateKey": ` + jsonQuote(p256PEM(t)) + `,
		"address": ["172.16.0.2/32"]
	}`)
	stream := json.RawMessage(`{
		"security": "tls",
		"tlsSettings": { "serverName": "consumer-masque.cloudflareclient.com", "alpn": ["h3"] },
		"sockopt": { "dialerProxy": "upstream", "mark": 255 }
	}`)

	var streamConfig conf.StreamConfig
	if err := json.Unmarshal(stream, &streamConfig); err != nil {
		t.Fatalf("streamSettings did not parse: %v", err)
	}

	detour := &conf.OutboundDetourConfig{
		Protocol:      "masque",
		Tag:           "masque-out",
		Settings:      &settings,
		StreamSetting: &streamConfig,
	}
	built, err := detour.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if built.Tag != "masque-out" {
		t.Errorf("tag = %q, want masque-out", built.Tag)
	}
	if url := built.ProxySettings.Type; !strings.Contains(url, "masque.Config") {
		t.Errorf("proxy settings type = %q, want the masque config", url)
	}
	if built.SenderSettings == nil {
		t.Fatal("sender settings are missing, so streamSettings would not reach the outbound")
	}
}

func jsonQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
