package masque

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	gotls "crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"

	xnet "github.com/GFW-knocker/Xray-core/common/net"
	"github.com/GFW-knocker/Xray-core/transport/internet"
	xtls "github.com/GFW-knocker/Xray-core/transport/internet/tls"
)

func testKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return key
}

// The certificate is only an envelope for the key, so what matters is that the
// key inside is the one that was enrolled and that the thing parses at all.
func TestSelfSignedCertificateCarriesTheEnrolledKey(t *testing.T) {
	key := testKey(t)
	cert, err := SelfSignedCertificate(key)
	if err != nil {
		t.Fatalf("SelfSignedCertificate: %v", err)
	}
	if len(cert.Certificate) != 1 {
		t.Fatalf("chain has %d certificates, want exactly the leaf", len(cert.Certificate))
	}
	if cert.Leaf == nil {
		t.Fatal("Leaf was not filled in, so every handshake would re-parse it")
	}

	public, ok := cert.Leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("certificate public key is %T, want *ecdsa.PublicKey", cert.Leaf.PublicKey)
	}
	if !public.Equal(&key.PublicKey) {
		t.Error("the certificate carries a different key than the one it was built from")
	}
	if cert.PrivateKey != key {
		t.Error("the private key was not attached, so the handshake could not sign with it")
	}

	// It signed itself. Checked directly rather than with CheckSignatureFrom,
	// which additionally demands the signer be a CA: this certificate is
	// deliberately bare, since nothing ever builds a chain through it.
	if err := cert.Leaf.CheckSignature(
		cert.Leaf.SignatureAlgorithm, cert.Leaf.RawTBSCertificate, cert.Leaf.Signature,
	); err != nil {
		t.Errorf("the certificate does not verify against its own key: %v", err)
	}
	if cert.Leaf.IsCA || cert.Leaf.BasicConstraintsValid {
		t.Error("the certificate claims to be a CA, which the client it mimics does not")
	}
	if got, want := cert.Leaf.SerialNumber, big.NewInt(0); got.Cmp(want) != 0 {
		t.Errorf("serial = %v, want %v to match what the edge expects", got, want)
	}
	if cert.Leaf.Subject.String() != "" {
		t.Errorf("subject = %q, want it empty", cert.Leaf.Subject.String())
	}
}

// A certificate that only becomes valid at the moment it is presented is one
// clock skew away from being refused.
func TestSelfSignedCertificateIsAlreadyValidWhenItIsIssued(t *testing.T) {
	cert, err := SelfSignedCertificate(testKey(t))
	if err != nil {
		t.Fatalf("SelfSignedCertificate: %v", err)
	}
	now := time.Now()
	if !cert.Leaf.NotBefore.Before(now) {
		t.Errorf("NotBefore = %v, which is not yet in the past at %v", cert.Leaf.NotBefore, now)
	}
	if got := cert.Leaf.NotAfter.Sub(now); got < 364*24*time.Hour {
		t.Errorf("certificate is valid for %v, want about a year", got)
	}
}

func TestParsePinsFallsBackToTheKnownKeys(t *testing.T) {
	pins, err := parsePins(nil)
	if err != nil {
		t.Fatalf("parsePins(nil): %v", err)
	}
	if len(pins) != len(DefaultPinnedPublicKeys) {
		t.Fatalf("got %d pins, want the %d built-in ones", len(pins), len(DefaultPinnedPublicKeys))
	}
	want, err := hex.DecodeString(DefaultPinnedPublicKeys[0])
	if err != nil {
		t.Fatalf("the built-in pins are not valid hex: %v", err)
	}
	if hex.EncodeToString(pins[0][:]) != hex.EncodeToString(want) {
		t.Error("the first built-in pin did not survive parsing")
	}
}

func TestParsePinsRejectsBadPins(t *testing.T) {
	for _, c := range []struct{ name, pin, want string }{
		{"not hex", "zz", "not hex"},
		{"too short", "aabb", "bytes"},
		{"too long", strings.Repeat("aa", 33), "bytes"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := parsePins([]string{c.pin}); err == nil {
				t.Fatal("parsePins succeeded, want an error")
			} else if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error is %q, want it to mention %q", err, c.want)
			}
		})
	}
}

// This is the check that stands in for chain validation, so it has to accept the
// key it was given and refuse everything else, including a second certificate
// that happens to be in the chain.
func TestVerifyPinnedPublicKey(t *testing.T) {
	wanted := testKey(t)
	other := testKey(t)

	certOf := func(key *ecdsa.PrivateKey) []byte {
		cert, err := SelfSignedCertificate(key)
		if err != nil {
			t.Fatalf("SelfSignedCertificate: %v", err)
		}
		return cert.Certificate[0]
	}
	leaf, err := x509.ParseCertificate(certOf(wanted))
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	pin := PublicKeySHA256(leaf)
	check := verifyPinnedPublicKey([][32]byte{pin})

	t.Run("the pinned key is accepted", func(t *testing.T) {
		if err := check([][]byte{certOf(wanted)}, nil); err != nil {
			t.Errorf("check rejected the pinned key: %v", err)
		}
	})

	t.Run("another key is refused", func(t *testing.T) {
		err := check([][]byte{certOf(other)}, nil)
		if err == nil {
			t.Fatal("check accepted a key that was not pinned")
		}
		if !strings.Contains(err.Error(), "matches none of the pins") {
			t.Errorf("error is %q, want it to say the key is not pinned", err)
		}
	})

	t.Run("a pinned key deeper in the chain does not count", func(t *testing.T) {
		// Only the leaf speaks for who is at the other end.
		if err := check([][]byte{certOf(other), certOf(wanted)}, nil); err == nil {
			t.Error("check accepted a chain whose leaf was not pinned")
		}
	})

	t.Run("no certificate at all is refused", func(t *testing.T) {
		if err := check(nil, nil); err == nil {
			t.Error("check accepted an empty chain")
		}
	})

	t.Run("an unparseable certificate is refused", func(t *testing.T) {
		if err := check([][]byte{{0x30, 0x00}}, nil); err == nil {
			t.Error("check accepted a certificate that does not parse")
		}
	})
}

// certificateFor is the DER of a bare self-signed certificate for key, which is
// what both ends of this protocol present.
func certificateFor(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	cert, err := SelfSignedCertificate(key)
	if err != nil {
		t.Fatalf("SelfSignedCertificate: %v", err)
	}
	return cert.Certificate[0]
}

func tlsHandler(t *testing.T, security *xtls.Config, pins []string) *Handler {
	t.Helper()
	stream := &internet.MemoryStreamConfig{}
	if security != nil {
		stream.SecuritySettings = security
	}
	return &Handler{
		conf:           &Config{Transport: Config_H3, PinnedPeerPublicKeySha256: pins},
		streamSettings: stream,
		privateKey:     testKey(t),
		endpoint: xnet.Destination{
			Address: xnet.ParseAddress("127.0.0.1"),
			Port:    443,
			Network: xnet.Network_UDP,
		},
	}
}

// allowInsecure is the one switch that decides whether the edge is checked.
// Unset, which is the default, the key has to match a pin.
func TestAllowInsecureDecidesWhetherThePinIsChecked(t *testing.T) {
	edgeKey := testKey(t)
	edgeCert := certificateFor(t, edgeKey)
	edgePin := PublicKeySHA256(mustParseCert(t, edgeCert))
	edgePinHex := hex.EncodeToString(edgePin[:])

	strangerCert := certificateFor(t, testKey(t))

	for _, c := range []struct {
		name          string
		security      *xtls.Config
		pins          []string
		wantStranger  bool // whether a key that is not pinned is accepted
		wantEdgeError bool // whether the pinned key itself is refused
	}{
		{
			name:         "no tls settings at all pins against the built-in keys",
			security:     nil,
			pins:         nil,
			wantStranger: false,
		},
		{
			name:         "allowInsecure unset pins against the configured key",
			security:     &xtls.Config{AllowInsecure: false},
			pins:         []string{edgePinHex},
			wantStranger: false,
		},
		{
			name:         "allowInsecure set accepts anything",
			security:     &xtls.Config{AllowInsecure: true},
			pins:         []string{edgePinHex},
			wantStranger: true,
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			handler := tlsHandler(t, c.security, c.pins)
			config, err := handler.buildTLSConfig()
			if err != nil {
				t.Fatalf("buildTLSConfig: %v", err)
			}
			if config.VerifyPeerCertificate == nil {
				t.Fatal("no verifier was installed, so nothing would ever look at the edge")
			}
			if !config.InsecureSkipVerify {
				t.Error("chain validation is on, which cannot succeed against this edge")
			}

			err = config.VerifyPeerCertificate([][]byte{strangerCert}, nil)
			if c.wantStranger && err != nil {
				t.Errorf("a key that is not pinned was refused: %v", err)
			}
			if !c.wantStranger && err == nil {
				t.Error("a key that is not pinned was accepted")
			}

			if len(c.pins) > 0 {
				if err := config.VerifyPeerCertificate([][]byte{edgeCert}, nil); err != nil {
					t.Errorf("the pinned key itself was refused: %v", err)
				}
			}
		})
	}
}

func mustParseCert(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}

// The client certificate and the ALPN follow the carrier, and the server name
// falls back to the one the edge answers on.
func TestBuildTLSConfigShape(t *testing.T) {
	handler := tlsHandler(t, nil, nil)
	config, err := handler.buildTLSConfig()
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if config.ServerName != DefaultSNI {
		t.Errorf("server name = %q, want %q", config.ServerName, DefaultSNI)
	}
	if len(config.NextProtos) != 1 || config.NextProtos[0] != "h3" {
		t.Errorf("alpn = %v, want [h3] for the HTTP/3 carrier", config.NextProtos)
	}
	if config.GetClientCertificate == nil {
		t.Fatal("no client certificate would be offered, and the edge asks for one")
	}
	offered, err := config.GetClientCertificate(&gotls.CertificateRequestInfo{})
	if err != nil {
		t.Fatalf("GetClientCertificate: %v", err)
	}
	if offered.Leaf == nil || !offered.Leaf.PublicKey.(*ecdsa.PublicKey).Equal(&handler.privateKey.PublicKey) {
		t.Error("the certificate offered does not carry the configured key")
	}

	handler.conf.Transport = Config_H2
	config, err = handler.buildTLSConfig()
	if err != nil {
		t.Fatalf("buildTLSConfig for h2: %v", err)
	}
	if len(config.NextProtos) != 1 || config.NextProtos[0] != "h2" {
		t.Errorf("alpn = %v, want [h2] for the HTTP/2 carrier", config.NextProtos)
	}
}
