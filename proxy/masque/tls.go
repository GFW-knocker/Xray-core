package masque

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	gotls "crypto/tls"
	"crypto/x509"
	"encoding/hex"

	"github.com/GFW-knocker/Xray-core/common/errors"
	"github.com/GFW-knocker/Xray-core/transport/internet/tls"
)

// DefaultPinnedPublicKeys are the SHA-256 hashes of the SubjectPublicKeyInfo of
// the certificates Cloudflare's MASQUE edges serve.
//
// Why pin at all: the edge cannot be verified the ordinary way. It answers with
// a different certificate depending on the SNI it is given, and at least one of
// those is self-signed, so an honest connection fails a chain check. Turning
// verification off instead would hand the tunnel to anyone able to sit on the
// path, which for a circumvention tool is the whole threat model. Pinning the
// key keeps a real check while skipping the chain.
//
// Why the public key rather than the certificate: a certificate pin breaks every
// time the edge renews, and one of these is issued by a public CA on a short
// cycle. The key outlives the certificate.
var DefaultPinnedPublicKeys = []string{
	// masque.cloudflareclient.com, self-signed under Cloudflare's own root. This
	// is what comes back when the SNI is empty or not one the edge knows.
	"eb591b36ab26ba617e98371918c10bcdeae3742db6e76543f94be524dce1d555",
	// cloudflareaccess.com, issued by Google Trust Services. This is what comes
	// back when the SNI is cloudflareaccess.com.
	"3fbb1d7452d32b3881eb4b5d48421445b6b9d8f5225959f033532d502637b040",
}

// PublicKeySHA256 hashes a certificate's SubjectPublicKeyInfo, which is what the
// pins above are. Note this is not Xray's own pinnedPeerCertSha256, which hashes
// the whole certificate.
func PublicKeySHA256(cert *x509.Certificate) [sha256.Size]byte {
	return sha256.Sum256(cert.RawSubjectPublicKeyInfo)
}

func parsePins(pins []string) ([][sha256.Size]byte, error) {
	if len(pins) == 0 {
		pins = DefaultPinnedPublicKeys
	}
	parsed := make([][sha256.Size]byte, 0, len(pins))
	for _, pin := range pins {
		raw, err := hex.DecodeString(pin)
		if err != nil {
			return nil, errors.New("pinned public key ", pin, " is not hex").Base(err)
		}
		if len(raw) != sha256.Size {
			return nil, errors.New("pinned public key ", pin, " is ", len(raw), " bytes, want ", sha256.Size)
		}
		parsed = append(parsed, [sha256.Size]byte(raw))
	}
	return parsed, nil
}

// verifyPinnedPublicKey checks the leaf the edge presented against the pins. It
// only ever looks at the leaf: an intermediate matching a pin would say nothing
// about who holds the key at the other end.
func verifyPinnedPublicKey(pins [][sha256.Size]byte) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("masque: the edge presented no certificate")
		}
		leaf, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return errors.New("masque: the edge's certificate will not parse").Base(err)
		}

		got := PublicKeySHA256(leaf)
		for _, pin := range pins {
			if subtle.ConstantTimeCompare(got[:], pin[:]) == 1 {
				return nil
			}
		}
		return errors.New(
			"masque: the edge's public key ", hex.EncodeToString(got[:]),
			" matches none of the pins; either something is intercepting this connection,",
			` or Cloudflare rotated the key and "pinnedPeerPublicKeySha256" needs the new one`,
		)
	}
}

// alpn is the protocol to negotiate, which the transport decides: the tunnel
// cannot be carried over anything else.
func (h *Handler) alpn() string {
	if h.conf.Transport == Config_H2 {
		return "h2"
	}
	return "h3"
}

// buildTLSConfig assembles what the tunnel hands to QUIC or to the HTTP/2 dialer.
// The server side of it comes from streamSettings like any other outbound, so
// ECH, fingerprints and the rest are configured the usual way; what this adds is
// the client certificate and the pin check that stands in for chain validation.
func (h *Handler) buildTLSConfig() (*gotls.Config, error) {
	certificate, err := SelfSignedCertificate(h.privateKey)
	if err != nil {
		return nil, err
	}

	var settings *tls.Config
	if h.streamSettings != nil {
		settings = tls.ConfigFromStreamSettings(h.streamSettings)
	}

	var config *gotls.Config
	allowInsecure := false
	if settings != nil {
		config = settings.GetTLSConfig(tls.WithDestination(h.endpoint), tls.WithNextProto(h.alpn()))
		allowInsecure = settings.AllowInsecure
	} else {
		config = &gotls.Config{NextProtos: []string{h.alpn()}}
	}
	if config.ServerName == "" {
		config.ServerName = DefaultSNI
	}

	// The edge asks for a client certificate. Leaving this to Certificates would
	// let Go filter by the authorities the request names, and a self-signed
	// certificate matches none of them, so it would send nothing at all.
	config.GetClientCertificate = func(*gotls.CertificateRequestInfo) (*gotls.Certificate, error) {
		return &certificate, nil
	}

	// Chain validation cannot succeed here whatever the configuration says, so it
	// is always off and something else has to do the checking.
	previous := config.VerifyPeerCertificate
	config.InsecureSkipVerify = true

	if allowInsecure {
		errors.LogWarning(context.Background(),
			`masque: "allowInsecure" is set, so the edge's key is not checked. `+
				"Anyone on the path can read and alter this tunnel; unset it to pin the key instead.")
		return config, nil
	}

	pins, err := parsePins(h.conf.PinnedPeerPublicKeySha256)
	if err != nil {
		return nil, err
	}
	check := verifyPinnedPublicKey(pins)
	config.VerifyPeerCertificate = func(rawCerts [][]byte, chains [][]*x509.Certificate) error {
		// Whatever streamSettings asked for still applies, and runs first.
		if previous != nil {
			if err := previous(rawCerts, chains); err != nil {
				return err
			}
		}
		return check(rawCerts, chains)
	}
	return config, nil
}
