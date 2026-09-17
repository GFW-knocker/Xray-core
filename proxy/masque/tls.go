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
// These rotate. The certificates behind them are ordinary ninety-day ones from
// public CAs, and Cloudflare rekeys on renewal, so a pin here has a shelf life
// of a few months rather than years. When one stops matching, the failure says
// so and names the key it saw: set "allowInsecure" once, take the key out of
// the log, put it in "pinnedPeerPublicKeySha256", and unset "allowInsecure"
// again.
var DefaultPinnedPublicKeys = []string{
	// *.cloudflareclient.com, Let's Encrypt YE2. Observed 2026-09-17 on
	// 104.16.0.1, 188.114.96.1 and 162.159.192.1 for both the HTTP/3 SNI
	// (consumer-masque) and the HTTP/2 one (consumer-masque-proxy).
	"19cee442633f9b409e769d4310896f9304d67bcf81e6bcf299a674392ca041f0",
	// cloudflareaccess.com, Google Trust Services WE1. Observed the same day on
	// the same addresses.
	"e78f36294ee550309fa034c90f10c3c82ab5d34cf79964d55e716c75b2755c3f",

	// The two below are what aether v2.0.0 ships. Neither is served on any
	// address probed above any more, so they are almost certainly rotated out,
	// but they are kept because that probing only covers TLS over TCP and the
	// HTTP/3 edge may still answer QUIC with one of them.
	//
	// masque.cloudflareclient.com, self-signed under Cloudflare's own root,
	// returned when the SNI is empty or unrecognised.
	"eb591b36ab26ba617e98371918c10bcdeae3742db6e76543f94be524dce1d555",
	// cloudflareaccess.com, an older Google Trust Services key.
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

	// Which server name to send is a real choice here, not a formality: the edge
	// answers differently per SNI, and at least one of its endpoints only
	// completes a handshake when no SNI is sent at all. So streamSettings has
	// the final say whenever it is present, an empty "serverName" included,
	// which is how sending none is asked for. The default only fills in for a
	// configuration that said nothing about TLS.
	var config *gotls.Config
	allowInsecure := false
	if settings != nil {
		config = settings.GetTLSConfig(tls.WithDestination(h.endpoint), tls.WithNextProto(h.alpn()))
		if settings.ServerName == "" {
			// WithDestination fills a name in from the address dialled. Here that
			// is an anycast IP and never what the edge expects, and an empty
			// "serverName" is a deliberate request for no SNI, so undo it.
			config.ServerName = ""
		}
		allowInsecure = settings.AllowInsecure
	} else {
		config = &gotls.Config{NextProtos: []string{h.alpn()}, ServerName: DefaultSNI}
	}
	if config.ServerName == "" {
		errors.LogInfo(context.Background(),
			`masque: sending no SNI, which is what an empty "serverName" asks for`)
	}

	// The edge asks for a client certificate. Leaving this to Certificates would
	// let Go filter by the authorities the request names, and a self-signed
	// certificate matches none of them, so it would send nothing at all.
	config.GetClientCertificate = func(*gotls.CertificateRequestInfo) (*gotls.Certificate, error) {
		return &certificate, nil
	}

	// Chain validation cannot succeed here whatever the configuration says, so it
	// is always off and the pin is what stands in for it. Which leaves
	// "allowInsecure" as the one switch that decides whether the edge is checked
	// at all: with it unset, which is the default, the key has to match a pin.
	previous := config.VerifyPeerCertificate
	config.InsecureSkipVerify = true

	var check func([][]byte, [][]*x509.Certificate) error
	if allowInsecure {
		if len(h.conf.PinnedPeerPublicKeySha256) > 0 {
			errors.LogWarning(context.Background(),
				`masque: "pinnedPeerPublicKeySha256" is set but "allowInsecure" overrides it, so the pins are not checked`)
		}
		errors.LogWarning(context.Background(),
			`masque: "allowInsecure" is set, so the edge's key is not checked. `+
				"Anyone on the path can read and alter this tunnel; unset it to pin the key instead.")
		// Still look at what the edge presented. It is the only way to learn a
		// key that is not in the built-in list, and reporting it is what makes
		// turning the pin back on possible.
		check = reportPublicKey
	} else {
		pins, err := parsePins(h.conf.PinnedPeerPublicKeySha256)
		if err != nil {
			return nil, err
		}
		check = verifyPinnedPublicKey(pins)
	}

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

// reportPublicKey names the key the edge presented without judging it, so an
// operator running with "allowInsecure" can see what to pin. It never refuses a
// connection: refusing is the pinned path's job.
func reportPublicKey(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return nil
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return nil
	}
	hash := PublicKeySHA256(leaf)
	errors.LogWarning(context.Background(),
		`masque: the edge's public key is `, hex.EncodeToString(hash[:]),
		`; put that in "pinnedPeerPublicKeySha256" and unset "allowInsecure" to pin it`)
	return nil
}
