package tls

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	goerrors "errors"
	"io"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/cryptobyte"

	"github.com/GFW-knocker/Xray-core/common/errors"
	"github.com/GFW-knocker/Xray-core/common/net"
	"github.com/GFW-knocker/Xray-core/transport/internet"
)

const (
	echProbeScheme = "probe"
	// Cloudflare uses one fleet-wide public name: every ECH-enabled zone behind
	// it advertises the same one, so it is the sensible default target.
	echProbeDefaultName = "cloudflare-ech.com"
	echProbeDefaultPort = "443"
	// A probed config carries no DNS TTL, so pick one. Cloudflare keeps older
	// keys working alongside new ones, and a stale config self-heals: the next
	// probe runs as soon as this expires.
	echProbeTTL     uint32 = 3600
	echProbeTimeout        = 12 * time.Second

	// draft-ietf-tls-esni-13 and later
	echConfigVersion uint16 = 0xfe0d
	// DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM
	echKemX25519    uint16 = 0x0020
	echKdfSHA256    uint16 = 0x0001
	echAeadAES128   uint16 = 0x0001
	echX25519KeyLen        = 32
)

// parseECHProbe recognises the "probe" pseudo-scheme accepted by echConfigList:
//
//	probe                           -> name cloudflare-ech.com, dial cloudflare-ech.com:443
//	probe://                        -> same
//	probe://example.com             -> name example.com,        dial example.com:443
//	probe://example.com@1.2.3.4:443 -> name example.com,        dial 1.2.3.4:443
//
// ok is false when s is not a probe spec, in which case the caller falls through
// to the pre-existing DNS-query and base64 handling untouched.
func parseECHProbe(s string) (publicName string, hostPort string, ok bool) {
	s = strings.TrimSpace(s)
	switch {
	case s == echProbeScheme:
		s = ""
	case strings.HasPrefix(s, echProbeScheme+"://"):
		s = s[len(echProbeScheme)+len("://"):]
	default:
		return "", "", false
	}

	// Split the optional dial target off the right. A public name therefore may
	// not contain '@', which is fine: it has to be a DNS name.
	if at := strings.LastIndex(s, "@"); at >= 0 {
		hostPort = strings.TrimSpace(s[at+1:])
		s = strings.TrimSpace(s[:at])
	}

	publicName = echProbeDefaultName
	if s != "" {
		publicName = s
	}
	switch {
	case hostPort == "":
		hostPort = publicName + ":" + echProbeDefaultPort
	default:
		if _, _, err := net.SplitHostPort(hostPort); err != nil {
			// address given without a port
			hostPort = net.JoinHostPort(hostPort, echProbeDefaultPort)
		}
	}
	return publicName, hostPort, true
}

// bogusECHConfigList builds a structurally valid ECHConfigList whose HPKE key is
// random, so the server can never decrypt a payload sealed to it.
//
// Per draft-ietf-tls-esni section 6.1.6 a server that cannot decrypt an ECH
// payload does not fail the handshake: it completes against the ClientHelloOuter,
// presents a certificate for the public name, and returns its current keys in the
// retry_configs field of EncryptedExtensions. Those keys are what we are after.
//
// On the wire this is shaped like the GREASE ECH that Chrome sends on every
// connection, so it introduces no new fingerprint.
func bogusECHConfigList(publicName string) ([]byte, error) {
	if l := len(publicName); l == 0 || l > 255 {
		return nil, errors.New("ECH probe public name has invalid length: ", l)
	}
	key := make([]byte, echX25519KeyLen)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	var configID [1]byte
	if _, err := io.ReadFull(rand.Reader, configID[:]); err != nil {
		return nil, err
	}

	var b cryptobyte.Builder
	b.AddUint16LengthPrefixed(func(list *cryptobyte.Builder) {
		list.AddUint16(echConfigVersion)
		list.AddUint16LengthPrefixed(func(cfg *cryptobyte.Builder) {
			cfg.AddUint8(configID[0])
			cfg.AddUint16(echKemX25519)
			cfg.AddUint16LengthPrefixed(func(pk *cryptobyte.Builder) { pk.AddBytes(key) })
			cfg.AddUint16LengthPrefixed(func(cs *cryptobyte.Builder) {
				cs.AddUint16(echKdfSHA256)
				cs.AddUint16(echAeadAES128)
			})
			cfg.AddUint8(0) // maximum_name_length
			cfg.AddUint8LengthPrefixed(func(n *cryptobyte.Builder) { n.AddBytes([]byte(publicName)) })
			cfg.AddUint16LengthPrefixed(func(*cryptobyte.Builder) {}) // extensions
		})
	})
	return b.Bytes()
}

// looksLikeECHConfigList applies the framing checks parseECHConfigList performs
// inside the TLS stack. A retry_configs value that fails them is rejected here so
// that we fail closed, rather than caching junk that would break every handshake
// for the lifetime of the cache entry.
func looksLikeECHConfigList(b []byte) bool {
	if len(b) < 2 || int(binary.BigEndian.Uint16(b[:2])) != len(b)-2 {
		return false
	}
	configs := 0
	for s := b[2:]; len(s) > 0; configs++ {
		if len(s) < 4 {
			return false
		}
		length := int(binary.BigEndian.Uint16(s[2:4]))
		if len(s) < 4+length {
			return false
		}
		s = s[4+length:]
	}
	return configs > 0
}

// echProbe opens one throwaway TLS connection to hostPort offering a bogus ECH
// config, and returns the retry_configs the server hands back. No DNS record is
// involved.
//
// The result is authenticated: retry_configs arrive inside a handshake whose
// certificate is validated against publicName, so an attacker who cannot obtain
// that certificate cannot feed us a key. That makes this no weaker than DoH, and
// strictly stronger than the plain udp:// path.
func echProbe(ctx context.Context, hostPort string, publicName string, sockopt *internet.SocketConfig,
	fingerprint *utls.ClientHelloID, rootCAs *x509.CertPool,
) ([]byte, uint32, error) {
	configList, err := bogusECHConfigList(publicName)
	if err != nil {
		return nil, 0, err
	}
	dest, err := net.ParseDestination("tcp:" + hostPort)
	if err != nil {
		return nil, 0, errors.New("failed to parse ECH probe address ", hostPort).Base(err)
	}

	ctx, cancel := context.WithTimeout(ctx, echProbeTimeout)
	defer cancel()

	// Same dial path as the DNS query, so echSockopt (including dialerProxy)
	// applies and Android VPN GUI clients keep working.
	conn, err := internet.DialSystem(ctx, dest, sockopt)
	if err != nil {
		return nil, 0, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}

	var retryConfigs []byte
	if fingerprint != nil {
		uConn := utls.UClient(conn, &utls.Config{
			ServerName: publicName,
			MinVersion: utls.VersionTLS13,
			// The parrot offers these. When ECH is rejected the server picks ALPN
			// from the outer hello, and uTLS rejects a pick we did not advertise.
			NextProtos:                     []string{"h2", "http/1.1"},
			RootCAs:                        rootCAs,
			EncryptedClientHelloConfigList: configList,
			// crypto/tls validates the ECH-rejection certificate against the outer
			// public name, as the spec requires. uTLS substitutes config.ServerName
			// (the inner name) there, which cannot match the public name's
			// certificate, so the correct name has to be requested explicitly. This
			// is a full WebPKI validation against publicName, not a relaxation:
			// InsecureSkipVerify is deliberately left off, and would not help here
			// anyway because the rejection branch bypasses it.
			InsecureServerNameToVerify: publicName,
		}, *fingerprint)
		err = uConn.HandshakeContext(ctx)
		var rejected *utls.ECHRejectionError
		if goerrors.As(err, &rejected) {
			retryConfigs, err = rejected.RetryConfigList, nil
		}
	} else {
		// "unsafe" fingerprint: crypto/tls already checks the rejection
		// certificate against the outer public name, so there is nothing to fix.
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:                     publicName,
			MinVersion:                     tls.VersionTLS13,
			NextProtos:                     []string{"h2", "http/1.1"},
			RootCAs:                        rootCAs,
			EncryptedClientHelloConfigList: configList,
		})
		err = tlsConn.HandshakeContext(ctx)
		var rejected *tls.ECHRejectionError
		if goerrors.As(err, &rejected) {
			retryConfigs, err = rejected.RetryConfigList, nil
		}
	}
	if err != nil {
		return nil, 0, err
	}
	if len(retryConfigs) == 0 {
		return nil, 0, errors.New("ECH probe to ", hostPort, " returned no retry_configs; ",
			publicName, " is probably not ECH-enabled")
	}
	if !looksLikeECHConfigList(retryConfigs) {
		return nil, 0, errors.New("ECH probe to ", hostPort, " returned a malformed ECHConfigList")
	}
	errors.LogDebug(ctx, "Obtained ECH config by probing ", hostPort, " as ", publicName,
		" (", len(retryConfigs), " bytes)")
	return retryConfigs, echProbeTTL, nil
}
