package tls

import (
	"crypto/tls"
	"encoding/binary"
	goerrors "errors"
	"strings"

	utls "github.com/refraction-networking/utls"

	"github.com/GFW-knocker/Xray-core/common/errors"
)

// rememberECHCacheKey records which GlobalECHConfigCache entry fed this
// tls.Config, so a later handshake failure can invalidate it. The key rides on
// the RandCarrier because that is the one per-config object copyConfig already
// carries over to utls.Config.
func rememberECHCacheKey(config *tls.Config, key string) {
	if r, ok := config.Rand.(*RandCarrier); ok {
		r.ECHCacheKey = key
	}
}

func echCacheKeyOf(config *tls.Config) string {
	if config == nil {
		return ""
	}
	if r, ok := config.Rand.(*RandCarrier); ok {
		return r.ECHCacheKey
	}
	return ""
}

// invalidateECHConfig forces the next lookup of this cache entry to fetch a
// fresh config instead of serving the cached one. It zeroes the record rather
// than deleting the entry, so the existing "expire.IsZero() means cold start,
// fetch synchronously" path in queryECHConfig does the work, and any refresh
// goroutine already in flight stays valid.
func invalidateECHConfig(key string) bool {
	if key == "" {
		return false
	}
	cache, ok := GlobalECHConfigCache.Load(key)
	if !ok {
		return false
	}
	cache.configRecord.Store(&echConfigRecord{})
	return true
}

// echPublicNameFromConfigList returns the public_name of the first config in an
// ECHConfigList, or "" if it cannot be read. Used only to recognise our own
// public name inside a certificate error message.
func echPublicNameFromConfigList(list []byte) string {
	// [listLen:2][version:2][cfgLen:2][configID:1][kem:2][pkLen:2][pk][csLen:2][cs][maxNameLen:1][nameLen:1][name]...
	if len(list) < 12 || int(binary.BigEndian.Uint16(list[:2])) != len(list)-2 {
		return ""
	}
	s := list[4:]
	if len(s) < 2 {
		return ""
	}
	s = s[2:] // skip cfgLen
	if len(s) < 5 {
		return ""
	}
	s = s[3:] // skip configID + kem
	pkLen := int(binary.BigEndian.Uint16(s[:2]))
	if len(s) < 2+pkLen+2 {
		return ""
	}
	s = s[2+pkLen:]
	csLen := int(binary.BigEndian.Uint16(s[:2]))
	if len(s) < 2+csLen+2 {
		return ""
	}
	s = s[2+csLen+1:] // also skip maximum_name_length
	nameLen := int(s[0])
	if len(s) < 1+nameLen {
		return ""
	}
	return string(s[1 : 1+nameLen])
}

// echRejectedByServer reports whether err is a handshake failure caused by the
// server refusing our ECH config, and returns the retry_configs when the TLS
// stack managed to surface them.
//
// Three shapes have to be recognised, because two of them are bugs in the stack
// rather than clean signals:
//
//   - ECHRejectionError, the clean signal. crypto/tls always produces it.
//   - A certificate error naming our own public name. uTLS validates the
//     rejection certificate against the inner server name instead of the outer
//     public name, so it fails here before it can construct ECHRejectionError.
//   - An ALPN mismatch. On rejection the server negotiates from ClientHelloOuter,
//     whose ALPN comes from the uTLS parrot (h2, http/1.1) and can be wider than
//     the config's own list -- WebSocket and HTTPUpgrade narrow it to http/1.1.
func echRejectedByServer(config *tls.Config, err error) (retryConfigs []byte, rejected bool) {
	var goRejection *tls.ECHRejectionError
	if goerrors.As(err, &goRejection) {
		return goRejection.RetryConfigList, true
	}
	var uRejection *utls.ECHRejectionError
	if goerrors.As(err, &uRejection) {
		return uRejection.RetryConfigList, true
	}

	msg := err.Error()
	var goCertErr *tls.CertificateVerificationError
	var uCertErr *utls.CertificateVerificationError
	if goerrors.As(err, &goCertErr) || goerrors.As(err, &uCertErr) {
		// Only claim this is an ECH rejection when the certificate is actually
		// the one for our public name, so a genuine certificate problem on an
		// ECH-accepted connection is still reported as itself.
		if name := echPublicNameFromConfigList(config.EncryptedClientHelloConfigList); name != "" &&
			strings.Contains(msg, name) {
			return nil, true
		}
		return nil, false
	}

	if strings.Contains(msg, "unadvertised ALPN protocol") ||
		strings.Contains(msg, "unrequested ALPN extension") {
		return nil, true
	}
	return nil, false
}

// RefineECHError turns an opaque TLS handshake failure on an ECH-enabled
// connection into one that says what actually went wrong, and drops the cached
// ECH config when the server told us it is stale so the next dial fetches a new
// one instead of waiting out the TTL.
//
// It returns err unchanged for connections that do not use ECH, and for
// failures unrelated to it.
func RefineECHError(config *tls.Config, err error) error {
	if err == nil || config == nil || len(config.EncryptedClientHelloConfigList) == 0 {
		return err
	}

	// The placeholder ApplyECH installs when no config could be obtained. The
	// TLS stack rejects it while parsing, long before any bytes reach the wire,
	// and reports it as a malformed list -- which tells the user nothing.
	if isFailClosedECHConfig(config.EncryptedClientHelloConfigList) {
		return errors.New("ECH is enabled but no ECH config could be obtained, so the connection was ",
			"refused rather than falling back to a plaintext SNI. Check echConfigList ",
			"(DNS server reachable? probe target reachable?)").Base(err)
	}

	retryConfigs, rejected := echRejectedByServer(config, err)
	if !rejected {
		return err
	}

	dropped := invalidateECHConfig(echCacheKeyOf(config))
	detail := "the ECH config we used was refused by the server"
	if len(retryConfigs) > 0 {
		detail += " (it offered replacement keys)"
	}
	switch {
	case dropped:
		detail += "; the cached config has been dropped, retry to fetch a fresh one"
	case echCacheKeyOf(config) == "":
		detail += "; echConfigList is a pinned base64 config, so it cannot refresh itself"
	}
	return errors.New("ECH rejected: ", detail).Base(err)
}

// isFailClosedECHConfig reports whether list is the deliberately invalid config
// ApplyECH installs when no real one could be obtained.
func isFailClosedECHConfig(list []byte) bool {
	return len(list) == len(failClosedECHConfig) && string(list) == string(failClosedECHConfig)
}
