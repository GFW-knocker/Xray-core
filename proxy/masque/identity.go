package masque

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	gotls "crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"time"

	"github.com/GFW-knocker/Xray-core/common/errors"
)

// ParsePrivateKey reads the PEM of the private key enrolled with the edge.
//
// There is no certificate authority in MASQUE as Cloudflare runs it: the account
// registration hands the edge this key's public half, and the edge then accepts
// a certificate that the client signs for itself. So the curve has to be the one
// the key was enrolled under, which is P-256, and a key on any other curve is a
// configuration mistake worth catching here rather than as a TLS alert later.
//
// Both PKCS#8 ("PRIVATE KEY", what the registration tooling writes) and SEC1
// ("EC PRIVATE KEY", what openssl writes by default) are accepted.
func ParsePrivateKey(text string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(text))
	if block == nil {
		return nil, errors.New("private key is not a PEM block")
	}

	var parsed any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		parsed, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, errors.New("private key PEM is of type ", block.Type, `, want "PRIVATE KEY" or "EC PRIVATE KEY"`)
	}
	if err != nil {
		return nil, errors.New("failed to parse the private key").Base(err)
	}

	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not an ECDSA key")
	}
	if key.Curve != elliptic.P256() {
		return nil, errors.New("private key is on curve ", key.Curve.Params().Name, ", want P-256")
	}
	return key, nil
}

// certificateLifetime matches what the WARP client's own enrollment issues.
const certificateLifetime = 365 * 24 * time.Hour

// SelfSignedCertificate builds the client certificate for key.
//
// Nothing signs this but the key itself, and that is the whole design: the edge
// never checks a chain, because the account registration already told it this
// key's public half. The certificate is only the envelope TLS needs in order to
// carry that key, so it is deliberately bare, the way the client this mimics
// makes it: serial 0, no subject, no issuer, no extensions.
//
// The start time is backdated a little. The edge has no reason to look at these
// dates, but a certificate that becomes valid at exactly the moment it is
// presented is one clock skew away from being refused, and nothing is lost by
// leaving room.
func SelfSignedCertificate(key *ecdsa.PrivateKey) (gotls.Certificate, error) {
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:       big.NewInt(0),
		NotBefore:          now.Add(-5 * time.Minute),
		NotAfter:           now.Add(certificateLifetime),
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return gotls.Certificate{}, errors.New("failed to build the client certificate").Base(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return gotls.Certificate{}, errors.New("built a client certificate that will not parse").Base(err)
	}

	return gotls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}
