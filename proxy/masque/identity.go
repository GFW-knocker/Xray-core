package masque

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"

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
