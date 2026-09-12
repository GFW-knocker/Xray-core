package tls

import (
	gonet "net"

	utls "github.com/refraction-networking/utls"
)

// GuaranteesX25519MLKEM768 reports whether every ClientHello uTLS builds for id
// will carry an X25519MLKEM768 key share.
//
// REALITY needs that guarantee: since github.com/xtls/reality 20260908062103 the
// server abandons authentication unless the ClientHello offers X25519MLKEM768
// ahead of any optional X25519 share, so a fingerprint that omits it -- even
// only sometimes -- cannot be verified on the connections where it does. Plain
// TLS has no such requirement.
//
// A fingerprint uTLS cannot build is reported as guaranteed, so an unexpected
// error never causes a caller to override the user's choice.
func GuaranteesX25519MLKEM768(id *utls.ClientHelloID) bool {
	if isUnseededRandomized(id) {
		// A fresh ClientHello per connection: sampling one says nothing about
		// the next, so the key share cannot be guaranteed.
		return false
	}

	// A pipe is enough: BuildHandshakeState only assembles the ClientHello, it
	// does not write. uConn closes neither end, so both are closed here.
	c1, c2 := gonet.Pipe()
	defer c1.Close()
	defer c2.Close()

	// ServerName only has to be non-empty for the ClientHello to build.
	uConn := utls.UClient(c1, &utls.Config{ServerName: "example.com"}, *id)
	if err := uConn.BuildHandshakeState(); err != nil {
		return true
	}
	for _, keyShare := range uConn.HandshakeState.Hello.KeyShares {
		if keyShare.Group == utls.X25519MLKEM768 {
			return true
		}
	}
	return false
}

// isUnseededRandomized reports whether id randomizes its ClientHello afresh on
// every connection. The randomized presets in this package carry a seed fixed
// at init and so are stable for the life of the process; the bare
// utls.HelloRandomized* ids are not.
func isUnseededRandomized(id *utls.ClientHelloID) bool {
	if id.Seed != nil {
		return false
	}
	switch id.Client {
	case utls.HelloRandomized.Client, utls.HelloRandomizedALPN.Client, utls.HelloRandomizedNoALPN.Client:
		return true
	}
	return false
}
