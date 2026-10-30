package outbound

import (
	"context"

	"github.com/GFW-knocker/Xray-core/common"
	"github.com/GFW-knocker/Xray-core/common/errors"
	"github.com/GFW-knocker/Xray-core/common/net"
	"github.com/GFW-knocker/Xray-core/proxy/vless"
	"github.com/GFW-knocker/Xray-core/proxy/vless/encoding"
	vlessoutbound "github.com/GFW-knocker/Xray-core/proxy/vless/outbound"
	"github.com/GFW-knocker/Xray-core/transport"
	"github.com/GFW-knocker/Xray-core/transport/internet"
	"github.com/GFW-knocker/Xray-core/transport/internet/stat"
)

// Version replaces vless's 0 in both the request and the reply. Nothing else changes.
const Version = byte(0x78)

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		vnext := config.(*Config).Vnext
		if vnext.GetUser().GetAccount() != nil {
			a, err := vnext.User.Account.GetInstance()
			if err != nil {
				return nil, err
			}
			// These can't go through the byte swap: Vision needs the raw TLS conn,
			// encryption writes its handshake first, and reverse dials without our wrapper.
			if a := a.(*vless.Account); a.Flow != "" || a.Reverse != nil || a.Encryption != "" && a.Encryption != "none" {
				return nil, errors.New(`jvless doesn't support "flow", "encryption" or "reverse"`)
			}
		}
		h, err := vlessoutbound.New(ctx, &vlessoutbound.Config{Vnext: vnext})
		if err != nil {
			return nil, err
		}
		return &Handler{h}, nil
	}))
}

// Handler is the vless outbound with the version byte swapped on the wire.
type Handler struct {
	*vlessoutbound.Handler
}

// Process hands vless a dialer whose conns swap the version byte.
func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	return h.Handler.Process(ctx, link, swapDialer{dialer})
}

type swapDialer struct {
	internet.Dialer
}

func (d swapDialer) Dial(ctx context.Context, dest net.Destination) (stat.Connection, error) {
	conn, err := d.Dialer.Dial(ctx, dest)
	if err != nil {
		return nil, err
	}
	return &swapConn{Connection: conn}, nil
}

// swapConn flips the first byte each way between 0 and 0x78. vless still checks
// the reply version, so any reply other than 0x78 gets rejected.
type swapConn struct {
	stat.Connection
	wrote, read bool
}

func (c *swapConn) Write(b []byte) (int, error) {
	if c.wrote || len(b) == 0 {
		return c.Connection.Write(b)
	}
	c.wrote = true
	// copy instead of editing b, it's the caller's buffer
	return c.Connection.Write(append([]byte{swap(b[0])}, b[1:]...))
}

func (c *swapConn) Read(b []byte) (int, error) {
	n, err := c.Connection.Read(b)
	if n > 0 && !c.read {
		c.read = true
		b[0] = swap(b[0])
	}
	return n, err
}

func swap(b byte) byte {
	switch b {
	case encoding.Version:
		return Version
	case Version:
		return encoding.Version
	}
	return b
}
