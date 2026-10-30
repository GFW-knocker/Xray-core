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

// Version is the request and response version byte. Everything else is VLESS.
const Version = byte(0x78)

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		vnext := config.(*Config).Vnext
		if vnext.GetUser().GetAccount() != nil {
			a, err := vnext.User.Account.GetInstance()
			if err != nil {
				return nil, err
			}
			// Vision needs the raw TLS conn, encryption sends its handshake first
			// and reverse dials around the swap, so none of them would speak jvless.
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

// Process implements proxy.Outbound.Process().
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

// swapConn swaps the first byte each way between the vless version and ours,
// so a reply with any other version still fails the vless check.
type swapConn struct {
	stat.Connection
	wrote, read bool
}

func (c *swapConn) Write(b []byte) (int, error) {
	if c.wrote || len(b) == 0 {
		return c.Connection.Write(b)
	}
	c.wrote = true
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
