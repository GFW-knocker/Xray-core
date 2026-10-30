package outbound

import (
	"bytes"
	"io"
	"testing"

	"github.com/GFW-knocker/Xray-core/common"
	"github.com/GFW-knocker/Xray-core/common/net"
	"github.com/GFW-knocker/Xray-core/common/protocol"
	"github.com/GFW-knocker/Xray-core/common/serial"
	"github.com/GFW-knocker/Xray-core/common/uuid"
	core "github.com/GFW-knocker/Xray-core/core"
	"github.com/GFW-knocker/Xray-core/proxy/vless"
	"github.com/GFW-knocker/Xray-core/proxy/vless/encoding"
)

type fakeConn struct {
	net.Conn
	in  io.Reader
	out bytes.Buffer
}

func (c *fakeConn) Read(b []byte) (int, error)  { return c.in.Read(b) }
func (c *fakeConn) Write(b []byte) (int, error) { return c.out.Write(b) }

func TestSwap(t *testing.T) {
	account, err := (&vless.Account{Id: protocol.NewID(uuid.New()).String()}).AsAccount()
	common.Must(err)
	request := &protocol.RequestHeader{
		Version: encoding.Version,
		User:    &protocol.MemoryUser{Account: account},
		Command: protocol.RequestCommandTCP,
		Address: net.DomainAddress("example.com"),
		Port:    443,
	}
	var plain bytes.Buffer
	common.Must(encoding.EncodeRequestHeader(&plain, request, &encoding.Addons{}))

	for _, reply := range []byte{Version, encoding.Version, 150} {
		conn := &fakeConn{in: bytes.NewReader([]byte{reply, 0})}
		c := &swapConn{Connection: conn}
		common.Must(encoding.EncodeRequestHeader(c, request, &encoding.Addons{}))
		if out := conn.out.Bytes(); out[0] != Version || !bytes.Equal(out[1:], plain.Bytes()[1:]) {
			t.Fatalf("wrote %x, want the vless header %x with version %#x", out, plain.Bytes(), Version)
		}
		if _, err := encoding.DecodeResponseHeader(c, request); (err == nil) != (reply == Version) {
			t.Errorf("reply version %#x: got err %v", reply, err)
		}
	}
}

func TestNew(t *testing.T) {
	instance, err := core.New(&core.Config{})
	common.Must(err)
	config := func(a *vless.Account) *Config {
		a.Id = protocol.NewID(uuid.New()).String()
		return &Config{Vnext: &protocol.ServerEndpoint{
			Address: net.NewIPOrDomain(net.LocalHostIP),
			Port:    443,
			User:    &protocol.User{Account: serial.ToTypedMessage(a)},
		}}
	}

	h, err := core.CreateObject(instance, config(&vless.Account{Encryption: "none"}))
	if _, ok := h.(*Handler); err != nil || !ok {
		t.Fatalf("got %T, %v", h, err)
	}
	for _, a := range []*vless.Account{
		{Encryption: "none", Flow: vless.XRV},
		{Encryption: "mlkem768x25519plus"},
		{Encryption: "none", Reverse: &vless.Reverse{Tag: "r"}},
	} {
		if _, err := core.CreateObject(instance, config(a)); err == nil {
			t.Errorf("accepted %v", a)
		}
	}
}
