package outbound

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/GFW-knocker/Xray-core/common"
	"github.com/GFW-knocker/Xray-core/common/buf"
	xnet "github.com/GFW-knocker/Xray-core/common/net"
	"github.com/GFW-knocker/Xray-core/common/protocol"
	"github.com/GFW-knocker/Xray-core/common/serial"
	"github.com/GFW-knocker/Xray-core/common/session"
	"github.com/GFW-knocker/Xray-core/common/uuid"
	core "github.com/GFW-knocker/Xray-core/core"
	"github.com/GFW-knocker/Xray-core/proxy"
	"github.com/GFW-knocker/Xray-core/proxy/vless"
	"github.com/GFW-knocker/Xray-core/proxy/vless/encoding"
	vlessoutbound "github.com/GFW-knocker/Xray-core/proxy/vless/outbound"
	"github.com/GFW-knocker/Xray-core/transport"
	"github.com/GFW-knocker/Xray-core/transport/internet/stat"
	"github.com/GFW-knocker/Xray-core/transport/pipe"
	"google.golang.org/protobuf/proto"
)

// pipeDialer hands Process one end of an in-memory connection.
type pipeDialer struct{ conn net.Conn }

func (d pipeDialer) Dial(context.Context, xnet.Destination) (stat.Connection, error) {
	return d.conn, nil
}
func (pipeDialer) DestIpAddress() xnet.IP                                { return nil }
func (pipeDialer) SetOutboundGateway(context.Context, *session.Outbound) {}

func endpoint(id string) *protocol.ServerEndpoint {
	return &protocol.ServerEndpoint{
		Address: xnet.NewIPOrDomain(xnet.DomainAddress("server.example.com")),
		Port:    443,
		User: &protocol.User{
			Account: serial.ToTypedMessage(&vless.Account{Id: id, Encryption: "none"}),
		},
	}
}

func jvlessConfig(id string) proto.Message { return &Config{Vnext: endpoint(id)} }
func vlessConfig(id string) proto.Message  { return &vlessoutbound.Config{Vnext: endpoint(id)} }

// newHandler goes through the config registry, the same way core builds outbounds.
func newHandler(t *testing.T, config proto.Message) proxy.Outbound {
	t.Helper()
	instance, err := core.New(&core.Config{})
	common.Must(err)
	h, err := core.CreateObject(instance, config)
	common.Must(err)
	return h.(proxy.Outbound)
}

type exchange struct {
	sent    byte // version byte the client wrote
	request *protocol.RequestHeader
	echoed  []byte
	err     error // from Process
}

// roundTrip sends one TCP request through h to a fake server that answers
// with the reply version byte and echoes the payload. It sticks to t.Errorf
// since the concurrency test calls it off the test goroutine.
func roundTrip(t *testing.T, h proxy.Outbound, id string, reply byte) exchange {
	t.Helper()
	account, err := (&vless.Account{Id: id}).AsAccount()
	common.Must(err)
	validator := new(vless.MemoryValidator)
	common.Must(validator.Add(&protocol.MemoryUser{Account: account}))

	payload := []byte("hello " + id)
	client, server := net.Pipe()
	served := make(chan exchange, 1)
	go func() {
		defer server.Close()
		var ex exchange
		first := make([]byte, 1)
		if _, ex.err = io.ReadFull(server, first); ex.err != nil {
			served <- ex
			return
		}
		ex.sent = first[0]
		// Everything after the version byte has to be plain VLESS, so the
		// stock decoder reads the rest once the byte is swapped back.
		_, ex.request, _, _, ex.err = encoding.DecodeRequestHeader(false, nil, io.MultiReader(bytes.NewReader([]byte{encoding.Version}), server), validator)
		if ex.err == nil {
			ex.echoed = make([]byte, len(payload))
			_, ex.err = io.ReadFull(server, ex.echoed)
		}
		served <- ex
		if ex.err == nil {
			// Write errors are expected when the client rejects the reply.
			encoding.EncodeResponseHeader(server, &protocol.RequestHeader{Version: reply}, &encoding.Addons{})
			server.Write(ex.echoed)
		}
	}()

	upReader, upWriter := pipe.New(pipe.WithoutSizeLimit())
	downReader, downWriter := pipe.New(pipe.WithoutSizeLimit())
	common.Must(upWriter.WriteMultiBuffer(buf.MergeBytes(nil, payload)))
	common.Must(upWriter.Close())

	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: xnet.TCPDestination(xnet.DomainAddress("example.com"), 443),
	}})
	err = h.Process(ctx, &transport.Link{Reader: upReader, Writer: downWriter}, pipeDialer{client})

	ex := <-served
	if ex.err != nil {
		t.Errorf("server failed to read the request: %v", ex.err)
		return ex
	}
	if ex.request.Command != protocol.RequestCommandTCP || ex.request.Address.String() != "example.com" || ex.request.Port != 443 {
		t.Errorf("server decoded the wrong target: %v %v:%v", ex.request.Command, ex.request.Address, ex.request.Port)
	}
	if ex.err = err; err == nil {
		ex.echoed, err = io.ReadAll(&buf.BufferedReader{Reader: downReader})
		if err != nil || !bytes.Equal(ex.echoed, payload) {
			t.Errorf("got %q back (%v), want %q", ex.echoed, err, payload)
		}
	}
	return ex
}

func randomID() string { return protocol.NewID(uuid.New()).String() }

var ids = []string{
	randomID(),
	randomID(),
	"00000000-0000-0000-0000-000000000000",
	"00787878-7878-4878-8878-787878787878",
	"78000000-0000-4000-8000-000000000000",
	"78787878-7878-7878-7878-787878787878",
	"ffffffff-ffff-ffff-ffff-ffffffffffff",
}

func TestJVLESSVersion(t *testing.T) {
	for _, id := range ids {
		ex := roundTrip(t, newHandler(t, jvlessConfig(id)), id, Version)
		if ex.err != nil {
			t.Fatalf("%s: %v", id, ex.err)
		}
		if ex.sent != 0x78 {
			t.Fatalf("%s: wrote version %#x, want 0x78", id, ex.sent)
		}
	}
}

func TestVLESSVersionUnchanged(t *testing.T) {
	for _, id := range ids {
		ex := roundTrip(t, newHandler(t, vlessConfig(id)), id, encoding.Version)
		if ex.err != nil {
			t.Fatalf("%s: %v", id, ex.err)
		}
		if ex.sent != 0 {
			t.Fatalf("%s: wrote version %#x, want 0", id, ex.sent)
		}
	}
}

func TestResponseVersionMismatch(t *testing.T) {
	id := randomID()
	for _, tc := range []struct {
		name   string
		config proto.Message
		reply  byte
	}{
		{"jvless gets 0x00", jvlessConfig(id), 0x00},
		{"jvless gets mvless", jvlessConfig(id), 150},
		{"vless gets 0x78", vlessConfig(id), 0x78},
	} {
		ex := roundTrip(t, newHandler(t, tc.config), id, tc.reply)
		if ex.err == nil || !strings.Contains(ex.err.Error(), "unexpected response version") {
			t.Errorf("%s: got %v, want a response version error", tc.name, ex.err)
		}
	}
}

func TestVLESSAndJVLESSConcurrently(t *testing.T) {
	id := randomID()
	jvlessHandler := newHandler(t, jvlessConfig(id))
	vlessHandler := newHandler(t, vlessConfig(id))

	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if ex := roundTrip(t, jvlessHandler, id, Version); ex.err != nil || ex.sent != 0x78 {
				t.Errorf("jvless: version %#x, err %v", ex.sent, ex.err)
			}
		})
		wg.Go(func() {
			if ex := roundTrip(t, vlessHandler, id, encoding.Version); ex.err != nil || ex.sent != 0 {
				t.Errorf("vless: version %#x, err %v", ex.sent, ex.err)
			}
		})
	}
	wg.Wait()
}

func TestConfigRoundTrip(t *testing.T) {
	id := randomID()
	config := jvlessConfig(id)

	wire, err := proto.Marshal(serial.ToTypedMessage(config))
	common.Must(err)
	tm := new(serial.TypedMessage)
	common.Must(proto.Unmarshal(wire, tm))
	if tm.Type != "xray.proxy.jvless.outbound.Config" {
		t.Fatalf("typed message type is %q", tm.Type)
	}
	decoded, err := tm.GetInstance()
	common.Must(err)
	if _, ok := decoded.(*Config); !ok || !proto.Equal(decoded, config) {
		t.Fatalf("round trip changed the config: %v", decoded)
	}

	if ex := roundTrip(t, newHandler(t, decoded), id, Version); ex.err != nil || ex.sent != 0x78 {
		t.Fatalf("decoded config: version %#x, err %v", ex.sent, ex.err)
	}
}
