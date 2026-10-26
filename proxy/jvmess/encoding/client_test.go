package encoding

import (
	"bytes"
	"context"
	"testing"

	"github.com/GFW-knocker/Xray-core/common"
	"github.com/GFW-knocker/Xray-core/common/net"
	"github.com/GFW-knocker/Xray-core/common/protocol"
	"github.com/GFW-knocker/Xray-core/common/uuid"
	"github.com/GFW-knocker/Xray-core/proxy/jvmess"
	vmessaead "github.com/GFW-knocker/Xray-core/proxy/vmess/aead"
)

func TestEncodeRequestHeaderUsesIDAsKey(t *testing.T) {
	id := protocol.NewID(uuid.New())
	header := &protocol.RequestHeader{
		Version:  Version,
		User:     &protocol.MemoryUser{Account: &jvmess.MemoryAccount{ID: id, Security: protocol.SecurityType_AES128_GCM}},
		Command:  protocol.RequestCommandTCP,
		Address:  net.DomainAddress("example.com"),
		Port:     443,
		Security: protocol.SecurityType_AES128_GCM,
	}

	session := NewClientSession(context.Background(), 0)
	var out bytes.Buffer
	common.Must(session.EncodeRequestHeader(header, &out))
	wire := out.Bytes()

	var key [16]byte
	copy(key[:], id.Bytes())
	if !bytes.Equal(wire[:16], key[:]) {
		t.Fatal("first 16 wire bytes must be the raw id")
	}

	plain, drain, _, err := vmessaead.OpenVMessAEADHeader(key, key, bytes.NewReader(wire[16:]))
	if err != nil || drain {
		t.Fatalf("open failed: drain=%v err=%v", drain, err)
	}
	if plain[0] != Version || !bytes.Equal(plain[1:17], session.requestBodyIV[:]) || !bytes.Equal(plain[17:33], session.requestBodyKey[:]) {
		t.Fatal("decoded header does not carry the session body iv and key")
	}
}
