package aead_test

import (
	"bytes"
	"testing"

	. "github.com/GFW-knocker/Xray-core/proxy/jvmess/aead"
	vmessaead "github.com/GFW-knocker/Xray-core/proxy/vmess/aead"
)

func TestSealHeader(t *testing.T) {
	key := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	header := []byte("test header payload")

	sealed := SealHeader(key, header)
	if !bytes.Equal(sealed[:16], key[:]) {
		t.Fatal("first 16 wire bytes must be the key")
	}

	// the stock opener reads the auth value from the wire, so it must accept this layout
	opened, drain, _, err := vmessaead.OpenVMessAEADHeader(key, key, bytes.NewReader(sealed[16:]))
	if err != nil || drain {
		t.Fatalf("open failed: drain=%v err=%v", drain, err)
	}
	if !bytes.Equal(opened, header) {
		t.Fatalf("got %q, want %q", opened, header)
	}

	if bytes.Equal(SealHeader(key, header), sealed) {
		t.Fatal("sealing twice must not give identical bytes")
	}
}
