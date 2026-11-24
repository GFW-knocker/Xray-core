package jtrojan_test

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/GFW-knocker/Xray-core/proxy/jtrojan"
	"github.com/GFW-knocker/Xray-core/proxy/trojan"
	"github.com/google/uuid"
)

func TestKey(t *testing.T) {
	const password = "21078987-1334-4000-0005-000000000001"
	a, err := (&jtrojan.Account{Password: password}).AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.MustParse(password)
	sum := sha256.Sum224([]byte(password))
	want := string(id[:]) + hex.EncodeToString(sum[:])[16:]
	if got := string(a.(*trojan.MemoryAccount).Key); got != want {
		t.Fatalf("key %q, want %q", got, want)
	}

	if _, err := (&jtrojan.Account{Password: "short"}).AsAccount(); err == nil {
		t.Fatal("non-UUID password was accepted")
	}
}
