package noise

import (
	"encoding/hex"
	"testing"
)

func TestQuicInitPacket(t *testing.T) {
	// All three of size, first byte and version are what make the prime work,
	// so all three are asserted along with the header layout around them.
	p := quicInitPacket()
	if p == nil {
		t.Fatal("quicInitPacket returned nil")
	}
	if len(p) != quicInitSize {
		t.Fatalf("length = %d, want %d", len(p), quicInitSize)
	}
	if p[0]&0xF0 != 0xC0 {
		t.Errorf("first byte = %#x, want 0xc0-0xcf (long header, Initial)", p[0])
	}
	if got := hex.EncodeToString(p[1:5]); got != "6b3343cf" {
		t.Errorf("version = %s, want 6b3343cf (QUIC v2)", got)
	}
	if p[5] != 8 {
		t.Errorf("DCID length = %#x, want 0x08", p[5])
	}
	if p[14] != 8 {
		t.Errorf("SCID length = %#x, want 0x08", p[14])
	}
	if p[23] != 0x00 {
		t.Errorf("token length = %#x, want 0x00", p[23])
	}
	if got := hex.EncodeToString(p[24:26]); got != "4400" {
		t.Errorf("length varint = %s, want 4400", got)
	}
}

func TestQuicHeaderVersions(t *testing.T) {
	// "quic" must emit QUIC v2 (RFC 9369) and "quicv1" the old v1 (RFC 9000).
	for _, tc := range []struct {
		gen     string
		version string
	}{
		{GenQUIC, "6b3343cf"},
		{GenQUICv1, "00000001"},
	} {
		t.Run(tc.gen, func(t *testing.T) {
			p := generate(tc.gen)
			if len(p) != 18 {
				t.Fatalf("length = %d, want 18", len(p))
			}
			if got := hex.EncodeToString(p[1:5]); got != tc.version {
				t.Errorf("version = %s, want %s", got, tc.version)
			}
			if p[5] != 0x08 {
				t.Errorf("DCID length = %#x, want 0x08", p[5])
			}
			if got := hex.EncodeToString(p[14:18]); got != "000044d0" {
				t.Errorf("trailer = %s, want 000044d0", got)
			}
		})
	}
}

func TestQuicHeaderFirstByteSpread(t *testing.T) {
	// The first byte is a random pick from clist: every index must be
	// reachable, and nothing outside the list may appear.
	clist := map[byte]bool{0xDC: true, 0xDE: true, 0xD3: true, 0xD9: true, 0xD0: true, 0xEC: true, 0xEE: true, 0xE3: true}
	seen := map[byte]bool{}
	for i := 0; i < 400; i++ {
		p := generate(GenQUIC)
		if !clist[p[0]] {
			t.Fatalf("first byte %#x is not in clist", p[0])
		}
		seen[p[0]] = true
	}
	if len(seen) != len(clist) {
		t.Errorf("only %d of %d clist entries seen over 400 packets", len(seen), len(clist))
	}
}

func TestGeneratorsRerollPerCall(t *testing.T) {
	// The point of a generator over a literal packet is that nothing is
	// constant on the wire, so the connection IDs must differ every time.
	for _, tc := range []struct {
		gen  string
		dcid [2]int
	}{
		{GenQUIC, [2]int{6, 14}},
		{GenQUICInit, [2]int{6, 14}},
	} {
		t.Run(tc.gen, func(t *testing.T) {
			seen := map[string]bool{}
			const n = 64
			for i := 0; i < n; i++ {
				p := generate(tc.gen)
				seen[hex.EncodeToString(p[tc.dcid[0]:tc.dcid[1]])] = true
			}
			if len(seen) != n {
				t.Errorf("%d distinct connection IDs over %d packets, want all distinct", len(seen), n)
			}
		})
	}
}

func TestIsGenerator(t *testing.T) {
	for _, name := range []string{GenQUIC, GenQUICv1, GenQUICInit} {
		if !IsGenerator(name) {
			t.Errorf("IsGenerator(%q) = false, want true", name)
		}
		if generate(name) == nil {
			t.Errorf("generate(%q) = nil, want a packet", name)
		}
	}
	for _, name := range []string{"", "none", "random", "QUIC", "quicinit2"} {
		if IsGenerator(name) {
			t.Errorf("IsGenerator(%q) = true, want false", name)
		}
		if generate(name) != nil {
			t.Errorf("generate(%q) returned a packet, want nil", name)
		}
	}
	if !IsFixedSize(GenQUICInit) {
		t.Error("IsFixedSize(quicinit) = false, want true")
	}
	for _, name := range []string{GenQUIC, GenQUICv1, ""} {
		if IsFixedSize(name) {
			t.Errorf("IsFixedSize(%q) = true, want false", name)
		}
	}
}

func TestItemDatagram(t *testing.T) {
	// rand alone and packet alone must behave exactly as they did before
	// generators existed; gen and gen+rand are the new shapes.
	literal := []byte{0xd0, 0x6b, 0x33, 0x43, 0xcf}

	t.Run("rand only", func(t *testing.T) {
		buf, ok := (&Item{RandMin: 18, RandMax: 18, RandRangeMax: 255}).datagram()
		if !ok || len(buf) != 18 {
			t.Fatalf("len = %d, ok = %v, want 18, true", len(buf), ok)
		}
	})

	t.Run("packet only", func(t *testing.T) {
		buf, ok := (&Item{Packet: literal}).datagram()
		if !ok || hex.EncodeToString(buf) != "d06b3343cf" {
			t.Fatalf("buf = %x, ok = %v, want the literal verbatim", buf, ok)
		}
	})

	t.Run("empty item still sends", func(t *testing.T) {
		// Pre-generator behaviour: an item with neither shape wrote a
		// zero-length datagram rather than being skipped.
		buf, ok := (&Item{}).datagram()
		if !ok || len(buf) != 0 {
			t.Fatalf("len = %d, ok = %v, want 0, true", len(buf), ok)
		}
	})

	t.Run("packet plus rand", func(t *testing.T) {
		buf, ok := (&Item{Packet: literal, RandMin: 5, RandMax: 5, RandRangeMax: 255}).datagram()
		if !ok || len(buf) != 10 {
			t.Fatalf("len = %d, ok = %v, want 10, true", len(buf), ok)
		}
		if hex.EncodeToString(buf[:5]) != "d06b3343cf" {
			t.Errorf("head = %x, want the literal", buf[:5])
		}
	})

	t.Run("gen only", func(t *testing.T) {
		buf, ok := (&Item{Gen: GenQUICInit}).datagram()
		if !ok || len(buf) != quicInitSize {
			t.Fatalf("len = %d, ok = %v, want %d, true", len(buf), ok, quicInitSize)
		}
	})

	t.Run("gen plus rand", func(t *testing.T) {
		// This is the wnoise "quic" shape: 18-byte header + wpayloadsize.
		buf, ok := (&Item{Gen: GenQUIC, RandMin: 5, RandMax: 5, RandRangeMax: 255}).datagram()
		if !ok || len(buf) != 23 {
			t.Fatalf("len = %d, ok = %v, want 23, true", len(buf), ok)
		}
		if got := hex.EncodeToString(buf[1:5]); got != "6b3343cf" {
			t.Errorf("version = %s, want 6b3343cf", got)
		}
	})

	t.Run("unknown gen is skipped", func(t *testing.T) {
		// The config builder rejects this, so it should be unreachable; if it
		// ever is reached, send nothing rather than a bare payload.
		if _, ok := (&Item{Gen: "nope", RandMin: 5, RandMax: 5}).datagram(); ok {
			t.Error("ok = true, want false")
		}
	})
}
