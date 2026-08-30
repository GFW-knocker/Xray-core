package freedom

import (
	"bytes"
	"testing"
)

// tlsRecord builds a handshake record of n payload bytes, the shape
// FragmentWriter's "tlshello" path expects.
func tlsRecord(n int) []byte {
	b := make([]byte, 5+n)
	b[0] = 22
	b[1] = 3
	b[2] = 1
	b[3] = byte(n >> 8)
	b[4] = byte(n)
	for i := range n {
		b[5+i] = byte(i)
	}
	return b
}

// reassemble parses the fragmented stream back into a single payload, so the
// test proves the split is lossless as well as in-bounds.
func reassemble(t *testing.T, out []byte) []byte {
	t.Helper()
	var got []byte
	for i := 0; i < len(out); {
		if len(out)-i < 5 {
			t.Fatalf("truncated record header at offset %d", i)
		}
		l := (int(out[i+3]) << 8) | int(out[i+4])
		if i+5+l > len(out) {
			t.Fatalf("record at %d claims %d bytes, only %d left", i, l, len(out)-i-5)
		}
		got = append(got, out[i+5:i+5+l]...)
		i += 5 + l
	}
	return got
}

func TestFragmentWriterBounds(t *testing.T) {
	cases := []struct {
		name                               string
		lenMin, lenMax, batchMin, batchMax uint64
		payload                            int
	}{
		{"default", 3, 5, 10, 20, 517},
		{"len1_batch100000", 1, 1, 100000, 100000, 2000},
		{"len1_batch100000_maxrecord", 1, 1, 100000, 100000, 65535},
		{"len1_defaultbatch", 1, 1, 10, 20, 65535},
		{"lengthLargerThanRecord", 1, 100000, 10, 20, 2000},
		{"batchZero", 3, 5, 0, 0, 1200},
		{"lenMinLargerThanRecord", 5000, 100000, 5, 9, 300},
		{"emptyRecord", 3, 5, 10, 20, 0},
		{"singleByteRecord", 3, 5, 10, 20, 1},
		{"absurdBatch", 2, 4, 1 << 62, 1 << 62, 4096},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var sink bytes.Buffer
			w := &FragmentWriter{
				fragment: &Fragment{
					PacketsFrom: 0,
					PacketsTo:   1,
					LengthMin:   tc.lenMin,
					LengthMax:   tc.lenMax,
					IntervalMin: 0,
					IntervalMax: 0,
					BatchMin:    tc.batchMin,
					BatchMax:    tc.batchMax,
				},
				writer: &sink,
			}

			in := tlsRecord(tc.payload)
			n, err := w.Write(in)
			if err != nil {
				t.Fatalf("Write: %v", err)
			}
			if n != len(in) {
				t.Fatalf("Write returned %d, want %d", n, len(in))
			}

			got := reassemble(t, sink.Bytes())
			if !bytes.Equal(got, in[5:]) {
				t.Fatalf("payload mismatch: got %d bytes, want %d", len(got), len(in)-5)
			}
		})
	}
}
