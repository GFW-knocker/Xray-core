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

type recordingWriter struct{ writes [][]byte }

func (r *recordingWriter) Write(b []byte) (int, error) {
	r.writes = append(r.writes, append([]byte(nil), b...))
	return len(b), nil
}

func TestFragmentWriterEmptyRecord(t *testing.T) {
	cases := []struct {
		name               string
		minor              uint32
		lenMax, batchMin   uint64
		batchMax           uint64
		payload            int
		wantFirstRecordsIn int
	}{
		{"minor01_batch3", 0x01, 20, 3, 3, 517, 4},
		{"minor02_batch0", 0x02, 20, 0, 0, 517, 1},
		{"minorff_len1", 0xff, 1, 10, 10, 300, 11},
		{"oneWrite", 0x03, 20, 65535, 65535, 1507, -1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sink := &recordingWriter{}
			w := &FragmentWriter{
				fragment: &Fragment{
					PacketsFrom:      0,
					PacketsTo:        1,
					LengthMin:        1,
					LengthMax:        tc.lenMax,
					BatchMin:         tc.batchMin,
					BatchMax:         tc.batchMax,
					EmptyRecordMinor: tc.minor,
				},
				writer: sink,
			}

			in := tlsRecord(tc.payload)
			if n, err := w.Write(in); err != nil || n != len(in) {
				t.Fatalf("Write = %d, %v; want %d, nil", n, err, len(in))
			}

			first := sink.writes[0]
			want := []byte{22, 3, byte(tc.minor), 0, 0}
			if !bytes.Equal(first[:5], want) {
				t.Fatalf("first write starts % x, want % x", first[:5], want)
			}

			var all []byte
			for _, b := range sink.writes {
				all = append(all, b...)
			}
			empties := 0
			for i := 0; i < len(all); {
				l := (int(all[i+3]) << 8) | int(all[i+4])
				if l == 0 {
					empties++
				} else if all[i+1] != 3 || all[i+2] != 1 {
					t.Fatalf("fragment at %d has version %02x%02x, want hello's 0301", i, all[i+1], all[i+2])
				} else if l > int(tc.lenMax) {
					t.Fatalf("fragment at %d is %d bytes, max %d", i, l, tc.lenMax)
				}
				i += 5 + l
			}
			if empties != 1 {
				t.Fatalf("found %d empty records, want 1", empties)
			}

			if tc.wantFirstRecordsIn >= 0 {
				recs := 0
				for i := 5; i < len(first); i += 5 + ((int(first[i+3]) << 8) | int(first[i+4])) {
					recs++
				}
				if recs != tc.wantFirstRecordsIn {
					t.Fatalf("first write carries %d fragments, want %d", recs, tc.wantFirstRecordsIn)
				}
			} else if len(sink.writes) != 1 {
				t.Fatalf("got %d writes, want everything in 1", len(sink.writes))
			}

			if got := reassemble(t, all); !bytes.Equal(got, in[5:]) {
				t.Fatalf("payload mismatch: got %d bytes, want %d", len(got), len(in)-5)
			}
		})
	}
}
