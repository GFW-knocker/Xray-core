package conf_test

import (
	"testing"

	. "github.com/GFW-knocker/Xray-core/infra/conf"
	"github.com/GFW-knocker/Xray-core/proxy/freedom"
)

func TestFreedomFragmentLength(t *testing.T) {
	cases := []struct {
		packets, length string
		wantErr         bool
		min, max        uint64
		minor           uint32
	}{
		{"tlshello", "10-20", false, 10, 20, 0},
		{"tlshello", "20-10", false, 10, 20, 0},
		{"tlshello", "5", false, 5, 5, 0},
		{"tlshello", "0-30", false, 1, 30, 0x01},
		{"tlshello", "-1-30", false, 1, 30, 0x02},
		{"tlshello", "-2-7", false, 1, 7, 0x03},
		{"tlshello", "-254-5", false, 1, 5, 0xff},
		{"tlshello", "0", false, 1, 20, 0x01},
		{"tlshello", "-1", false, 1, 20, 0x02},
		{"tlshello", "-254", false, 1, 20, 0xff},
		{"tlshello", "30-0", false, 1, 30, 0x01},
		{"1-3", "-5-9", false, 1, 9, 0},
		{"1-3", "0", false, 1, 20, 0},
		{"tlshello", "-255-5", true, 0, 0, 0},
		{"tlshello", "-255", true, 0, 0, 0},
		{"tlshello", "0-0", true, 0, 0, 0},
		{"tlshello", "20--5", true, 0, 0, 0},
		{"tlshello", "-1-70000", true, 0, 0, 0},
		{"tlshello", "--1", true, 0, 0, 0},
		{"tlshello", "abc", true, 0, 0, 0},
		{"tlshello", "", true, 0, 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.packets+"/"+tc.length, func(t *testing.T) {
			c := &FreedomConfig{Fragment: &Fragment{Packets: tc.packets, Length: tc.length, Interval: "0"}}
			m, err := c.Build()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got config %+v", m.(*freedom.Config).Fragment)
				}
				return
			}
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			f := m.(*freedom.Config).Fragment
			if f.LengthMin != tc.min || f.LengthMax != tc.max || f.EmptyRecordMinor != tc.minor {
				t.Fatalf("got min=%d max=%d minor=%#x, want min=%d max=%d minor=%#x",
					f.LengthMin, f.LengthMax, f.EmptyRecordMinor, tc.min, tc.max, tc.minor)
			}
		})
	}
}
