package quicdial_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/GFW-knocker/Xray-core/transport/internet/quicdial"
	"github.com/apernet/quic-go"
)

// record returns a Dialer that logs the version list of each attempt and
// succeeds only on the version in okOn (0 meaning never).
func record(seen *[][]quic.Version, okOn quic.Version) quicdial.Dialer {
	return func(cfg *quic.Config) (*quic.Conn, error) {
		*seen = append(*seen, cfg.Versions)
		if okOn != 0 && len(cfg.Versions) > 0 && cfg.Versions[0] == okOn {
			return nil, nil // nil conn is fine; only the error matters here
		}
		return nil, errors.New("handshake failed")
	}
}

func names(lists [][]quic.Version) []string {
	out := make([]string, 0, len(lists))
	for _, l := range lists {
		out = append(out, quicdial.Names(l))
	}
	return out
}

func eq(a []string, b ...string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestPrefersV2(t *testing.T) {
	var seen [][]quic.Version
	_, err := quicdial.Dial(context.Background(), &quic.Config{}, quicdial.H3, nil,
		record(&seen, quic.Version2))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if got := names(seen); !eq(got, "v2") {
		t.Errorf("attempts = %v, want [v2] only", got)
	}
}

func TestFallsBackToV1(t *testing.T) {
	var seen [][]quic.Version
	_, err := quicdial.Dial(context.Background(), &quic.Config{}, quicdial.H3, nil,
		record(&seen, quic.Version1))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if got := names(seen); !eq(got, "v2", "v1") {
		t.Errorf("attempts = %v, want [v2 v1]", got)
	}
}

func TestPlainOffersBothFirst(t *testing.T) {
	// The non-HTTP/3 order leans on QUIC's own version negotiation first.
	var seen [][]quic.Version
	quicdial.Dial(context.Background(), &quic.Config{}, quicdial.Plain, nil,
		record(&seen, 0))
	if got := names(seen); !eq(got, "v2+v1", "v1") {
		t.Errorf("attempts = %v, want [v2+v1 v1]", got)
	}
}

func TestAllFailingReturnsError(t *testing.T) {
	var seen [][]quic.Version
	_, err := quicdial.Dial(context.Background(), &quic.Config{}, quicdial.H3, nil,
		record(&seen, 0))
	if err == nil {
		t.Fatal("want an error when every version fails")
	}
	if len(seen) != len(quicdial.H3) {
		t.Errorf("tried %d attempts, want %d", len(seen), len(quicdial.H3))
	}
}

func TestStickyPrefersLastWorkingVersion(t *testing.T) {
	pref := new(atomic.Int32)

	var first [][]quic.Version
	quicdial.Dial(context.Background(), &quic.Config{}, quicdial.H3, pref,
		record(&first, quic.Version1))
	if got := names(first); !eq(got, "v2", "v1") {
		t.Fatalf("first dial = %v, want [v2 v1]", got)
	}

	// Second dial must go straight to v1 rather than re-paying the v2 failure.
	var second [][]quic.Version
	quicdial.Dial(context.Background(), &quic.Config{}, quicdial.H3, pref,
		record(&second, quic.Version1))
	if got := names(second); !eq(got, "v1") {
		t.Errorf("second dial = %v, want [v1] only", got)
	}
}

func TestStickyStillFallsBackIfPreferenceStops(t *testing.T) {
	pref := new(atomic.Int32)
	pref.Store(1) // pretend v1 worked last time

	// Now only v2 works; the sticky choice must not trap us on v1.
	var seen [][]quic.Version
	_, err := quicdial.Dial(context.Background(), &quic.Config{}, quicdial.H3, pref,
		record(&seen, quic.Version2))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if got := names(seen); !eq(got, "v1", "v2") {
		t.Errorf("attempts = %v, want [v1 v2]", got)
	}
}

func TestCancelledContextStopsRetrying(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var seen [][]quic.Version
	_, err := quicdial.Dial(ctx, &quic.Config{}, quicdial.H3, nil, record(&seen, 0))
	if err == nil {
		t.Fatal("want an error")
	}
	if len(seen) != 1 {
		t.Errorf("tried %d attempts on a cancelled context, want 1", len(seen))
	}
}

func TestBaseConfigNotMutated(t *testing.T) {
	base := &quic.Config{MaxIncomingStreams: 7}
	var seen [][]quic.Version
	quicdial.Dial(context.Background(), base, quicdial.H3, nil, record(&seen, 0))
	if base.Versions != nil {
		t.Errorf("base config Versions = %v, want untouched nil", base.Versions)
	}
	if base.MaxIncomingStreams != 7 {
		t.Error("base config was modified")
	}
}
