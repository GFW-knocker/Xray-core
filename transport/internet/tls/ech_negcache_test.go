package tls

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// newECHTestCache registers an empty cache entry under the key queryECHConfig
// will actually compute for this server/domain pair.
func newECHTestCache(t *testing.T, server, domain string) (*ECHConfigCache, string) {
	t.Helper()
	key := ECHCacheKey(server, domain, nil)
	cache := &ECHConfigCache{}
	cache.configRecord.Store(&echConfigRecord{})
	GlobalECHConfigCache.Store(key, cache)
	t.Cleanup(func() { GlobalECHConfigCache.Delete(key) })
	return cache, key
}

// A failing lookup must be remembered, so later dials fail fast instead of each
// paying the full timeout again.
func TestECHNegativeCacheStopsRepeatedLookups(t *testing.T) {
	newECHTestCache(t, "udp://neg.invalid:53", "neg.invalid")

	var calls atomic.Int32
	boom := errors.New("dns unreachable")
	fetch := func() ([]byte, uint32, error) {
		calls.Add(1)
		return nil, 0, boom
	}

	for i := range 5 {
		_, err := queryECHConfig("udp://neg.invalid:53", "neg.invalid", nil, fetch)
		if !errors.Is(err, boom) {
			t.Fatalf("dial %d: want the fetch error, got %v", i, err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("lookup ran %d times, want 1 (failure was not cached)", got)
	}
}

// Concurrent dials must not queue on UpdateLock and then each redo the lookup.
func TestECHNegativeCacheCollapsesConcurrentDials(t *testing.T) {
	newECHTestCache(t, "udp://herd.invalid:53", "herd.invalid")

	var calls atomic.Int32
	boom := errors.New("dns unreachable")
	fetch := func() ([]byte, uint32, error) {
		calls.Add(1)
		time.Sleep(150 * time.Millisecond) // stand in for a network timeout
		return nil, 0, boom
	}

	start := time.Now()
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			queryECHConfig("udp://herd.invalid:53", "herd.invalid", nil, fetch)
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	if got := calls.Load(); got != 1 {
		t.Errorf("lookup ran %d times for 8 concurrent dials, want 1", got)
	}
	if elapsed > time.Second {
		t.Errorf("8 concurrent dials took %v, expected roughly one lookup", elapsed)
	}
}

// The failure must be forgotten once it expires, so recovery is picked up.
func TestECHNegativeCacheExpires(t *testing.T) {
	cache, _ := newECHTestCache(t, "udp://recover.invalid:53", "recover.invalid")

	boom := errors.New("dns unreachable")
	if _, err := queryECHConfig("udp://recover.invalid:53", "recover.invalid", nil,
		func() ([]byte, uint32, error) { return nil, 0, boom }); !errors.Is(err, boom) {
		t.Fatalf("want failure, got %v", err)
	}
	rec := cache.configRecord.Load()
	if rec.err == nil || rec.expire.IsZero() {
		t.Fatal("no negative record was stored")
	}

	// age it out
	cache.configRecord.Store(&echConfigRecord{err: rec.err, expire: time.Now().Add(-time.Second)})

	good := []byte("fresh-config")
	got, err := queryECHConfig("udp://recover.invalid:53", "recover.invalid", nil,
		func() ([]byte, uint32, error) { return good, 300, nil })
	if err != nil {
		t.Fatalf("recovery lookup failed: %v", err)
	}
	if string(got) != string(good) {
		t.Errorf("got %q, want %q", got, good)
	}
}

// The regression that matters most: a background refresh that fails must not
// throw away a config that is still being served.
func TestECHFailedRefreshKeepsExistingConfig(t *testing.T) {
	cache, _ := newECHTestCache(t, "udp://keep.invalid:53", "keep.invalid")

	existing := []byte("still-usable")
	cache.configRecord.Store(&echConfigRecord{
		config: existing,
		expire: time.Now().Add(-time.Minute), // expired, but inside the stale-serve window
	})

	boom := errors.New("dns unreachable")
	// A locked update is what the background refresh goroutine performs.
	if _, err := cache.UpdateWith("keep.invalid", "udp://keep.invalid:53", true,
		func() ([]byte, uint32, error) { return nil, 0, boom }); !errors.Is(err, boom) {
		t.Fatalf("want failure, got %v", err)
	}

	rec := cache.configRecord.Load()
	if string(rec.config) != string(existing) {
		t.Fatalf("failed refresh discarded the usable config, got %q", rec.config)
	}
	if rec.err != nil {
		t.Error("failed refresh turned a usable entry into a negative one")
	}
}

// Invalidation from RefineECHError must still force a fresh synchronous fetch.
func TestECHInvalidateStillForcesRefetch(t *testing.T) {
	cache, key := newECHTestCache(t, "udp://inval.invalid:53", "inval.invalid")
	cache.configRecord.Store(&echConfigRecord{config: []byte("stale"), expire: time.Now().Add(time.Hour)})

	if !invalidateECHConfig(key) {
		t.Fatal("invalidateECHConfig reported no entry")
	}
	var calls atomic.Int32
	got, err := queryECHConfig("udp://inval.invalid:53", "inval.invalid", nil,
		func() ([]byte, uint32, error) { calls.Add(1); return []byte("fresh"), 300, nil })
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "fresh" || calls.Load() != 1 {
		t.Errorf("got %q after %d lookups, want \"fresh\" after 1", got, calls.Load())
	}
}
