// Package quicdial dials QUIC preferring v2 (RFC 9369) and falling back to
// v1 (RFC 9000).
//
// v2 is preferred because some networks drop QUIC v1 Initial packets outright,
// and such a drop can poison the flow before QUIC's own version negotiation
// gets a chance to run. v1 stays reachable as a fallback so peers that do not
// implement v2 keep working.
//
// Two fallback mechanisms exist and this package uses whichever the caller can
// support:
//
//   - Plain QUIC paths can hand quic-go a list of versions and let the
//     protocol's Version Negotiation choose. That costs one extra round trip
//     at most, but it only fires when the peer actually *answers* with a
//     Version Negotiation packet.
//   - HTTP/3 paths cannot: http3.Transport rejects a config carrying more than
//     one version ("can only use a single QUIC version for dialing a HTTP/3
//     connection"). For those, a failed dial is retried a level up with the
//     next version, which also covers a peer whose v2 packets are silently
//     dropped rather than negotiated.
package quicdial

import (
	"context"
	"sync/atomic"

	"github.com/GFW-knocker/Xray-core/common/errors"
	"github.com/apernet/quic-go"
)

// Ordered dial attempts. Each entry is one dial, carrying the version list
// handed to quic-go for it.
var (
	// Plain is for dialers that talk to quic-go directly. The first attempt
	// offers both versions so Version Negotiation can settle it in-band; the
	// second forces v1 for a peer that never answered at all.
	Plain = [][]quic.Version{
		{quic.Version2, quic.Version1},
		{quic.Version1},
	}

	// H3 is for dialers that go through http3.Transport, which permits only a
	// single version per dial, so each version needs its own attempt.
	H3 = [][]quic.Version{
		{quic.Version2},
		{quic.Version1},
	}
)

// Dialer opens one QUIC connection using the supplied config.
type Dialer func(cfg *quic.Config) (*quic.Conn, error)

// Dial walks attempts until one connects, cloning base for each so the
// caller's config is never mutated.
//
// pref, when non-nil, remembers which attempt last succeeded for this peer and
// is tried first, so the fallback is paid for once instead of on every dial.
// It is safe for concurrent use.
func Dial(ctx context.Context, base *quic.Config, attempts [][]quic.Version, pref *atomic.Int32, dial Dialer) (*quic.Conn, error) {
	if len(attempts) == 0 {
		return dial(base)
	}

	order := make([]int, 0, len(attempts))
	if pref != nil {
		if i := int(pref.Load()); i > 0 && i < len(attempts) {
			order = append(order, i)
		}
	}
	for i := range attempts {
		if len(order) == 0 || order[0] != i {
			order = append(order, i)
		}
	}

	var lastErr error
	for n, i := range order {
		cfg := base.Clone()
		cfg.Versions = attempts[i]

		conn, err := dial(cfg)
		if err == nil {
			if pref != nil {
				pref.Store(int32(i))
			}
			return conn, nil
		}
		lastErr = err

		// A cancelled or expired context means the caller gave up; trying the
		// next version would just ignore that and stall.
		if ctx.Err() != nil {
			return nil, lastErr
		}
		if n < len(order)-1 {
			errors.LogInfoInner(ctx, err, "QUIC dial with ", Names(attempts[i]),
				" failed, retrying with ", Names(attempts[order[n+1]]))
		}
	}
	return nil, lastErr
}

// Names renders a version list for logs.
func Names(versions []quic.Version) string {
	out := ""
	for i, v := range versions {
		if i > 0 {
			out += "+"
		}
		switch v {
		case quic.Version1:
			out += "v1"
		case quic.Version2:
			out += "v2"
		default:
			out += v.String()
		}
	}
	if out == "" {
		return "default"
	}
	return out
}
