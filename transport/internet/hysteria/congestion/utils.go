package congestion

import (
	"context"
	"fmt"
	"strings"

	"github.com/GFW-knocker/Xray-core/common/errors"
	"github.com/GFW-knocker/Xray-core/transport/internet/hysteria/congestion/bbr"
	"github.com/GFW-knocker/Xray-core/transport/internet/hysteria/congestion/brutal"
	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/congestion"
)

const (
	TypeBBR  = "bbr"
	TypeReno = "reno"
)

func NormalizeType(congestionType string) (string, error) {
	switch normalized := strings.ToLower(congestionType); normalized {
	case "", TypeBBR:
		return TypeBBR, nil
	case TypeReno:
		return TypeReno, nil
	default:
		return "", fmt.Errorf("unsupported congestion type %q", congestionType)
	}
}

func NormalizeBBRProfile(profile string) (string, error) {
	normalized, err := bbr.ParseProfile(profile)
	if err != nil {
		return "", err
	}
	return string(normalized), nil
}

func UseBBR(conn *quic.Conn, profile bbr.Profile) {
	conn.SetCongestionControl(bbr.NewBbrSender(
		bbr.DefaultClock{},
		seedPacketSize(conn.InitialPacketSize(), bbr.GetInitialPacketSize(conn.RemoteAddr())),
		profile,
	))
}

// seedPacketSize picks the datagram size to seed a replacement congestion
// controller with, given the size QUIC itself starts at and the guess derived
// from the remote address.
//
// The seed must not exceed what QUIC actually starts at. If it does, the first
// path MTU probe can land between the two: QUIC sees an increase and reports
// it, but the controller sees a decrease, which it cannot represent. Taking the
// smaller of the two keeps the address-based guess as a floor for connections
// whose path we can't reason about, while never seeding above QUIC.
func seedPacketSize(quicSize, byAddr congestion.ByteCount) congestion.ByteCount {
	if quicSize <= 0 {
		return byAddr
	}
	return min(quicSize, byAddr)
}

func UseBrutal(conn *quic.Conn, tx uint64, disableLossCompensation bool) {
	conn.SetCongestionControl(brutal.NewBrutalSender(tx, disableLossCompensation))
}

// The values of the quicParams "congestion" setting that are not plain
// algorithm names.
const (
	TypeBrutal      = "brutal"
	TypeForceBrutal = "force-brutal"
)

// UseNamed applies a quicParams "congestion" setting to conn. It never panics:
// a value it cannot honour falls back to BBR with a log line, so a config that
// slipped past validation (an API-pushed one, say) degrades instead of taking
// the process down.
//
//   - empty is what "" means to the caller: "brutal" for hysteria, "bbr" for
//     xhttp and masque, "reno" for xdns.
//   - "brutal" sends at the lower of brutalUp and peerRx, the receive rate the
//     peer announced. Only hysteria announces one; everywhere else peerRx is 0,
//     and "brutal" falls back to BBR exactly as hysteria does when either rate
//     is unknown. "force-brutal" is the way to send at brutalUp regardless.
//   - "force-brutal" with no brutalUp would pace at zero and stall the
//     connection for good, so it falls back to BBR as well.
func UseNamed(conn *quic.Conn, name, empty, bbrProfile string, brutalUp, peerRx uint64, disableLossCompensation bool) {
	if name == "" {
		name = empty
	}
	switch name {
	case TypeReno:
	case TypeBBR:
		UseBBR(conn, bbr.Profile(bbrProfile))
	case TypeBrutal:
		if brutalUp == 0 || peerRx == 0 {
			UseBBR(conn, bbr.Profile(bbrProfile))
		} else {
			UseBrutal(conn, min(brutalUp, peerRx), disableLossCompensation)
		}
	case TypeForceBrutal:
		if brutalUp == 0 {
			errors.LogWarning(context.Background(), `congestion "force-brutal" without "brutalUp", using BBR`)
			UseBBR(conn, bbr.Profile(bbrProfile))
		} else {
			UseBrutal(conn, brutalUp, disableLossCompensation)
		}
	default:
		errors.LogError(context.Background(), `unknown congestion control "`, name, `", using BBR`)
		UseBBR(conn, bbr.Profile(bbrProfile))
	}
}

func UseConfigured(conn *quic.Conn, congestionType, bbrProfile string) {
	switch congestionType {
	case TypeReno:
		return
	default:
		UseBBR(conn, bbr.Profile(bbrProfile))
	}
}
