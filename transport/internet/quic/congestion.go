package quic

import (
	"github.com/GFW-knocker/Xray-core/transport/internet"
	"github.com/GFW-knocker/Xray-core/transport/internet/hysteria/congestion"
	"github.com/apernet/quic-go"
)

// useCongestion swaps in the congestion control named by finalmask
// "quicParams".congestion. Only an explicit setting does anything: without one
// the connection keeps quic-go's own, as the quic transport always had.
// "network": "quictcp" sets BBR, because spreading datagrams over many TCP
// lanes reorders them and loss-based control reads that as loss.
func useCongestion(conn *quic.Conn, qp *internet.QuicParams) {
	if conn == nil || qp == nil || qp.Congestion == "" {
		return
	}
	// the peer's receive rate is unknown here, so "brutal" means BBR and
	// "force-brutal" sends at brutalUp
	congestion.UseNamed(conn, qp.Congestion, congestion.TypeBBR, qp.BbrProfile, qp.BrutalUp, 0, qp.BrutalDisableLossCompensation)
}
