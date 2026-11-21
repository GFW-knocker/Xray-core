package splithttp_test

import (
	"context"
	"crypto/rand"
	"runtime"
	"testing"
	"time"

	"github.com/GFW-knocker/Xray-core/common"
	"github.com/GFW-knocker/Xray-core/common/buf"
	"github.com/GFW-knocker/Xray-core/common/net"
	"github.com/GFW-knocker/Xray-core/common/protocol/tls/cert"
	"github.com/GFW-knocker/Xray-core/testing/servers/udp"
	"github.com/GFW-knocker/Xray-core/transport/internet"
	. "github.com/GFW-knocker/Xray-core/transport/internet/splithttp"
	"github.com/GFW-knocker/Xray-core/transport/internet/stat"
	"github.com/GFW-knocker/Xray-core/transport/internet/tls"
	"github.com/google/go-cmp/cmp"
)

// Every congestion setting must leave an XHTTP/3 connection working on both
// ends. "brutal" used to reach panic() in the dialer and the listener, which
// took the whole process down; "force-brutal" without a rate and unknown names
// can still arrive through configs that skip JSON validation.
func TestXH3CongestionSettings(t *testing.T) {
	if runtime.GOARCH == "arm64" {
		return
	}
	for _, params := range []*internet.QuicParams{
		{Congestion: "brutal", BrutalUp: 10 << 20},
		{Congestion: "brutal"},
		{Congestion: "force-brutal"}, // no brutalUp: must not pace at zero
		{Congestion: "force-brutal", BrutalUp: 10 << 20},
		{Congestion: "reno"},
		{Congestion: "bbr"},
		{Congestion: "no-such-algorithm"},
	} {
		t.Run(params.Congestion, func(t *testing.T) {
			listenPort := udp.PickPort()
			ct, ctHash := cert.MustGenerate(nil, cert.CommonName("localhost"))
			streamSettings := &internet.MemoryStreamConfig{
				ProtocolName:     "splithttp",
				ProtocolSettings: &Config{Path: "shs"},
				SecurityType:     "tls",
				SecuritySettings: &tls.Config{
					Certificate:          []*tls.Certificate{tls.ParseCertificate(ct)},
					PinnedPeerCertSha256: [][]byte{ctHash[:]},
					NextProtocol:         []string{"h3"},
				},
				QuicParams: params,
			}

			listen, err := ListenXH(context.Background(), net.LocalHostIP, listenPort, streamSettings, func(conn stat.Connection) {
				go func() {
					defer conn.Close()
					b := buf.New()
					defer b.Release()
					for {
						b.Clear()
						if _, err := b.ReadFrom(conn); err != nil {
							return
						}
						common.Must2(conn.Write(b.Bytes()))
					}
				}()
			})
			common.Must(err)
			defer listen.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			conn, err := Dial(ctx, net.UDPDestination(net.DomainAddress("localhost"), listenPort), streamSettings)
			common.Must(err)
			defer conn.Close()

			const N = 1024
			b1 := make([]byte, N)
			common.Must2(rand.Read(b1))
			b2 := buf.New()
			defer b2.Release()
			common.Must2(conn.Write(b1))
			common.Must2(b2.ReadFullFrom(conn, N))
			if r := cmp.Diff(b2.Bytes(), b1); r != "" {
				t.Error(r)
			}
		})
	}
}
