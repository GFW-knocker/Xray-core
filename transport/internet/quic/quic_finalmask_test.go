package quic_test

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	"github.com/GFW-knocker/Xray-core/common"
	"github.com/GFW-knocker/Xray-core/common/buf"
	"github.com/GFW-knocker/Xray-core/common/net"
	"github.com/GFW-knocker/Xray-core/common/serial"
	"github.com/GFW-knocker/Xray-core/testing/servers/udp"
	"github.com/GFW-knocker/Xray-core/transport/internet"
	"github.com/GFW-knocker/Xray-core/transport/internet/finalmask/salamander"
	"github.com/GFW-knocker/Xray-core/transport/internet/quic"
	"github.com/GFW-knocker/Xray-core/transport/internet/stat"
	"github.com/google/go-cmp/cmp"
)

// quicStreamSettings builds quic stream settings, with a salamander mask when
// password is set. salamander rewrites every datagram, so a connection only
// comes up when both ends apply it: that is what shows the dialer and the
// listener both honour the FinalMask.
func quicStreamSettings(t *testing.T, password string) *internet.MemoryStreamConfig {
	t.Helper()
	sc := &internet.StreamConfig{
		ProtocolName: "quic",
		TransportSettings: []*internet.TransportConfig{{
			ProtocolName: "quic",
			Settings:     serial.ToTypedMessage(&quic.Config{}),
		}},
	}
	if password != "" {
		sc.Udpmasks = []*serial.TypedMessage{serial.ToTypedMessage(&salamander.Config{Password: password})}
	}
	mss, err := internet.ToMemoryStreamConfig(sc)
	common.Must(err)
	if (mss.FinalMask != nil) != (password != "") {
		t.Fatalf("FinalMask set = %v, want %v", mss.FinalMask != nil, password != "")
	}
	return mss
}

func listenEcho(t *testing.T, port net.Port, settings *internet.MemoryStreamConfig) internet.Listener {
	t.Helper()
	listener, err := quic.Listen(context.Background(), net.LocalHostIP, port, settings, func(conn stat.Connection) {
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
	return listener
}

func TestQuicConnectionWithFinalMask(t *testing.T) {
	port := udp.PickPort()
	listener := listenEcho(t, port, quicStreamSettings(t, "mask-password"))
	defer listener.Close()

	conn, err := quic.Dial(context.Background(), net.TCPDestination(net.LocalHostIP, port), quicStreamSettings(t, "mask-password"))
	common.Must(err)
	defer conn.Close()

	const N = 1024
	b1 := make([]byte, N)
	common.Must2(rand.Read(b1))
	b2 := buf.New()
	defer b2.Release()
	for i := 0; i < 2; i++ {
		common.Must2(conn.Write(b1))
		b2.Clear()
		common.Must2(b2.ReadFullFrom(conn, N))
		if r := cmp.Diff(b2.Bytes(), b1); r != "" {
			t.Error(r)
		}
	}
}

// A mask on one end only must fail: if either side ignored its FinalMask, one
// of these would connect.
func TestQuicFinalMaskMismatchFails(t *testing.T) {
	for _, tc := range []struct {
		name           string
		server, client string
	}{
		{"server masked, client plain", "mask-password", ""},
		{"server plain, client masked", "", "mask-password"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			port := udp.PickPort()
			listener := listenEcho(t, port, quicStreamSettings(t, tc.server))
			defer listener.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			conn, err := quic.Dial(ctx, net.TCPDestination(net.LocalHostIP, port), quicStreamSettings(t, tc.client))
			if err == nil {
				conn.Close()
				t.Fatal("connected although only one end applies the mask")
			}
		})
	}
}
