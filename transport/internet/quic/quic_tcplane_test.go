package quic_test

import (
	"context"
	"crypto/rand"
	"io"
	"testing"
	"time"

	"github.com/GFW-knocker/Xray-core/common"
	"github.com/GFW-knocker/Xray-core/common/net"
	"github.com/GFW-knocker/Xray-core/common/serial"
	"github.com/GFW-knocker/Xray-core/testing/servers/tcp"
	"github.com/GFW-knocker/Xray-core/transport/internet"
	"github.com/GFW-knocker/Xray-core/transport/internet/finalmask/salamander"
	"github.com/GFW-knocker/Xray-core/transport/internet/finalmask/tcplane"
	"github.com/GFW-knocker/Xray-core/transport/internet/quic"
	"github.com/google/go-cmp/cmp"
)

// tcplaneStreamSettings is what "network": "quictcp" builds: the quic
// transport with a tcplane mask as its last udp mask.
func tcplaneStreamSettings(t *testing.T, salamanderPassword string) *internet.MemoryStreamConfig {
	t.Helper()
	sc := &internet.StreamConfig{
		ProtocolName: "quic",
		TransportSettings: []*internet.TransportConfig{{
			ProtocolName: "quic",
			Settings:     serial.ToTypedMessage(&quic.Config{}),
		}},
	}
	if salamanderPassword != "" {
		sc.Udpmasks = append(sc.Udpmasks, serial.ToTypedMessage(&salamander.Config{Password: salamanderPassword}))
	}
	sc.Udpmasks = append(sc.Udpmasks, serial.ToTypedMessage(&tcplane.Config{
		PacketsMin: 4, PacketsMax: 8,
		LifeMin: 500, LifeMax: 800,
		BytesMin: 24576, BytesMax: 32768,
		Lanes: 4, MaxRate: 0,
		Grace: 1000, Idle: 20000, MaxLife: 60000,
		DownLife: 3000, Flush: 10,
	}))
	mss, err := internet.ToMemoryStreamConfig(sc)
	common.Must(err)
	return mss
}

func testQuicOverLanes(t *testing.T, salamanderPassword string) {
	port := tcp.PickPort()
	listener := listenEcho(t, port, tcplaneStreamSettings(t, salamanderPassword))
	defer listener.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := quic.Dial(ctx, net.TCPDestination(net.LocalHostIP, port), tcplaneStreamSettings(t, salamanderPassword))
	common.Must(err)
	defer conn.Close()

	// 1 MB both ways over lanes of 4-8 packets: hundreds of lanes, and the
	// stream must still arrive whole and in order.
	const N = 1 << 20
	want := make([]byte, N)
	common.Must2(rand.Read(want))
	go func() {
		for off := 0; off < N; off += 16384 {
			if _, err := conn.Write(want[off : off+16384]); err != nil {
				return
			}
		}
	}()
	got := make([]byte, N)
	conn.SetReadDeadline(time.Now().Add(20 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if r := cmp.Diff(got, want); r != "" {
		t.Fatal("echo differs")
	}
}

func TestQuicOverTCPLanes(t *testing.T) {
	testQuicOverLanes(t, "")
}

// salamander stacks on top of tcplane: it rewrites each datagram, tcplane
// carries the result.
func TestQuicOverTCPLanesWithSalamander(t *testing.T) {
	testQuicOverLanes(t, "mask-password")
}
