package masque

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/GFW-knocker/Xray-core/transport/internet"
)

// Each congestion setting masque accepts must leave a tunnel that carries
// packets. "force-brutal" without a brutalUp used to hand Brutal a rate of 0:
// its pacer allows a 10-packet burst, then divides by the rate and panics,
// taking the process down. So the test sends well past that burst.
func TestDialH3CongestionSettingsCarryDatagrams(t *testing.T) {
	for _, params := range []*internet.QuicParams{
		{},
		{Congestion: "reno"},
		{Congestion: "bbr"},
		{Congestion: "force-brutal", BrutalUp: 10 << 20},
		{Congestion: "force-brutal"}, // no brutalUp
	} {
		name := params.Congestion
		if name == "" {
			name = "default"
		}
		if params.Congestion == "force-brutal" && params.BrutalUp == 0 {
			name += "-without-rate"
		}
		t.Run(name, func(t *testing.T) {
			edge := startFakeEdge(t, DefaultConnectProtocol)
			handler := handlerFor(t, edge)
			handler.streamSettings = &internet.MemoryStreamConfig{QuicParams: params}

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			tunnel, err := handler.dialH3(ctx)
			if err != nil {
				t.Fatalf("dialH3: %v", err)
			}
			defer tunnel.Close()

			// 64 datagrams of ~1000 bytes, far past the pacer's 10-packet burst;
			// the edge echoes them, so the client sends ACKs on top.
			packet := make([]byte, 1000)
			copy(packet, ipv4Packet(42))
			const sent = 64
			for i := 0; i < sent; i++ {
				if err := tunnel.request.SendDatagram(appendH3Datagram(nil, packet)); err != nil {
					t.Fatalf("SendDatagram %d: %v", i, err)
				}
			}
			received, cancelReceive := context.WithTimeout(ctx, 5*time.Second)
			defer cancelReceive()
			echoed := 0
			for echoed < sent {
				payload, err := tunnel.request.ReceiveDatagram(received)
				if err != nil {
					break
				}
				if got, ok := stripDatagramContext(payload); ok && string(got) == string(packet) {
					echoed++
				}
			}
			// datagrams are unreliable, but on loopback nearly all come back
			if echoed < sent/2 {
				t.Errorf("%d of %d datagrams came back", echoed, sent)
			}
		})
	}
}

// masque keeps refusing what it cannot honour: plain "brutal" has no rate
// from the edge to adapt to, and an unknown name is a mistake.
func TestDialH3RefusesUnsupportedCongestion(t *testing.T) {
	for _, name := range []string{"brutal", "no-such-algorithm"} {
		t.Run(name, func(t *testing.T) {
			edge := startFakeEdge(t, DefaultConnectProtocol)
			handler := handlerFor(t, edge)
			handler.streamSettings = &internet.MemoryStreamConfig{QuicParams: &internet.QuicParams{Congestion: name}}

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			tunnel, err := handler.dialH3(ctx)
			if err == nil {
				tunnel.Close()
				t.Fatal("dialH3 succeeded")
			}
			if !strings.Contains(err.Error(), "unknown congestion control") {
				t.Errorf("dialH3: %v, want an unknown congestion control error", err)
			}
		})
	}
}
