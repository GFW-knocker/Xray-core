package scenarios

import (
	"bytes"
	"crypto/rand"
	gonet "net"
	"testing"
	"time"

	"github.com/GFW-knocker/Xray-core/app/proxyman"
	"github.com/GFW-knocker/Xray-core/common"
	"github.com/GFW-knocker/Xray-core/common/buf"
	"github.com/GFW-knocker/Xray-core/common/errors"
	"github.com/GFW-knocker/Xray-core/common/net"
	"github.com/GFW-knocker/Xray-core/common/protocol"
	"github.com/GFW-knocker/Xray-core/common/serial"
	"github.com/GFW-knocker/Xray-core/core"
	"github.com/GFW-knocker/Xray-core/proxy/freedom"
	"github.com/GFW-knocker/Xray-core/proxy/socks"
	"github.com/GFW-knocker/Xray-core/testing/servers/tcp"
	"github.com/GFW-knocker/Xray-core/testing/servers/udp"
)

// MahsaNG: Android's badvpn tun2socks "--enable-udprelay" sends SOCKS5-UDP
// datagrams straight to the SOCKS inbound's own port, without UDP ASSOCIATE.
// Upstream #6149 dropped that port, which silently broke every app's UDP
// (DNS first of all) on Android. These tests fail if a sync drops it again.

// socksUDPViaInboundPort sends one SOCKS5-UDP datagram for dest to the inbound
// port and checks the xor-ed echo comes back with the right header.
func socksUDPViaInboundPort(socksPort net.Port, dest net.Destination, timeout time.Duration) error {
	conn, err := gonet.DialUDP("udp", nil, &gonet.UDPAddr{IP: gonet.IPv4(127, 0, 0, 1), Port: int(socksPort)})
	if err != nil {
		return err
	}
	defer conn.Close()

	payload := make([]byte, 512)
	common.Must2(rand.Read(payload))
	packet, err := socks.EncodeUDPPacket(&protocol.RequestHeader{Address: dest.Address, Port: dest.Port}, payload)
	if err != nil {
		return err
	}
	defer packet.Release()
	if _, err := conn.Write(packet.Bytes()); err != nil {
		return err
	}

	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	response := buf.New()
	defer response.Release()
	if _, err := response.ReadFrom(conn); err != nil {
		return err
	}
	request, err := socks.DecodeUDPPacket(response)
	if err != nil {
		return err
	}
	if request.Port != dest.Port {
		return errors.New("reply from port ", request.Port, ", want ", dest.Port)
	}
	if !bytes.Equal(response.Bytes(), xor(payload)) {
		return errors.New("reply payload mismatch")
	}
	return nil
}

func startSocksUDPServer(t *testing.T, config *socks.ServerConfig) (net.Port, func()) {
	t.Helper()
	for retry := 0; retry < 5; retry++ {
		port := tcp.PickPort()
		server, err := InitializeServerConfig(&core.Config{
			Inbound: []*core.InboundHandlerConfig{
				{
					ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
						PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(port)}},
						Listen:   net.NewIPOrDomain(net.LocalHostIP),
					}),
					ProxySettings: serial.ToTypedMessage(config),
				},
			},
			Outbound: []*core.OutboundHandlerConfig{
				{
					// the echo server is on 127.0.0.1, which freedom's default finalRules block
					ProxySettings: serial.ToTypedMessage(&freedom.Config{FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}}}),
				},
			},
		})
		if err == nil && server != nil {
			return port, func() { CloseServer(server) }
		}
	}
	t.Fatal("All attempts failed to start server")
	return 0, nil
}

func TestSocksUDPOnInboundPort(t *testing.T) {
	udpServer := udp.Server{MsgProcessor: xor}
	dest, err := udpServer.Start()
	common.Must(err)
	defer udpServer.Close()

	port, stop := startSocksUDPServer(t, &socks.ServerConfig{
		AuthType:   socks.AuthType_NO_AUTH,
		UdpEnabled: true,
	})
	defer stop()

	if !WaitConnAvailableWithTest(t, func() error { return socksUDPViaInboundPort(port, dest, time.Second) }) {
		t.Fatal("no reply to a SOCKS5-UDP datagram sent to the inbound port")
	}
}

func TestSocksUDPOnInboundPortNeedsAuth(t *testing.T) {
	udpServer := udp.Server{MsgProcessor: xor}
	dest, err := udpServer.Start()
	common.Must(err)
	defer udpServer.Close()

	port, stop := startSocksUDPServer(t, &socks.ServerConfig{
		AuthType:   socks.AuthType_PASSWORD,
		Accounts:   map[string]string{"Test Account": "Test Password"},
		UdpEnabled: true,
	})
	defer stop()

	// wait for the inbound to come up over TCP, then give UDP a few tries
	WaitConnAvailableWithTest(t, func() error {
		c, err := gonet.DialTimeout("tcp", gonet.JoinHostPort("127.0.0.1", port.String()), time.Second)
		if err == nil {
			c.Close()
		}
		return err
	})
	for i := 0; i < 3; i++ {
		if err := socksUDPViaInboundPort(port, dest, 500*time.Millisecond); err == nil {
			t.Fatal("an unauthenticated SOCKS5-UDP datagram on the inbound port got a reply")
		}
	}
}
