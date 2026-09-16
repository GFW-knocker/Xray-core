package masque

import (
	"context"
	"io"
	"net/netip"
	"sort"
	"strings"
	"testing"
	"time"
)

func heldAddresses(t *testing.T, device *netTun) []string {
	t.Helper()
	info, ok := device.stack.NICInfo()[1]
	if !ok {
		t.Fatal("the device has no NIC")
	}
	var held []string
	for _, a := range info.ProtocolAddresses {
		held = append(held, a.AddressWithPrefix.String())
	}
	sort.Strings(held)
	return held
}

func prefixes(t *testing.T, list ...string) []netip.Prefix {
	t.Helper()
	parsed := make([]netip.Prefix, 0, len(list))
	for _, p := range list {
		parsed = append(parsed, netip.MustParsePrefix(p))
	}
	return parsed
}

func TestSetAddresses(t *testing.T) {
	t.Run("replaces an address of the same family", func(t *testing.T) {
		device, _, _, err := CreateNetTUN(prefixAddrs(t, "10.0.0.2/32"), nil, DefaultMTU, true)
		if err != nil {
			t.Fatalf("CreateNetTUN: %v", err)
		}
		defer device.Close()

		changed, err := device.setAddresses(prefixes(t, "10.0.0.7/32"))
		if err != nil {
			t.Fatalf("setAddresses: %v", err)
		}
		if !changed {
			t.Error("setAddresses reported no change while replacing the address")
		}
		if got := heldAddresses(t, device); len(got) != 1 || got[0] != "10.0.0.7/32" {
			t.Errorf("device holds %v, want only 10.0.0.7/32", got)
		}
	})

	t.Run("confirming what is already held changes nothing", func(t *testing.T) {
		device, _, _, err := CreateNetTUN(prefixAddrs(t, "10.0.0.2/32"), nil, DefaultMTU, true)
		if err != nil {
			t.Fatalf("CreateNetTUN: %v", err)
		}
		defer device.Close()

		changed, err := device.setAddresses(prefixes(t, "10.0.0.2/32"))
		if err != nil {
			t.Fatalf("setAddresses: %v", err)
		}
		if changed {
			t.Error("setAddresses reported a change for the address already held")
		}
		if got := heldAddresses(t, device); len(got) != 1 || got[0] != "10.0.0.2/32" {
			t.Errorf("device holds %v, want 10.0.0.2/32 untouched", got)
		}
	})

	// An assignment naming only IPv4 must not take an IPv6 address away, which
	// is how aether treats it too.
	t.Run("a family the edge did not name is left alone", func(t *testing.T) {
		device, _, _, err := CreateNetTUN(prefixAddrs(t, "10.0.0.2/32", "fd00::2/128"), nil, DefaultMTU, true)
		if err != nil {
			t.Fatalf("CreateNetTUN: %v", err)
		}
		defer device.Close()

		if _, err := device.setAddresses(prefixes(t, "10.0.0.7/32")); err != nil {
			t.Fatalf("setAddresses: %v", err)
		}
		got := heldAddresses(t, device)
		if len(got) != 2 {
			t.Fatalf("device holds %v, want the new IPv4 and the untouched IPv6", got)
		}
		if strings.Join(got, " ") != "10.0.0.7/32 fd00::2/128" {
			t.Errorf("device holds %v, want [10.0.0.7/32 fd00::2/128]", got)
		}
	})

	t.Run("a family that was not there is added", func(t *testing.T) {
		device, _, _, err := CreateNetTUN(prefixAddrs(t, "10.0.0.2/32"), nil, DefaultMTU, true)
		if err != nil {
			t.Fatalf("CreateNetTUN: %v", err)
		}
		defer device.Close()

		if device.hasV6 {
			t.Fatal("the device claims IPv6 before any was assigned")
		}
		if _, err := device.setAddresses(prefixes(t, "fd00::7/128")); err != nil {
			t.Fatalf("setAddresses: %v", err)
		}
		if !device.hasV6 {
			t.Error("the device did not record that it now has IPv6, so no route was added")
		}
		if got := heldAddresses(t, device); strings.Join(got, " ") != "10.0.0.2/32 fd00::7/128" {
			t.Errorf("device holds %v, want both families", got)
		}
	})

	t.Run("an empty assignment is a no-op", func(t *testing.T) {
		device, _, _, err := CreateNetTUN(prefixAddrs(t, "10.0.0.2/32"), nil, DefaultMTU, true)
		if err != nil {
			t.Fatalf("CreateNetTUN: %v", err)
		}
		defer device.Close()

		changed, err := device.setAddresses(nil)
		if err != nil || changed {
			t.Errorf("setAddresses(nil) = %v, %v; want false, nil", changed, err)
		}
	})
}

func prefixAddrs(t *testing.T, list ...string) []netip.Addr {
	t.Helper()
	addrs := make([]netip.Addr, 0, len(list))
	for _, p := range list {
		addrs = append(addrs, netip.MustParsePrefix(p).Addr())
	}
	return addrs
}

// The point of the whole fix: when the edge assigns an address that is not the
// one configured, the tunnel has to start using the assigned one, because that
// is the only address the edge routes for. Traffic proves it, not a log line.
func TestTunnelTakesOverAnAddressThatDisagreesWithTheConfiguration(t *testing.T) {
	edge := startRoutingEdge(t)
	// The edge hands out 10.0.0.7, not the 10.0.0.2 the configuration names.
	edge.assign = []byte{0x01, 4, 10, 0, 0, 7, 32}

	handler := handlerForRoutingEdge(t, edge, []string{clientAddress + "/32"})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tunnel, err := handler.startTunnel(ctx)
	if err != nil {
		t.Fatalf("startTunnel: %v", err)
	}
	defer tunnel.Close()

	// The capsule is handled by the control loop, so wait for it to land.
	deadline := time.Now().Add(10 * time.Second)
	for {
		held := heldAddresses(t, tunnel.device)
		if len(held) == 1 && held[0] == "10.0.0.7/32" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the device still holds %v, want the assigned 10.0.0.7/32", held)
		}
		time.Sleep(10 * time.Millisecond)
	}

	netStack := <-edge.stacks
	echoOnEdge(t, netStack, 84)

	from := make(chan string, 1)
	go func() {
		listener := listenOnEdge(t, netStack, 85)
		conn, err := listener.Accept()
		if err != nil {
			from <- ""
			return
		}
		defer conn.Close()
		from <- conn.RemoteAddr().String()
	}()

	conn, err := tunnel.tnet.DialContextTCPAddrPort(ctx, netip.MustParseAddrPort(edgeAddress+":85"))
	if err != nil {
		t.Fatalf("dialling after the address changed: %v", err)
	}
	defer conn.Close()

	select {
	case remote := <-from:
		if !strings.HasPrefix(remote, "10.0.0.7:") {
			t.Errorf("the far side saw the connection from %q, want it from the assigned 10.0.0.7", remote)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the far side never saw the connection")
	}

	// And it still carries data, so the takeover did not leave a half-built
	// interface behind.
	echo, err := tunnel.tnet.DialContextTCPAddrPort(ctx, netip.MustParseAddrPort(edgeAddress+":84"))
	if err != nil {
		t.Fatalf("dialling the echo port: %v", err)
	}
	defer echo.Close()
	echo.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := echo.Write([]byte("hello")); err != nil {
		t.Fatalf("writing after the address changed: %v", err)
	}
	reply := make([]byte, 5)
	if _, err := io.ReadFull(echo, reply); err != nil {
		t.Fatalf("reading after the address changed: %v", err)
	}
	if string(reply) != "HELLO" {
		t.Errorf("got %q, want HELLO", reply)
	}
}
