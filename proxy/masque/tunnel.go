package masque

import (
	"context"
	goerrors "errors"
	"net/netip"
	"sync"
	"time"

	"github.com/GFW-knocker/Xray-core/common/errors"
	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/quicvarint"
)

// addressWait bounds how long a tunnel waits for the edge to hand it an address
// when the configuration did not name one. The edge sends ADDRESS_ASSIGN of its
// own accord once the CONNECT is answered, so this is short.
const addressWait = 10 * time.Second

// tunnel is a running MASQUE session: a netstack for the proxy to dial through,
// a carrier moving that netstack's packets, and the loops joining the two.
type tunnel struct {
	device   *netTun
	tnet     *Net
	carrier  *h3Tunnel
	capsules *capsuleReader
	mtu      int

	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
}

// startTunnel brings a session up far enough to carry traffic.
func (h *Handler) startTunnel(ctx context.Context) (*tunnel, error) {
	carrier, err := h.dialH3(ctx)
	if err != nil {
		return nil, err
	}

	// One reader for the life of the tunnel: it buffers, so reading the address
	// with a second one would swallow whatever it read past the first capsule.
	capsules := newCapsuleReader(carrier.stream)

	addresses := h.addresses
	if len(addresses) == 0 {
		addresses, err = readAssignedAddresses(carrier, capsules)
		if err != nil {
			carrier.Close()
			return nil, err
		}
	}

	device, tnet, _, err := CreateNetTUN(addresses, h.dnsServers, h.mtu, true)
	if err != nil {
		carrier.Close()
		return nil, errors.New("masque: failed to bring up the netstack").Base(err)
	}

	t := &tunnel{
		device:   device,
		tnet:     tnet,
		carrier:  carrier,
		capsules: capsules,
		mtu:      h.mtu,
	}
	t.ctx, t.cancel = context.WithCancel(context.Background())

	go t.uplink()
	go t.downlink()
	go t.control()

	errors.LogInfo(ctx, "masque: tunnel carrying ", addresses, " at mtu ", h.mtu)
	return t, nil
}

// readAssignedAddresses waits for the edge to say what address this tunnel
// holds, for configurations that did not name one.
func readAssignedAddresses(carrier *h3Tunnel, capsules *capsuleReader) ([]netip.Addr, error) {
	// A deadline on the stream is what bounds the wait; the reader blocks in
	// there and a partly read capsule does not matter, since a failure here
	// tears the whole tunnel down.
	carrier.stream.SetReadDeadline(time.Now().Add(addressWait))
	defer carrier.stream.SetReadDeadline(time.Time{})

	for {
		kind, value, err := capsules.next()
		if err != nil {
			return nil, errors.New(
				`masque: the edge assigned no address within `, addressWait,
				` and the configuration named none; set "address" to the one the registration returned`,
			).Base(err)
		}
		if kind != capsuleAddressAssign {
			continue
		}

		assigned, err := parseAddressAssign(value)
		if err != nil {
			return nil, err
		}
		addresses := make([]netip.Addr, 0, len(assigned))
		for _, a := range assigned {
			addresses = append(addresses, a.Prefix.Addr())
		}
		if len(addresses) > 0 {
			return addresses, nil
		}
	}
}

// uplink carries what the netstack wants to send out to the edge.
func (t *tunnel) uplink() {
	defer t.Close()

	packet := make([]byte, t.mtu)
	frame := make([]byte, 0, t.mtu+quicvarint.Len(connectIPContextID))
	for {
		n, err := t.device.ReadPacket(packet)
		if err != nil {
			// The device is closed, which is how this loop is meant to end.
			return
		}

		frame = appendH3Datagram(frame[:0], packet[:n])
		if err := t.carrier.stream.SendDatagram(frame); err != nil {
			var tooLarge *quic.DatagramTooLargeError
			if goerrors.As(err, &tooLarge) {
				// The path got smaller than the interface. Dropping one packet
				// is what any link does here; tearing the tunnel down is not.
				errors.LogDebug(t.ctx, "masque: dropped a ", n, " byte packet, the path takes ", tooLarge.MaxDatagramPayloadSize)
				continue
			}
			errors.LogInfoInner(t.ctx, err, "masque: the tunnel stopped accepting packets")
			return
		}
	}
}

// downlink carries what the edge sends back into the netstack.
func (t *tunnel) downlink() {
	defer t.Close()

	for {
		payload, err := t.carrier.stream.ReceiveDatagram(t.ctx)
		if err != nil {
			errors.LogInfoInner(t.ctx, err, "masque: the tunnel stopped delivering packets")
			return
		}

		packet, ok := stripDatagramContext(payload)
		if !ok {
			// Something that is not an IP packet in the tunnel's own context.
			continue
		}
		if err := t.device.WritePacket(packet); err != nil {
			errors.LogDebugInner(t.ctx, err, "masque: the netstack refused a packet")
		}
	}
}

// control reads the capsule stream, which carries everything that is not a
// packet: the address the edge assigns, the routes it advertises, and on a
// carrier without datagrams, the packets too.
func (t *tunnel) control() {
	defer t.Close()

	for {
		kind, value, err := t.capsules.next()
		if err != nil {
			errors.LogInfoInner(t.ctx, err, "masque: the capsule stream ended")
			return
		}

		switch kind {
		case capsuleAddressAssign:
			assigned, err := parseAddressAssign(value)
			if err != nil {
				errors.LogInfoInner(t.ctx, err, "masque: a bad ADDRESS_ASSIGN")
				continue
			}
			// The netstack already holds an address by now, so this only ever
			// confirms it. A change would need the interface rebuilt.
			for _, a := range assigned {
				errors.LogInfo(t.ctx, "masque: the edge assigns ", a.Prefix)
			}

		case capsuleRouteAdvertisement:
			routes, err := parseRouteAdvertisement(value)
			if err != nil {
				errors.LogInfoInner(t.ctx, err, "masque: a bad ROUTE_ADVERTISEMENT")
				continue
			}
			errors.LogDebug(t.ctx, "masque: the edge advertises ", len(routes), " routes")

		case capsuleDatagram:
			// The HTTP/2 carrier has nowhere else to put packets, and an edge
			// may fall back to this on HTTP/3 as well.
			if packet, ok := stripDatagramContext(value); ok {
				if err := t.device.WritePacket(packet); err != nil {
					errors.LogDebugInner(t.ctx, err, "masque: the netstack refused a packet")
				}
			}

		default:
			// RFC 9297: a capsule of an unknown type is skipped.
			errors.LogDebug(t.ctx, "masque: ignoring capsule type ", uint64(kind))
		}
	}
}

// Close tears the session down. Every loop calls it on the way out, so whichever
// end fails first takes the rest with it.
func (t *tunnel) Close() error {
	t.closeOnce.Do(func() {
		t.cancel()
		t.device.Close()
		t.carrier.Close()
	})
	return nil
}
