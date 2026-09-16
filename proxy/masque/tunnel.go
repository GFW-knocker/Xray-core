package masque

import (
	"context"
	goerrors "errors"
	"io"
	"net/netip"
	"sync"
	"time"

	"github.com/GFW-knocker/Xray-core/common/errors"
	"github.com/apernet/quic-go"
)

// addressWait bounds how long a tunnel waits for the edge to hand it an address
// when the configuration did not name one. The edge sends ADDRESS_ASSIGN of its
// own accord once the CONNECT is answered, so this is short.
const addressWait = 10 * time.Second

// carrier is what a tunnel moves its packets over. HTTP/3 has datagrams and
// keeps the stream for control capsules; HTTP/2 has no datagrams, so packets
// travel as DATAGRAM capsules on the stream with everything else.
type carrier interface {
	// sendPacket puts one IP packet on the wire, framed however this carrier
	// frames packets.
	sendPacket(packet []byte) error
	// receivePacket returns the next packet. Only meaningful when hasDatagrams
	// reports true.
	receivePacket(ctx context.Context) ([]byte, error)
	// hasDatagrams reports whether packets arrive outside the capsule stream.
	hasDatagrams() bool
	// stream is where capsules arrive.
	stream() io.Reader
	Close() error
}

// tunnel is a running MASQUE session: a netstack for the proxy to dial through,
// a carrier moving that netstack's packets, and the loops joining the two.
type tunnel struct {
	device   *netTun
	tnet     *Net
	carrier  carrier
	capsules *capsuleReader
	mtu      int

	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
}

// startTunnel brings a session up far enough to carry traffic.
func (h *Handler) startTunnel(ctx context.Context) (*tunnel, error) {
	carrier, err := h.dialCarrier(ctx)
	if err != nil {
		return nil, err
	}

	// One reader for the life of the tunnel: it buffers, so reading the address
	// with a second one would swallow whatever it read past the first capsule.
	capsules := newCapsuleReader(carrier.stream())

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
	if carrier.hasDatagrams() {
		go t.downlink()
	}
	go t.control()

	errors.LogInfo(ctx, "masque: tunnel carrying ", addresses, " at mtu ", h.mtu)
	return t, nil
}

// readAssignedAddresses waits for the edge to say what address this tunnel
// holds, for configurations that did not name one.
func readAssignedAddresses(carrier carrier, capsules *capsuleReader) ([]netip.Addr, error) {
	// The read is bounded from out here rather than with a deadline on the
	// carrier: HTTP/2 runs its own read loop over the same connection, and a
	// deadline meant for one capsule would take that down with it. On the
	// timeout path the caller closes the carrier, which releases this reader.
	type result struct {
		addresses []netip.Addr
		err       error
	}
	out := make(chan result, 1)
	go func() {
		for {
			kind, value, err := capsules.next()
			if err != nil {
				out <- result{err: err}
				return
			}
			if kind != capsuleAddressAssign {
				continue
			}
			assigned, err := parseAddressAssign(value)
			if err != nil {
				out <- result{err: err}
				return
			}
			addresses := make([]netip.Addr, 0, len(assigned))
			for _, a := range assigned {
				addresses = append(addresses, a.Prefix.Addr())
			}
			if len(addresses) > 0 {
				out <- result{addresses: addresses}
				return
			}
		}
	}()

	select {
	case r := <-out:
		if r.err != nil {
			return nil, errors.New("masque: the edge sent no usable address").Base(r.err)
		}
		return r.addresses, nil
	case <-time.After(addressWait):
		return nil, errors.New(
			`masque: the edge assigned no address within `, addressWait,
			` and the configuration named none; set "address" to the one the registration returned`,
		)
	}
}

// uplink carries what the netstack wants to send out to the edge.
func (t *tunnel) uplink() {
	defer t.Close()

	packet := make([]byte, t.mtu)
	for {
		n, err := t.device.ReadPacket(packet)
		if err != nil {
			// The device is closed, which is how this loop is meant to end.
			return
		}

		if err := t.carrier.sendPacket(packet[:n]); err != nil {
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
		payload, err := t.carrier.receivePacket(t.ctx)
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

// alive reports whether this tunnel is still carrying traffic. Every loop
// closes the tunnel on its way out, so a cancelled context means the session
// is over and a new one is needed.
func (t *tunnel) alive() bool {
	return t.ctx.Err() == nil
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
