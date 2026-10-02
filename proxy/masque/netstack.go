/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

// This file is a copy of proxy/wireguard/netstack.go, trimmed for MASQUE.
//
// It is duplicated rather than shared so that proxy/wireguard stays identical to
// upstream and keeps merging cleanly. Everything from `type Net` down is
// byte-identical to the WireGuard copy, so when upstream changes that file a
// plain diff of the two shows what needs carrying over.
//
// What differs above that line:
//   - Nothing depends on wireguard-go. The device does not implement tun.Device,
//     so Name, File, Events, BatchSize and the tun.Event channel are gone.
//   - Read and Write, which had wireguard-go's vectorised shape, are ReadPacket
//     and WritePacket, carrying one IP packet at a time. That is what a MASQUE
//     QUIC datagram or DATAGRAM capsule holds, and it saves the packet pump
//     unpacking a batch of one on every call.
//   - MTU returns an int; nothing here can fail.
//
// The (Knocker) shutdown-race handling is carried over unchanged.

package masque

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/GFW-knocker/Xray-core/transport/internet"

	"golang.org/x/net/dns/dnsmessage"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

type netTun struct {
	ep             *channel.Endpoint
	stack          *stack.Stack
	notifyHandle   *channel.NotificationHandle
	incomingPacket chan *buffer.View
	mtu            int
	dnsServers     []netip.Addr
	hasV4, hasV6   bool
	// (Knocker) shutdown signalling, to avoid a send/close race on incomingPacket
	closed    chan struct{}
	closeOnce sync.Once
}

func CreateNetTUN(localAddresses, dnsServers []netip.Addr, mtu int, handleLocal bool) (*netTun, *Net, *stack.Stack, error) {
	opts := stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4},
		HandleLocal:        handleLocal,
	}
	dev := &netTun{
		ep:             channel.New(1024, uint32(mtu), ""),
		stack:          stack.New(opts),
		incomingPacket: make(chan *buffer.View),
		dnsServers:     dnsServers,
		mtu:            mtu,
		closed:         make(chan struct{}), // (Knocker)
	}
	sackEnabledOpt := tcpip.TCPSACKEnabled(true) // TCP SACK is disabled by default
	tcpipErr := dev.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &sackEnabledOpt)
	if tcpipErr != nil {
		return nil, nil, nil, fmt.Errorf("could not enable TCP SACK: %v", tcpipErr)
	}
	dev.notifyHandle = dev.ep.AddNotify(dev)
	tcpipErr = dev.stack.CreateNIC(1, dev.ep)
	if tcpipErr != nil {
		return nil, nil, nil, fmt.Errorf("CreateNIC: %v", tcpipErr)
	}
	for _, ip := range localAddresses {
		var protoNumber tcpip.NetworkProtocolNumber
		if ip.Is4() {
			protoNumber = ipv4.ProtocolNumber
		} else if ip.Is6() {
			protoNumber = ipv6.ProtocolNumber
		}
		protoAddr := tcpip.ProtocolAddress{
			Protocol:          protoNumber,
			AddressWithPrefix: tcpip.AddrFromSlice(ip.AsSlice()).WithPrefix(),
		}
		tcpipErr := dev.stack.AddProtocolAddress(1, protoAddr, stack.AddressProperties{})
		if tcpipErr != nil {
			return nil, nil, nil, fmt.Errorf("AddProtocolAddress(%v): %v", ip, tcpipErr)
		}
		if ip.Is4() {
			dev.hasV4 = true
		} else if ip.Is6() {
			dev.hasV6 = true
		}
	}
	if dev.hasV4 {
		dev.stack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1})
	}
	if dev.hasV6 {
		dev.stack.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: 1})
	}

	tnet := &Net{
		DialContextTCPAddrPort: dev.DialContextTCPAddrPort,
		DialUDPAddrPort:        dev.DialUDPAddrPort,
		dnsServers:             dev.dnsServers,
		hasV4:                  dev.hasV4,
		hasV6:                  dev.hasV6,
	}

	return dev, tnet, dev.stack, nil
}

// ReadPacket blocks until the stack has an IP packet to send, copies it into p
// and returns its length. This is the tunnel's uplink: what comes out here is
// what the MASQUE side puts on the wire. It returns os.ErrClosed once the
// device is closed.
func (tun *netTun) ReadPacket(p []byte) (int, error) {
	var view *buffer.View
	select {
	case view = <-tun.incomingPacket:
	case <-tun.closed:
		return 0, os.ErrClosed
	}

	n, err := view.Read(p)
	view.Release()
	return n, err
}

// WritePacket hands one IP packet from the tunnel to the stack. This is the
// downlink: what the MASQUE side reads off the wire goes in here.
func (tun *netTun) WritePacket(p []byte) error {
	if len(p) == 0 {
		return nil
	}

	pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(p)})
	switch p[0] >> 4 {
	case 4:
		tun.ep.InjectInbound(header.IPv4ProtocolNumber, pkb)
	case 6:
		tun.ep.InjectInbound(header.IPv6ProtocolNumber, pkb)
	default:
		return syscall.EAFNOSUPPORT
	}
	return nil
}

func (tun *netTun) WriteNotify() {
	// (Knocker) bail out if the device is already shutting down
	select {
	case <-tun.closed:
		return
	default:
	}

	pkt := tun.ep.Read()
	if pkt == nil {
		return
	}

	view := pkt.ToView()
	pkt.DecRef()

	// (Knocker) never block on a channel Close() may be closing
	select {
	case tun.incomingPacket <- view:
	case <-tun.closed:
		view.Release() // avoid memory leak
	}
}

func (tun *netTun) Close() error {
	// (Knocker) closeOnce guards against a second Close() panicking on an
	// already-closed channel; closing tun.closed first unblocks WriteNotify.
	tun.closeOnce.Do(func() {
		close(tun.closed)

		tun.stack.RemoveNIC(1)
		tun.stack.Close()
		tun.ep.RemoveNotify(tun.notifyHandle)
		tun.ep.Close()

		// incomingPacket is not closed: WriteNotify may be mid-send on it and
		// would panic; ReadPacket returns on tun.closed instead.
	})
	return nil
}

func (tun *netTun) MTU() int {
	return tun.mtu
}

// setAddresses makes the device hold the addresses the edge says it will route
// for, in place of whatever it was holding for those families.
//
// The edge is the authority: it routes for the address it assigned, so a device
// holding anything else sends from a source the far side will not answer. Only
// families the edge actually named are touched, so an assignment carrying one
// IPv4 address leaves an IPv6 address alone rather than tearing it out.
//
// It reports whether anything actually changed, so a mere confirmation of what
// was already configured stays quiet.
func (tun *netTun) setAddresses(prefixes []netip.Prefix) (bool, error) {
	if len(prefixes) == 0 {
		return false, nil
	}

	info, ok := tun.stack.NICInfo()[1]
	if !ok {
		return false, fmt.Errorf("the device has no NIC to address")
	}

	wanted := make(map[tcpip.Address]int, len(prefixes))
	families := make(map[tcpip.NetworkProtocolNumber]struct{}, 2)
	for _, prefix := range prefixes {
		wanted[tcpip.AddrFromSlice(prefix.Addr().AsSlice())] = prefix.Bits()
		families[protocolNumberFor(prefix.Addr())] = struct{}{}
	}

	changed := false
	held := make(map[tcpip.Address]struct{}, len(info.ProtocolAddresses))
	for _, existing := range info.ProtocolAddresses {
		if _, touching := families[existing.Protocol]; !touching {
			continue
		}
		address := existing.AddressWithPrefix.Address
		if bits, keep := wanted[address]; keep && bits == existing.AddressWithPrefix.PrefixLen {
			held[address] = struct{}{}
			continue
		}
		if err := tun.stack.RemoveAddress(1, address); err != nil {
			return changed, fmt.Errorf("RemoveAddress(%v): %v", address, err)
		}
		changed = true
	}

	for _, prefix := range prefixes {
		address := tcpip.AddrFromSlice(prefix.Addr().AsSlice())
		if _, already := held[address]; already {
			continue
		}
		protoAddr := tcpip.ProtocolAddress{
			Protocol: protocolNumberFor(prefix.Addr()),
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   address,
				PrefixLen: prefix.Bits(),
			},
		}
		if err := tun.stack.AddProtocolAddress(1, protoAddr, stack.AddressProperties{}); err != nil {
			return changed, fmt.Errorf("AddProtocolAddress(%v): %v", prefix, err)
		}
		changed = true

		// A family the device did not have before needs its default route too.
		if prefix.Addr().Is4() && !tun.hasV4 {
			tun.stack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1})
			tun.hasV4 = true
		}
		if prefix.Addr().Is6() && !tun.hasV6 {
			tun.stack.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: 1})
			tun.hasV6 = true
		}
	}
	return changed, nil
}

func protocolNumberFor(addr netip.Addr) tcpip.NetworkProtocolNumber {
	if addr.Is4() {
		return ipv4.ProtocolNumber
	}
	return ipv6.ProtocolNumber
}

func (tun *netTun) DialContextTCPAddrPort(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	fa, pn := convertToFullAddr(addr)
	return gonet.DialContextTCP(ctx, tun.stack, fa, pn)
}

func (tun *netTun) DialUDPAddrPort(laddr, raddr netip.AddrPort) (net.Conn, error) {
	var pn tcpip.NetworkProtocolNumber = ipv6.ProtocolNumber
	if raddr.IsValid() || raddr.Port() > 0 {
		_, pn = convertToFullAddr(raddr)
	}
	conn, err := gonet.DialUDP(tun.stack, nil, nil, pn)
	if err != nil {
		return nil, err
	}
	return &internet.PacketConnWrapper{
		PacketConn: conn,
		Dest:       net.UDPAddrFromAddrPort(raddr),
	}, nil
}

type Net struct {
	DialContextTCPAddrPort func(ctx context.Context, addr netip.AddrPort) (net.Conn, error)
	DialUDPAddrPort        func(laddr, raddr netip.AddrPort) (net.Conn, error)
	dnsServers             []netip.Addr
	hasV4, hasV6           bool
}

func convertToFullAddr(endpoint netip.AddrPort) (tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
	var protoNumber tcpip.NetworkProtocolNumber
	if endpoint.Addr().Is4() {
		protoNumber = ipv4.ProtocolNumber
	} else {
		protoNumber = ipv6.ProtocolNumber
	}
	return tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(endpoint.Addr().AsSlice()),
		Port: endpoint.Port(),
	}, protoNumber
}

var (
	errNoSuchHost                   = errors.New("no such host")
	errLameReferral                 = errors.New("lame referral")
	errCannotUnmarshalDNSMessage    = errors.New("cannot unmarshal DNS message")
	errCannotMarshalDNSMessage      = errors.New("cannot marshal DNS message")
	errServerMisbehaving            = errors.New("server misbehaving")
	errInvalidDNSResponse           = errors.New("invalid DNS response")
	errNoAnswerFromDNSServer        = errors.New("no answer from DNS server")
	errServerTemporarilyMisbehaving = errors.New("server misbehaving")
	errCanceled                     = errors.New("operation was canceled")
	errTimeout                      = errors.New("i/o timeout")
)

func (net *Net) LookupHost(host string) (addrs []net.IP, ttl uint32, err error) {
	return net.LookupContextHost(context.Background(), host)
}

func isDomainName(s string) bool {
	l := len(s)
	if l == 0 || l > 254 || l == 254 && s[l-1] != '.' {
		return false
	}
	last := byte('.')
	nonNumeric := false
	partlen := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		default:
			return false
		case 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || c == '_':
			nonNumeric = true
			partlen++
		case '0' <= c && c <= '9':
			partlen++
		case c == '-':
			if last == '.' {
				return false
			}
			partlen++
			nonNumeric = true
		case c == '.':
			if last == '.' || last == '-' {
				return false
			}
			if partlen > 63 || partlen == 0 {
				return false
			}
			partlen = 0
		}
		last = c
	}
	if last == '-' || partlen > 63 {
		return false
	}
	return nonNumeric
}

func randU16() uint16 {
	var b [2]byte
	_, err := rand.Read(b[:])
	if err != nil {
		panic(err)
	}
	return binary.LittleEndian.Uint16(b[:])
}

func newRequest(q dnsmessage.Question) (id uint16, udpReq, tcpReq []byte, err error) {
	id = randU16()
	b := dnsmessage.NewBuilder(make([]byte, 2, 514), dnsmessage.Header{ID: id, RecursionDesired: true})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return 0, nil, nil, err
	}
	if err := b.Question(q); err != nil {
		return 0, nil, nil, err
	}
	tcpReq, err = b.Finish()
	udpReq = tcpReq[2:]
	l := len(tcpReq) - 2
	tcpReq[0] = byte(l >> 8)
	tcpReq[1] = byte(l)
	return id, udpReq, tcpReq, err
}

func equalASCIIName(x, y dnsmessage.Name) bool {
	if x.Length != y.Length {
		return false
	}
	for i := 0; i < int(x.Length); i++ {
		a := x.Data[i]
		b := y.Data[i]
		if 'A' <= a && a <= 'Z' {
			a += 0x20
		}
		if 'A' <= b && b <= 'Z' {
			b += 0x20
		}
		if a != b {
			return false
		}
	}
	return true
}

func checkResponse(reqID uint16, reqQues dnsmessage.Question, respHdr dnsmessage.Header, respQues dnsmessage.Question) bool {
	if !respHdr.Response {
		return false
	}
	if reqID != respHdr.ID {
		return false
	}
	if reqQues.Type != respQues.Type || reqQues.Class != respQues.Class || !equalASCIIName(reqQues.Name, respQues.Name) {
		return false
	}
	return true
}

func dnsPacketRoundTrip(c net.Conn, id uint16, query dnsmessage.Question, b []byte) (dnsmessage.Parser, dnsmessage.Header, error) {
	if _, err := c.Write(b); err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, err
	}
	b = make([]byte, 512)
	for {
		n, err := c.Read(b)
		if err != nil {
			return dnsmessage.Parser{}, dnsmessage.Header{}, err
		}
		var p dnsmessage.Parser
		h, err := p.Start(b[:n])
		if err != nil {
			continue
		}
		q, err := p.Question()
		if err != nil || !checkResponse(id, query, h, q) {
			continue
		}
		return p, h, nil
	}
}

func dnsStreamRoundTrip(c net.Conn, id uint16, query dnsmessage.Question, b []byte) (dnsmessage.Parser, dnsmessage.Header, error) {
	if _, err := c.Write(b); err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, err
	}
	b = make([]byte, 1280)
	if _, err := io.ReadFull(c, b[:2]); err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, err
	}
	l := int(b[0])<<8 | int(b[1])
	if l > len(b) {
		b = make([]byte, l)
	}
	n, err := io.ReadFull(c, b[:l])
	if err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, err
	}
	var p dnsmessage.Parser
	h, err := p.Start(b[:n])
	if err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, errCannotUnmarshalDNSMessage
	}
	q, err := p.Question()
	if err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, errCannotUnmarshalDNSMessage
	}
	if !checkResponse(id, query, h, q) {
		return dnsmessage.Parser{}, dnsmessage.Header{}, errInvalidDNSResponse
	}
	return p, h, nil
}

func (tnet *Net) exchange(ctx context.Context, server netip.Addr, q dnsmessage.Question, timeout time.Duration) (dnsmessage.Parser, dnsmessage.Header, error) {
	q.Class = dnsmessage.ClassINET
	id, udpReq, tcpReq, err := newRequest(q)
	if err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, errCannotMarshalDNSMessage
	}

	for _, useUDP := range []bool{true, false} {
		ctx, cancel := context.WithDeadline(ctx, time.Now().Add(timeout))
		defer cancel()

		var c net.Conn
		var err error
		if useUDP {
			c, err = tnet.DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(server, 53))
		} else {
			c, err = tnet.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(server, 53))
		}

		if err != nil {
			return dnsmessage.Parser{}, dnsmessage.Header{}, err
		}
		if d, ok := ctx.Deadline(); ok && !d.IsZero() {
			err := c.SetDeadline(d)
			if err != nil {
				return dnsmessage.Parser{}, dnsmessage.Header{}, err
			}
		}
		var p dnsmessage.Parser
		var h dnsmessage.Header
		if useUDP {
			p, h, err = dnsPacketRoundTrip(c, id, q, udpReq)
		} else {
			p, h, err = dnsStreamRoundTrip(c, id, q, tcpReq)
		}
		c.Close()
		if err != nil {
			if err == context.Canceled {
				err = errCanceled
			} else if err == context.DeadlineExceeded {
				err = errTimeout
			}
			return dnsmessage.Parser{}, dnsmessage.Header{}, err
		}
		if err := p.SkipQuestion(); err != dnsmessage.ErrSectionDone {
			return dnsmessage.Parser{}, dnsmessage.Header{}, errInvalidDNSResponse
		}
		if h.Truncated {
			continue
		}
		return p, h, nil
	}
	return dnsmessage.Parser{}, dnsmessage.Header{}, errNoAnswerFromDNSServer
}

func checkHeader(p *dnsmessage.Parser, h dnsmessage.Header) error {
	if h.RCode == dnsmessage.RCodeNameError {
		return errNoSuchHost
	}
	_, err := p.AnswerHeader()
	if err != nil && err != dnsmessage.ErrSectionDone {
		return errCannotUnmarshalDNSMessage
	}
	if h.RCode == dnsmessage.RCodeSuccess && !h.Authoritative && !h.RecursionAvailable && err == dnsmessage.ErrSectionDone {
		return errLameReferral
	}
	if h.RCode != dnsmessage.RCodeSuccess && h.RCode != dnsmessage.RCodeNameError {
		if h.RCode == dnsmessage.RCodeServerFailure {
			return errServerTemporarilyMisbehaving
		}
		return errServerMisbehaving
	}
	return nil
}

func skipToAnswer(p *dnsmessage.Parser, qtype dnsmessage.Type) error {
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			return errNoSuchHost
		}
		if err != nil {
			return errCannotUnmarshalDNSMessage
		}
		if h.Type == qtype {
			return nil
		}
		if err := p.SkipAnswer(); err != nil {
			return errCannotUnmarshalDNSMessage
		}
	}
}

func (tnet *Net) tryOneName(ctx context.Context, name string, qtype dnsmessage.Type) (dnsmessage.Parser, string, error) {
	var lastErr error

	n, err := dnsmessage.NewName(name)
	if err != nil {
		return dnsmessage.Parser{}, "", errCannotMarshalDNSMessage
	}
	q := dnsmessage.Question{
		Name:  n,
		Type:  qtype,
		Class: dnsmessage.ClassINET,
	}

	for i := 0; i < 2; i++ {
		for _, server := range tnet.dnsServers {
			p, h, err := tnet.exchange(ctx, server, q, time.Second*5)
			if err != nil {
				dnsErr := &net.DNSError{
					Err:    err.Error(),
					Name:   name,
					Server: server.String(),
				}
				if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
					dnsErr.IsTimeout = true
				}
				if _, ok := err.(*net.OpError); ok {
					dnsErr.IsTemporary = true
				}
				lastErr = dnsErr
				continue
			}

			if err := checkHeader(&p, h); err != nil {
				dnsErr := &net.DNSError{
					Err:    err.Error(),
					Name:   name,
					Server: server.String(),
				}
				if err == errServerTemporarilyMisbehaving {
					dnsErr.IsTemporary = true
				}
				if err == errNoSuchHost {
					dnsErr.IsNotFound = true
					return p, server.String(), dnsErr
				}
				lastErr = dnsErr
				continue
			}

			err = skipToAnswer(&p, qtype)
			if err == nil {
				return p, server.String(), nil
			}
			lastErr = &net.DNSError{
				Err:    err.Error(),
				Name:   name,
				Server: server.String(),
			}
			if err == errNoSuchHost {
				lastErr.(*net.DNSError).IsNotFound = true
				return p, server.String(), lastErr
			}
		}
	}
	return dnsmessage.Parser{}, "", lastErr
}

func (tnet *Net) LookupContextHost(ctx context.Context, host string) ([]net.IP, uint32, error) {
	if host == "" || (!tnet.hasV6 && !tnet.hasV4) {
		return nil, 0, &net.DNSError{Err: errNoSuchHost.Error(), Name: host, IsNotFound: true}
	}
	zlen := len(host)
	if strings.IndexByte(host, ':') != -1 {
		if zidx := strings.LastIndexByte(host, '%'); zidx != -1 {
			zlen = zidx
		}
	}
	if ip, err := netip.ParseAddr(host[:zlen]); err == nil {
		return []net.IP{ip.AsSlice()}, 0, nil
	}

	if !isDomainName(host) {
		return nil, 0, &net.DNSError{Err: errNoSuchHost.Error(), Name: host, IsNotFound: true}
	}
	type result struct {
		p      dnsmessage.Parser
		server string
		error
	}
	var addrsV4, addrsV6 []netip.Addr
	lanes := 0
	if tnet.hasV4 {
		lanes++
	}
	if tnet.hasV6 {
		lanes++
	}
	lane := make(chan result, lanes)
	var lastErr error
	if tnet.hasV4 {
		go func() {
			p, server, err := tnet.tryOneName(ctx, host+".", dnsmessage.TypeA)
			lane <- result{p, server, err}
		}()
	}
	if tnet.hasV6 {
		go func() {
			p, server, err := tnet.tryOneName(ctx, host+".", dnsmessage.TypeAAAA)
			lane <- result{p, server, err}
		}()
	}
	ttl := uint32(300)
	for l := 0; l < lanes; l++ {
		result := <-lane
		if result.error != nil {
			if lastErr == nil {
				lastErr = result.error
			}
			continue
		}

	loop:
		for {
			h, err := result.p.AnswerHeader()
			if err != nil && err != dnsmessage.ErrSectionDone {
				lastErr = &net.DNSError{
					Err:    errCannotMarshalDNSMessage.Error(),
					Name:   host,
					Server: result.server,
				}
			}
			if err != nil {
				break
			}
			switch h.Type {
			case dnsmessage.TypeA:
				a, err := result.p.AResource()
				if err != nil {
					lastErr = &net.DNSError{
						Err:    errCannotMarshalDNSMessage.Error(),
						Name:   host,
						Server: result.server,
					}
					break loop
				}
				ttl = min(ttl, h.TTL)
				addrsV4 = append(addrsV4, netip.AddrFrom4(a.A))

			case dnsmessage.TypeAAAA:
				aaaa, err := result.p.AAAAResource()
				if err != nil {
					lastErr = &net.DNSError{
						Err:    errCannotMarshalDNSMessage.Error(),
						Name:   host,
						Server: result.server,
					}
					break loop
				}
				ttl = min(ttl, h.TTL)
				addrsV6 = append(addrsV6, netip.AddrFrom16(aaaa.AAAA))

			default:
				if err := result.p.SkipAnswer(); err != nil {
					lastErr = &net.DNSError{
						Err:    errCannotMarshalDNSMessage.Error(),
						Name:   host,
						Server: result.server,
					}
					break loop
				}
				continue
			}
		}
	}
	// We don't do RFC6724. Instead just put V6 addresses first if an IPv6 address is enabled
	var addrs []netip.Addr
	if tnet.hasV6 {
		addrs = append(addrsV6, addrsV4...)
	} else {
		addrs = append(addrsV4, addrsV6...)
	}

	if len(addrs) == 0 && lastErr != nil {
		return nil, 0, lastErr
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, ip := range addrs {
		ips = append(ips, ip.AsSlice())
	}
	return ips, ttl, nil
}
