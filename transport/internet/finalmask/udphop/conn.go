package udphop

import (
	"context"
	"crypto/rand"
	goerrors "errors"
	"io"
	mrand "math/rand"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/GFW-knocker/Xray-core/common"
	"github.com/GFW-knocker/Xray-core/common/crypto"
	"github.com/GFW-knocker/Xray-core/common/errors"
	"github.com/GFW-knocker/Xray-core/common/net"
	"github.com/GFW-knocker/Xray-core/transport/internet/finalmask"
)

var pool = sync.Pool{
	New: func() any {
		return make([]byte, finalmask.UDPSize)
	},
}

type packet struct {
	p    []byte
	addr net.Addr
	err  error
}

// packetLocalKeep is how long a port that packet_local stopped sending from
// keeps receiving after its last datagram arrived. Servers differ in where
// they answer a client that moves: a QUIC server keeps sending to the address
// it already uses (often the very first port), WireGuard follows the newest
// one. So a retired port is closed only once it is both retired and idle.
const packetLocalKeep = 10 * time.Second

// sockState is what the receive loop of one socket shares with the hopper.
type sockState struct {
	lastRx  atomic.Int64 // unix nanos of the last datagram received
	closing atomic.Bool  // closed on purpose, so its read error is not news
}

// retiredSock is a packet_local port that no longer sends but still receives.
type retiredSock struct {
	conn net.PacketConn
	st   *sockState
	at   time.Time
}

type udpHopConn struct {
	dialer *finalmask.Dialer
	local  bool
	remote bool

	intervalMin int64
	intervalMax int64
	remoteIPs   []netip.Prefix
	remotePorts []uint32

	// packet_local: a fresh local port every packetsMin..packetsMax datagrams
	packetLocal bool
	packetsMin  int64
	packetsMax  int64
	sent        int64 // datagrams sent from cur (guarded by mu)
	limit       int64 // when cur is retired (guarded by mu)
	curSt       *sockState
	retired     []retiredSock

	deadline      time.Time
	readDeadline  time.Time
	writeDeadline time.Time

	pre     net.PacketConn
	cur     net.PacketConn
	addr    *net.UDPAddr
	readCh  chan packet
	closeCh chan struct{}
	wg      sync.WaitGroup
	mu      sync.RWMutex
}

func NewUDPHopConn(c *Config, dest *net.Destination, dialer *finalmask.Dialer) (net.PacketConn, error) {
	if c.IntervalMin < 5 || c.IntervalMax < 5 {
		return nil, errors.New("invalid interval")
	}
	if c.PacketLocal {
		if c.Local {
			return nil, errors.New("packetLocal and intervalLocal cannot be combined")
		}
		if c.PacketsMin < 1 || c.PacketsMax < c.PacketsMin {
			return nil, errors.New("invalid packets range")
		}
	}
	remoteIPs := make([]netip.Prefix, 0, len(c.RemoteIPs))
	for _, ip := range c.RemoteIPs {
		remoteIPs = append(remoteIPs, netip.MustParsePrefix(ip))
	}
	remotePorts := c.RemotePorts
	if c.Remote || c.RemoteOnce {
		if len(remoteIPs) > 0 {
			dest.Address = net.IPAddress(randPrefix(remoteIPs[mrand.Intn(len(remoteIPs))]))
		}
		if len(remotePorts) > 0 {
			dest.Port = net.Port(remotePorts[mrand.Intn(len(remotePorts))])
		}
	}
	conn, err := dialer.DialUDP(*dest)
	if err != nil {
		return nil, err
	}
	cur := conn.(*net.PacketConnWrapper).PacketConn
	addr := conn.RemoteAddr().(*net.UDPAddr)
	client := &udpHopConn{
		dialer: dialer,
		local:  c.Local,
		remote: c.Remote,

		intervalMin: c.IntervalMin,
		intervalMax: c.IntervalMax,
		remoteIPs:   remoteIPs,
		remotePorts: remotePorts,

		packetLocal: c.PacketLocal,
		packetsMin:  c.PacketsMin,
		packetsMax:  c.PacketsMax,
		curSt:       &sockState{},

		cur:     cur,
		addr:    addr,
		readCh:  make(chan packet),
		closeCh: make(chan struct{}),
	}
	if client.packetLocal {
		client.limit = crypto.RandBetween(client.packetsMin, client.packetsMax+1)
	}
	go client.run()
	client.wg.Add(1)
	go client.recv(client.cur, client.curSt)
	return client, nil
}

func (c *udpHopConn) closed() bool {
	select {
	case <-c.closeCh:
		return true
	default:
		return false
	}
}

func (c *udpHopConn) run() {
	ticker := time.NewTicker(time.Second * time.Duration(crypto.RandBetween(c.intervalMin, c.intervalMax+1)))
	defer ticker.Stop()
	for {
		select {
		case <-c.closeCh:
			return
		case <-ticker.C:
			ticker.Reset(time.Second * time.Duration(crypto.RandBetween(c.intervalMin, c.intervalMax+1)))
			c.hop()
		}
	}
}

func (c *udpHopConn) hop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed() {
		return
	}
	oldIP := c.addr.IP
	oldPort := c.addr.Port
	if c.remote {
		if len(c.remoteIPs) > 0 {
			c.addr.IP = randPrefix(c.remoteIPs[mrand.Intn(len(c.remoteIPs))])
		}
		if len(c.remotePorts) > 0 {
			c.addr.Port = int(c.remotePorts[mrand.Intn(len(c.remotePorts))])
		}
	}
	if c.local {
		conn, err := c.dialer.DialUDP(net.UDPDestination(net.IPAddress(c.addr.IP), net.Port(c.addr.Port)))
		if err != nil {
			c.addr.IP = oldIP
			c.addr.Port = oldPort
			errors.LogErrorInner(context.Background(), err, "hop err")
			return
		}
		conn.SetDeadline(c.deadline)
		conn.SetReadDeadline(c.readDeadline)
		conn.SetWriteDeadline(c.writeDeadline)
		if c.pre != nil {
			_ = c.pre.Close()
		}
		c.pre = c.cur
		c.cur = conn.(*net.PacketConnWrapper).PacketConn
		c.curSt = &sockState{}
		c.wg.Add(1)
		go c.recv(c.cur, c.curSt)
	}
}

// rotateLocked is packet_local's hop: send from a new local port from now on,
// keep the old one receiving, and close the retired ports that went quiet.
// Called with mu held.
func (c *udpHopConn) rotateLocked() {
	// whatever happens, wait another full allowance before the next attempt
	c.sent = 0
	c.limit = crypto.RandBetween(c.packetsMin, c.packetsMax+1)

	conn, err := c.dialer.DialUDP(net.UDPDestination(net.IPAddress(c.addr.IP), net.Port(c.addr.Port)))
	if err != nil {
		errors.LogErrorInner(context.Background(), err, "hop err")
		return
	}
	conn.SetDeadline(c.deadline)
	conn.SetReadDeadline(c.readDeadline)
	conn.SetWriteDeadline(c.writeDeadline)

	now := time.Now()
	c.retired = append(c.retired, retiredSock{conn: c.cur, st: c.curSt, at: now})
	c.cur = conn.(*net.PacketConnWrapper).PacketConn
	c.curSt = &sockState{}
	c.wg.Add(1)
	go c.recv(c.cur, c.curSt)

	kept := c.retired[:0]
	for _, r := range c.retired {
		if now.Sub(r.at) > packetLocalKeep && now.Sub(time.Unix(0, r.st.lastRx.Load())) > packetLocalKeep {
			r.st.closing.Store(true)
			_ = r.conn.Close()
			continue
		}
		kept = append(kept, r)
	}
	clear(c.retired[len(kept):])
	c.retired = kept
}

func (c *udpHopConn) recv(conn net.PacketConn, st *sockState) {
	defer c.wg.Done()

	for {
		p := pool.Get().([]byte)
		n, addr, err := conn.ReadFrom(p)
		if err == nil {
			st.lastRx.Store(time.Now().UnixNano())
		}
		if err != nil {
			pool.Put(p[:cap(p)])
			if c.closed() || st.closing.Load() {
				return
			}
			var netErr net.Error
			if goerrors.As(err, &netErr) && netErr.Timeout() {
				select {
				case c.readCh <- packet{err: err}:
				case <-c.closeCh:
					return
				}
				continue
			}
			errors.LogErrorInner(context.Background(), err, "recv err")
			return
		}
		select {
		case c.readCh <- packet{p: p[:n], addr: addr}:
		case <-c.closeCh:
			pool.Put(p[:cap(p)])
			return
		}
	}
}

func (c *udpHopConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	packet, ok := <-c.readCh
	if ok {
		if packet.p != nil {
			n = copy(p, packet.p)
			pool.Put(packet.p[:cap(packet.p)])
		}
		return n, packet.addr, packet.err
	}
	return 0, nil, io.ErrClosedPipe
}

func (c *udpHopConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if c.packetLocal {
		return c.writePacketLocal(p)
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, err = c.cur.WriteTo(p, c.addr)
	if err != nil {
		errors.LogErrorInner(context.Background(), err, "send err")
		return 0, err
	}
	return len(p), nil
}

// writePacketLocal counts datagrams on the current port and moves to a new one
// once its allowance is spent. The send itself runs outside the lock: a
// retired port is never closed right away, so the socket stays valid.
func (c *udpHopConn) writePacketLocal(p []byte) (int, error) {
	c.mu.Lock()
	if c.closed() {
		c.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	if c.sent >= c.limit {
		c.rotateLocked()
	}
	c.sent++
	conn := c.cur
	dst := *c.addr // intervalRemote may change c.addr meanwhile
	c.mu.Unlock()

	if _, err := conn.WriteTo(p, &dst); err != nil {
		errors.LogErrorInner(context.Background(), err, "send err")
		return 0, err
	}
	return len(p), nil
}

func (c *udpHopConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed() {
		return nil
	}
	close(c.closeCh)
	for _, r := range c.retired {
		_ = r.conn.Close()
	}
	c.retired = nil
	if c.pre != nil {
		_ = c.pre.Close()
	}
	_ = c.cur.Close()
	c.wg.Wait()
	close(c.readCh)
	return nil
}

func (c *udpHopConn) LocalAddr() net.Addr {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cur.LocalAddr()
}

func (c *udpHopConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadline = t
	if c.pre != nil {
		_ = c.pre.SetDeadline(t)
	}
	for _, r := range c.retired {
		_ = r.conn.SetDeadline(t)
	}
	return c.cur.SetDeadline(t)
}

func (c *udpHopConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	if c.pre != nil {
		_ = c.pre.SetReadDeadline(t)
	}
	for _, r := range c.retired {
		_ = r.conn.SetReadDeadline(t)
	}
	return c.cur.SetReadDeadline(t)
}

func (c *udpHopConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDeadline = t
	if c.pre != nil {
		_ = c.pre.SetWriteDeadline(t)
	}
	for _, r := range c.retired {
		_ = r.conn.SetWriteDeadline(t)
	}
	return c.cur.SetWriteDeadline(t)
}

func randPrefix(p netip.Prefix) []byte {
	if p.IsSingleIP() {
		return p.Addr().AsSlice()
	}
	b := p.Addr().AsSlice()
	prefix := p.Bits()
	var new [16]byte
	common.Must2(rand.Read(new[:len(b)]))
	i := prefix / 8
	j := prefix % 8
	if i+1 < len(b) {
		copy(b[i+1:], new[i+1:])
	}
	mask := byte(0xff << (8 - j))
	b[i] = (b[i] & mask) | (new[i] &^ mask)
	return b
}
