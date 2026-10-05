package wireguard

import (
	"context"
	goerrors "errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/GFW-knocker/Xray-core/common"
	"github.com/GFW-knocker/Xray-core/common/errors"
	"github.com/GFW-knocker/wireguard/conn"
	"github.com/GFW-knocker/wireguard/device"
)

// Source-port rotation: with rotateN > 0 the bind moves to a fresh socket
// (new source port) every rotateN datagrams, for paths that drop a UDP
// 4-tuple after a few packets. The peer roams to the new port by itself.
const defaultRetireGrace = time.Second

var recvBufPool = sync.Pool{New: func() any { return new([device.MaxMessageSize]byte) }}

// one UDP socket; its reader stops quietly once closed
type sock struct {
	conn     net.PacketConn
	stop     chan struct{}
	stopOnce sync.Once
}

func (s *sock) close() {
	s.stopOnce.Do(func() {
		close(s.stop)
		_ = s.conn.Close()
	})
}

type recvPkt struct {
	buf  *[device.MaxMessageSize]byte
	n    int
	addr net.Addr
	err  error
}

type bind struct {
	resolveFunc func(host string) (net.IP, error)
	listenFunc  func() (net.PacketConn, error)
	downFunc    func() error
	reserved    []byte

	// GFW-knocker: wireguard noise parameters, exposed via Get_extra_data().
	Wnoise           string
	Wheader          []byte
	WnoisecountFrom  int
	WnoisecountTo    int
	WnoisedelayFrom  int
	WnoisedelayTo    int
	WpayloadsizeFrom int
	WpayloadsizeTo   int

	rotateN     int           // datagrams per source port, 0 = never rotate
	retireGrace time.Duration // how long a rotated-out socket stays readable, 0 = default

	cur     *sock // current socket, all sends go through it
	sent    int   // datagrams sent on cur since it became current
	socks   map[*sock]bool
	recvCh  chan *recvPkt
	closeCh chan struct{}
	mu      sync.Mutex
}

func (b *bind) Open(port uint16) (fns []conn.ReceiveFunc, actualPort uint16, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.cur != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	c, err := b.listenFunc()
	if err != nil {
		return nil, 0, err
	}
	ch := make(chan struct{})
	recvCh := make(chan *recvPkt, 128)
	b.closeCh = ch
	b.recvCh = recvCh
	b.socks = make(map[*sock]bool)
	b.startSocketLocked(c)

	return []conn.ReceiveFunc{
		func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (n int, err error) {
			select {
			case <-ch:
				return 0, net.ErrClosed
			case p := <-recvCh:
				if p.err != nil {
					return 0, p.err
				}
				sizes[0] = copy(bufs[0], p.buf[:p.n])
				recvBufPool.Put(p.buf)
				if sizes[0] > 3 {
					bufs[0][1] = 0
					bufs[0][2] = 0
					bufs[0][3] = 0
				}
				eps[0] = &conn.StdNetEndpoint{AddrPort: p.addr.(*net.UDPAddr).AddrPort()}
				return 1, nil
			}
		},
	}, uint16(c.LocalAddr().(*net.UDPAddr).Port), nil
}

// startSocketLocked makes c the current send socket and starts its reader.
func (b *bind) startSocketLocked(c net.PacketConn) {
	s := &sock{conn: c, stop: make(chan struct{})}
	b.socks[s] = true
	b.cur = s
	b.sent = 0
	go b.serveRecv(s, b.recvCh)
}

// serveRecv pumps packets from one socket into the shared receive channel.
func (b *bind) serveRecv(s *sock, recvCh chan *recvPkt) {
	for {
		buf := recvBufPool.Get().(*[device.MaxMessageSize]byte)
		n, addr, err := s.conn.ReadFrom(buf[:])
		if err != nil {
			recvBufPool.Put(buf)
			select {
			case <-s.stop:
				return
			default:
			}
			if goerrors.Is(err, io.EOF) || goerrors.Is(err, io.ErrClosedPipe) || goerrors.Is(err, net.ErrClosed) {
				b.mu.Lock()
				current := b.cur == s
				downFunc := b.downFunc
				b.mu.Unlock()
				if !current {
					// a retired port died on its own, the tunnel does not care
					return
				}
				errors.LogErrorInner(context.Background(), err, "unexpected closed")
				select {
				case recvCh <- &recvPkt{err: net.ErrClosed}:
				case <-s.stop:
				}
				if downFunc != nil {
					go func() {
						common.Must(downFunc())
					}()
				}
				return
			}
			errors.LogErrorInner(context.Background(), err, "bind recv err")
			continue
		}
		select {
		case recvCh <- &recvPkt{buf: buf, n: n, addr: addr}:
		case <-s.stop:
			recvBufPool.Put(buf)
			return
		}
	}
}

// setDownFunc sets downFunc after the device is created, since the device may already be using the bind.
func (b *bind) setDownFunc(f func() error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.downFunc = f
}

func (b *bind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cur == nil {
		return nil
	}
	if b.closeCh != nil {
		close(b.closeCh)
		b.closeCh = nil
	}
	for s := range b.socks {
		s.close()
	}
	b.socks = nil
	b.cur = nil
	return nil
}

func (b *bind) SetMark(mark uint32) error {
	return nil
}

func (b *bind) Send(bufs [][]byte, ep conn.Endpoint) (err error) {
	nend, ok := ep.(*conn.StdNetEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}

	for i := range bufs {
		if len(bufs[i]) > 3 && len(b.reserved) == 3 {
			bufs[i][1] = b.reserved[0]
			bufs[i][2] = b.reserved[1]
			bufs[i][3] = b.reserved[2]
		}
		err = b.send(bufs[i], nend.AddrPort)
		if err != nil {
			errors.LogErrorInner(context.Background(), err, "bind send err")
			break
		}
	}
	return err
}

// send writes one datagram. With rotation off it only grabs the socket under
// the lock; with rotation on the write stays locked so the per-port count is
// exact. Noise packets go through here too, so they spend the same budget.
func (b *bind) send(p []byte, ap netip.AddrPort) error {
	b.mu.Lock()
	s := b.cur
	if s == nil {
		b.mu.Unlock()
		return syscall.EAFNOSUPPORT
	}
	if b.rotateN <= 0 {
		b.mu.Unlock()
		_, err := s.conn.WriteTo(p, net.UDPAddrFromAddrPort(ap))
		return err
	}
	defer b.mu.Unlock()
	if b.sent >= b.rotateN {
		b.rotateLocked()
	}
	b.sent++
	_, err := b.cur.conn.WriteTo(p, net.UDPAddrFromAddrPort(ap))
	return err
}

// rotateLocked swaps in a freshly bound socket. The old one stays readable
// for the grace period so replies racing the swap still land.
func (b *bind) rotateLocked() {
	c, err := b.listenFunc()
	if err != nil {
		// stay on the old port, try again on the next datagram
		errors.LogErrorInner(context.Background(), err, "bind rotate err")
		return
	}
	old := b.cur
	b.startSocketLocked(c)
	grace := b.retireGrace
	if grace <= 0 {
		grace = defaultRetireGrace
	}
	time.AfterFunc(grace, func() {
		b.mu.Lock()
		delete(b.socks, old)
		b.mu.Unlock()
		old.close()
	})
}

func (b *bind) ParseEndpoint(s string) (conn.Endpoint, error) {
	if b.resolveFunc == nil {
		e, err := netip.ParseAddrPort(s)
		if err != nil {
			return nil, err
		}
		return &conn.StdNetEndpoint{
			AddrPort: e,
		}, nil
	}
	host, sport, err := net.SplitHostPort(s)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(sport)
	if err != nil {
		return nil, err
	}
	if port < 0 || port > 65535 {
		return nil, errors.New("invalid port " + sport)
	}
	ip, err := b.resolveFunc(host)
	if err != nil {
		return nil, err
	}
	addr, _ := netip.AddrFromSlice(ip)
	return &conn.StdNetEndpoint{
		AddrPort: netip.AddrPortFrom(addr, uint16(port)),
	}, nil
}

func (b *bind) BatchSize() int {
	return 1
}

// --------- GFW knocker -----------------------
// Required by the conn.Bind interface in github.com/GFW-knocker/wireguard.

func (b *bind) Get_extra_data() (string, []byte, int, int, int, int, int, int) {
	return b.Wnoise, b.Wheader, b.WnoisecountFrom, b.WnoisecountTo, b.WnoisedelayFrom, b.WnoisedelayTo, b.WpayloadsizeFrom, b.WpayloadsizeTo
}

// Send_without_modify is Send without the reserved-bytes rewrite, so noise
// packets go out verbatim.
func (b *bind) Send_without_modify(bufs [][]byte, ep conn.Endpoint) (err error) {
	nend, ok := ep.(*conn.StdNetEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}

	for i := range bufs {
		err = b.send(bufs[i], nend.AddrPort)
		if err != nil {
			errors.LogErrorInner(context.Background(), err, "bind send err")
			break
		}
	}
	return err
}

// --------------------------------------------------------
