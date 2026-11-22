package tcplane

import (
	"context"
	goerrors "errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/GFW-knocker/Xray-core/common/errors"
	"github.com/GFW-knocker/Xray-core/transport/internet/finalmask"
)

const (
	headerWait    = 10 * time.Second
	serverWrite   = 5 * time.Second
	laneQueue     = 256
	sessionIdle   = 3 * time.Minute
	nonceKeep     = 10 * time.Minute
	maxNonces     = 1 << 17
	coalesceLimit = 16 * 1024
	// a datagram waits this long for a down lane before it goes on an up lane
	pendingWait = 250 * time.Millisecond
	maxPending  = 512
)

type serverLane struct {
	conn   net.Conn
	sendCh chan []byte
	done   chan struct{}
	once   sync.Once
	ip     string
	role   byte
	budget int64 // down lanes: bytes the client allows, 0 = no limit

	// guarded by serverSession.mu
	sent int64
	full bool
}

func (l *serverLane) close() {
	l.once.Do(func() {
		close(l.done)
		resetClose(l.conn)
	})
}

func (l *serverLane) alive() bool {
	select {
	case <-l.done:
		return false
	default:
		return true
	}
}

type serverSession struct {
	id   sessionID
	addr *net.UDPAddr
	key  string

	mu        sync.Mutex
	lanes     []*serverLane
	last      time.Time
	pending   []pendingPkt // datagrams waiting for a down lane
	pendTimer *time.Timer
	reply     atomic.Pointer[serverLane]
}

type pendingPkt struct {
	b  []byte
	at time.Time
}

// send queues one datagram for the client, on the open down lane that has
// carried the least so far and still has budget for it. With none it waits up
// to pendingWait for the client's next down lane, then goes on the up lane the
// client last sent on (or else the newest live lane).
func (s *serverSession) send(b []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.pending) == 0 && s.sendDownLocked(b) {
		return
	}
	if len(s.pending) >= maxPending {
		// a full queue is a full socket buffer: drop
		return
	}
	s.pending = append(s.pending, pendingPkt{b: b, at: time.Now()})
	if s.pendTimer == nil {
		s.pendTimer = time.AfterFunc(pendingWait, s.flushTimer)
	}
}

// sendDownLocked queues b on a down lane, and reports false if none can
// take it.
func (s *serverSession) sendDownLocked(b []byte) bool {
	n := int64(len(b) + 2)
	var best *serverLane
	for _, l := range s.lanes {
		if l.role != roleDown || l.full || !l.alive() {
			continue
		}
		if l.budget > 0 && l.sent+n > l.budget {
			// spent: tell the client, which opens another
			l.full = true
			select {
			case l.sendCh <- []byte{}:
			default:
				l.close()
			}
			continue
		}
		if best == nil || l.sent < best.sent {
			best = l
		}
	}
	if best == nil {
		return false
	}
	select {
	case best.sendCh <- b:
		best.sent += n
	default:
		// lane backed up: drop, as a full UDP socket buffer would
	}
	return true
}

// flushLocked sends what waited, in order, while down lanes take it.
func (s *serverSession) flushLocked() {
	i := 0
	for ; i < len(s.pending); i++ {
		if !s.sendDownLocked(s.pending[i].b) {
			break
		}
	}
	if i > 0 {
		clear(s.pending[:i])
		s.pending = s.pending[i:]
	}
}

// flushTimer sends what still waits after pendingWait on an up lane.
func (s *serverSession) flushTimer() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pendTimer = nil
	s.flushLocked()
	if len(s.pending) == 0 {
		return
	}
	var fallback *serverLane
	if l := s.reply.Load(); l != nil && l.alive() {
		fallback = l
	} else {
		for i := len(s.lanes) - 1; i >= 0; i-- {
			if l := s.lanes[i]; l.alive() && !l.full {
				fallback = l
				break
			}
		}
	}
	now := time.Now()
	i := 0
	for ; i < len(s.pending) && now.Sub(s.pending[i].at) >= pendingWait; i++ {
		if fallback != nil {
			select {
			case fallback.sendCh <- s.pending[i].b:
			default:
			}
		}
	}
	clear(s.pending[:i])
	s.pending = s.pending[i:]
	if len(s.pending) > 0 {
		s.pendTimer = time.AfterFunc(pendingWait-now.Sub(s.pending[0].at), s.flushTimer)
	}
}

type inPacket struct {
	p    []byte
	addr net.Addr
}

type serverConn struct {
	cfg       *Config
	keys      *keys
	listeners []net.Listener
	local     net.Addr

	mu       sync.Mutex
	sessions map[sessionID]*serverSession
	byAddr   map[string]*serverSession
	perIP    map[string]int
	nonces   map[[8]byte]time.Time

	readCh    chan inPacket
	rd        *deadline
	closeOnce sync.Once
	closeCh   chan struct{}
}

func newServerConn(c *Config, addr net.Addr, lc *finalmask.ListenConfig) (*serverConn, error) {
	if lc == nil || lc.Listen == nil {
		return nil, goerrors.New("tcplane: no listener")
	}
	var ip net.IP
	port := 0
	switch a := addr.(type) {
	case *net.UDPAddr:
		ip, port = a.IP, a.Port
	case *net.TCPAddr:
		ip, port = a.IP, a.Port
	default:
		return nil, errors.New("tcplane: unsupported listen address ", addr)
	}
	ports := c.Ports
	if len(ports) == 0 {
		ports = []uint32{uint32(port)}
	}
	sc := &serverConn{
		cfg:      c,
		keys:     newKeys(c.Password),
		sessions: make(map[sessionID]*serverSession),
		byAddr:   make(map[string]*serverSession),
		perIP:    make(map[string]int),
		nonces:   make(map[[8]byte]time.Time),
		readCh:   make(chan inPacket, readQueue),
		rd:       newDeadline(),
		closeCh:  make(chan struct{}),
	}
	for _, p := range ports {
		l, err := lc.Listen(&net.TCPAddr{IP: ip, Port: int(p)})
		if err != nil {
			for _, l := range sc.listeners {
				l.Close()
			}
			return nil, errors.New("tcplane: listen on port ", p, " failed").Base(err)
		}
		sc.listeners = append(sc.listeners, l)
	}
	ta := sc.listeners[0].Addr()
	if t, ok := ta.(*net.TCPAddr); ok {
		sc.local = &net.UDPAddr{IP: t.IP, Port: t.Port}
	} else {
		sc.local = &net.UDPAddr{IP: ip, Port: port}
	}
	for _, l := range sc.listeners {
		go sc.accept(l)
	}
	go sc.clean()
	return sc, nil
}

func (s *serverConn) closed() bool {
	select {
	case <-s.closeCh:
		return true
	default:
		return false
	}
}

func (s *serverConn) accept(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if s.closed() {
				return
			}
			var ne net.Error
			if goerrors.As(err, &ne) && ne.Timeout() {
				continue
			}
			if goerrors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go s.handle(conn)
	}
}

func remoteIP(c net.Conn) (string, *net.UDPAddr) {
	switch a := c.RemoteAddr().(type) {
	case *net.TCPAddr:
		return a.IP.String(), &net.UDPAddr{IP: a.IP, Port: a.Port, Zone: a.Zone}
	default:
		return a.String(), nil
	}
}

func (s *serverConn) handle(conn net.Conn) {
	if s.cfg.Sndbuf > 0 {
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.SetWriteBuffer(int(s.cfg.Sndbuf))
		}
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	_ = conn.SetReadDeadline(time.Now().Add(headerWait))
	var hdr [headerLen]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		resetClose(conn)
		return
	}
	h, ok := s.keys.open(hdr[:])
	if !ok {
		errors.LogDebug(context.Background(), "tcplane: dropped a lane with a bad header from ", conn.RemoteAddr())
		// read and discard until the peer gives up, like a closed service
		_ = conn.SetReadDeadline(time.Now().Add(headerWait))
		_, _ = io.Copy(io.Discard, conn)
		resetClose(conn)
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	ip, first := remoteIP(conn)
	lane := &serverLane{
		conn:   conn,
		sendCh: make(chan []byte, laneQueue),
		done:   make(chan struct{}),
		ip:     ip,
		role:   h.role,
		budget: int64(h.budget),
	}
	sess := s.addLane(h.session, h.nonce, lane, first)
	if sess == nil {
		resetClose(conn)
		return
	}
	if ml := time.Duration(s.cfg.MaxLife) * time.Millisecond; ml > 0 {
		t := time.AfterFunc(ml, lane.close)
		defer t.Stop()
	}
	go s.writeLane(lane)

	var lb [2]byte
	for {
		p, err := readFrame(conn, lb[:])
		if err != nil {
			break
		}
		sess.reply.Store(lane)
		select {
		case s.readCh <- inPacket{p: p, addr: sess.addr}:
		case <-s.closeCh:
			lane.close()
			s.removeLane(sess, lane)
			return
		}
	}
	lane.close()
	s.removeLane(sess, lane)
}

// addLane attaches a lane to its session, creating the session on its first
// lane. It returns nil if the lane is refused.
func (s *serverConn) addLane(id sessionID, nonce [8]byte, lane *serverLane, first *net.UDPAddr) *serverSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed() {
		return nil
	}
	now := time.Now()
	if _, seen := s.nonces[nonce]; seen {
		errors.LogDebug(context.Background(), "tcplane: dropped a replayed lane from ", lane.ip)
		return nil
	}
	if len(s.nonces) >= maxNonces {
		for k, t := range s.nonces {
			if now.Sub(t) > nonceKeep/2 {
				delete(s.nonces, k)
			}
		}
		if len(s.nonces) >= maxNonces {
			clear(s.nonces)
		}
	}
	s.nonces[nonce] = now
	if limit := int(s.cfg.MaxLanesPerIp); limit > 0 && s.perIP[lane.ip] >= limit {
		errors.LogDebug(context.Background(), "tcplane: too many lanes from ", lane.ip)
		return nil
	}
	sess := s.sessions[id]
	if sess == nil {
		// The session's address is its first lane's, so logs and routing see
		// the client's real IP. A clash with a live session gets a private one.
		addr := first
		if addr == nil || s.byAddr[addr.String()] != nil {
			ip := make(net.IP, 16)
			ip[0], ip[1] = 0xfd, 0x00
			copy(ip[8:], id[:])
			addr = &net.UDPAddr{IP: ip, Port: 1}
		}
		sess = &serverSession{id: id, addr: addr, key: addr.String()}
		s.sessions[id] = sess
		s.byAddr[sess.key] = sess
		errors.LogDebug(context.Background(), "tcplane: new session from ", lane.ip, " as ", sess.key)
	}
	s.perIP[lane.ip]++
	sess.mu.Lock()
	sess.lanes = append(sess.lanes, lane)
	sess.last = now
	if lane.role == roleDown {
		sess.flushLocked()
	}
	sess.mu.Unlock()
	return sess
}

func (s *serverConn) removeLane(sess *serverSession, lane *serverLane) {
	s.mu.Lock()
	if n := s.perIP[lane.ip] - 1; n > 0 {
		s.perIP[lane.ip] = n
	} else {
		delete(s.perIP, lane.ip)
	}
	s.mu.Unlock()
	sess.mu.Lock()
	for i, l := range sess.lanes {
		if l == lane {
			sess.lanes = append(sess.lanes[:i], sess.lanes[i+1:]...)
			break
		}
	}
	sess.last = time.Now()
	sess.mu.Unlock()
}

// writeLane sends queued datagrams, several per write when they pile up.
func (s *serverConn) writeLane(l *serverLane) {
	buf := make([]byte, 0, coalesceLimit+2+maxFrame)
	for {
		var p []byte
		select {
		case p = <-l.sendCh:
		case <-l.done:
			return
		}
		buf = appendFrame(buf[:0], p)
	more:
		for len(buf) < coalesceLimit {
			select {
			case p = <-l.sendCh:
				buf = appendFrame(buf, p)
			default:
				break more
			}
		}
		_ = l.conn.SetWriteDeadline(time.Now().Add(serverWrite))
		if _, err := l.conn.Write(buf); err != nil {
			l.close()
			return
		}
	}
}

func (s *serverConn) clean() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
		case <-s.closeCh:
			return
		}
		now := time.Now()
		s.mu.Lock()
		for id, sess := range s.sessions {
			sess.mu.Lock()
			idle := len(sess.lanes) == 0 && now.Sub(sess.last) > sessionIdle
			sess.mu.Unlock()
			if idle {
				delete(s.sessions, id)
				delete(s.byAddr, sess.key)
			}
		}
		for k, t := range s.nonces {
			if now.Sub(t) > nonceKeep {
				delete(s.nonces, k)
			}
		}
		s.mu.Unlock()
	}
}

func (s *serverConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case in := <-s.readCh:
		return copy(p, in.p), in.addr, nil
	case <-s.closeCh:
		return 0, nil, net.ErrClosed
	case <-s.rd.wait():
		return 0, nil, errTimeout
	}
}

func (s *serverConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if s.closed() {
		return 0, net.ErrClosed
	}
	if len(p) > maxFrame {
		return 0, goerrors.New("tcplane: datagram too large")
	}
	if addr == nil {
		return len(p), nil
	}
	s.mu.Lock()
	sess := s.byAddr[addr.String()]
	s.mu.Unlock()
	if sess == nil {
		return len(p), nil
	}
	if len(p) == 0 {
		// a zero-length frame ends a lane, so it cannot carry a datagram
		return 0, nil
	}
	b := make([]byte, len(p))
	copy(b, p)
	sess.send(b)
	return len(p), nil
}

func (s *serverConn) Close() error {
	s.closeOnce.Do(func() {
		close(s.closeCh)
		for _, l := range s.listeners {
			l.Close()
		}
		s.mu.Lock()
		for _, sess := range s.sessions {
			sess.mu.Lock()
			for _, l := range sess.lanes {
				l.close()
			}
			sess.mu.Unlock()
		}
		s.mu.Unlock()
	})
	return nil
}

func (s *serverConn) LocalAddr() net.Addr {
	return s.local
}

func (s *serverConn) SetDeadline(t time.Time) error {
	return s.SetReadDeadline(t)
}

func (s *serverConn) SetReadDeadline(t time.Time) error {
	s.rd.set(t)
	return nil
}

func (s *serverConn) SetWriteDeadline(time.Time) error {
	return nil
}
