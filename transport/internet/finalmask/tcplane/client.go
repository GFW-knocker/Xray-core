package tcplane

import (
	"context"
	"crypto/rand"
	goerrors "errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/GFW-knocker/Xray-core/common/errors"
	xnet "github.com/GFW-knocker/Xray-core/common/net"
	"github.com/GFW-knocker/Xray-core/transport/internet/finalmask"
)

const (
	// writeWait is how long a datagram waits for an up lane before it is
	// dropped.
	writeWait = 3 * time.Second
	// a lane's TCP handshake may take 3x the usual connect time, within
	// these bounds: a SYN the firewall dropped must not hold a slot for long
	minDialTimeout = 800 * time.Millisecond
	maxDialTimeout = 3 * time.Second
	// down lanes go to "lanes" once this many bytes/s arrive
	busyDown = 32 * 1024
	// activeFor: after traffic, the full set of lanes is kept this long; an
	// idle session keeps a few.
	activeFor = 3 * time.Second
	readQueue = 1024
	outQueue  = 1024
	// coalesceMax keeps a write of several small datagrams within one TCP
	// segment on a 1500-byte MTU path.
	coalesceMax = 1360
	// coalesceSmall: only datagrams below this wait for company; a full-size
	// one (QUIC data) goes out at once
	coalesceSmall = 600
	// idleDown down lanes stay open while a session is idle, so the server can
	// still reach the client; activeUp up lanes are kept ready at least while
	// it is busy.
	idleDown = 2
	activeUp = 2
	// maxUpReady bounds the up lanes kept ready for a heavy upload
	maxUpReady = 64
	// from the third failed dial in a row, the next waits 100 ms, doubling up
	// to maxBackoff
	minBackoff = 100 * time.Millisecond
	maxBackoff = time.Second
	// the lane rate never drops below this after failed dials
	minDialRate = 5
)

type clientLane struct {
	conn   net.Conn
	role   byte
	born   time.Time
	header [headerLen]byte

	// up lanes; written by the writer goroutine only
	hdrSent bool

	// up lanes, guarded by clientConn.mu
	written     int64
	budgetPkts  int64
	budgetBytes int64
	lifeLen     time.Duration
	lifeEnd     time.Time // zero until the first write
	retired     bool

	recv  atomic.Int64
	dead  atomic.Bool
	ended atomic.Bool // down lanes: no longer counted as open
	first sync.Once
}

// spent reports whether an up lane must not carry another write.
func (l *clientLane) spent(now time.Time) bool {
	if l.dead.Load() {
		return true
	}
	if l.written >= l.budgetPkts {
		return true
	}
	if !l.lifeEnd.IsZero() && now.After(l.lifeEnd) {
		return true
	}
	// the server answers on an up lane only when no down lane is open
	return l.budgetBytes > 0 && l.recv.Load() >= l.budgetBytes
}

type clientConn struct {
	cfg    *Config
	keys   *keys
	dest   xnet.Destination
	dial   func(xnet.Destination) (net.Conn, error)
	ports  []uint32
	sessID sessionID

	mu          sync.Mutex
	current     *clientLane   // up lane being written
	upReady     []*clientLane // up lanes connected in advance
	down        []*clientLane // open down lanes
	dialingUp   int
	dialingDown int
	readyCh     chan struct{} // closed and replaced when an up lane gets ready
	lastWrite   time.Time
	tokens      float64
	tokenAt     time.Time
	refill      *time.Timer
	failures    int           // dial failures in a row
	retryAt     time.Time     // no new dial before this, after failures
	dialAvg     time.Duration // smoothed lane connect time
	offerRate   float64       // smoothed bytes/s handed to WriteTo
	offerAt     time.Time

	recvRate float64 // smoothed bytes/s read from down lanes
	dialRate float64 // lanes/s now allowed, at most maxRate

	offered  atomic.Int64 // bytes handed to WriteTo since offerAt
	received atomic.Int64 // bytes read since offerAt

	lastRead atomic.Int64 // unix nano

	outCh    chan []byte
	readCh   chan []byte
	readAddr atomic.Pointer[net.Addr]
	rd       *deadline

	closeOnce sync.Once
	closeCh   chan struct{}
}

func newClientConn(c *Config, dest *xnet.Destination, dialer *finalmask.Dialer) (*clientConn, error) {
	if dest == nil || dialer == nil {
		return nil, goerrors.New("tcplane: no destination")
	}
	dial := dialer.DialTCPDetached
	if dial == nil {
		dial = dialer.DialTCP
	}
	cc := &clientConn{
		cfg:      c,
		keys:     newKeys(c.Password),
		dest:     *dest,
		dial:     dial,
		ports:    c.Ports,
		readyCh:  make(chan struct{}),
		tokens:   float64(burst(c)),
		dialRate: float64(c.MaxRate),
		tokenAt:  time.Now(),
		outCh:    make(chan []byte, outQueue),
		readCh:   make(chan []byte, readQueue),
		rd:       newDeadline(),
		closeCh:  make(chan struct{}),
	}
	rand.Read(cc.sessID[:])
	var any net.Addr = &net.UDPAddr{IP: net.IPv4zero}
	cc.readAddr.Store(&any)
	cc.mu.Lock()
	cc.lastWrite = time.Now()
	cc.fillLocked()
	cc.mu.Unlock()
	go cc.writer()
	return cc, nil
}

// burst is the lane-rate bucket size: a new session may open all its lanes
// at once.
func burst(c *Config) int {
	return max(int(c.Lanes), 1) + activeUp + 1
}

func (c *clientConn) closed() bool {
	select {
	case <-c.closeCh:
		return true
	default:
		return false
	}
}

// takeToken spends one lane-rate token, or reports when the next one is due.
func (c *clientConn) takeToken(now time.Time) (bool, time.Duration) {
	if c.cfg.MaxRate <= 0 {
		return true, 0
	}
	rate := c.dialRate
	c.tokens += now.Sub(c.tokenAt).Seconds() * rate
	c.tokenAt = now
	if b := float64(burst(c.cfg)); c.tokens > b {
		c.tokens = b
	}
	if c.tokens >= 1 {
		c.tokens--
		return true, 0
	}
	return false, time.Duration((1 - c.tokens) / rate * float64(time.Second))
}

func (c *clientConn) active(now time.Time) bool {
	return now.Sub(c.lastWrite) < activeFor || now.Sub(time.Unix(0, c.lastRead.Load())) < activeFor
}

// fillLocked drops stale lanes and dials new ones until enough are open or
// connecting, within the lane rate.
func (c *clientConn) fillLocked() {
	if c.closed() {
		return
	}
	now := time.Now()
	idle := time.Duration(c.cfg.Idle) * time.Millisecond
	kept := c.upReady[:0]
	for _, l := range c.upReady {
		if l.dead.Load() || (idle > 0 && now.Sub(l.born) > idle) {
			go resetClose(l.conn)
			continue
		}
		kept = append(kept, l)
	}
	clear(c.upReady[len(kept):])
	c.upReady = kept
	keptDown := c.down[:0]
	for _, l := range c.down {
		if l.ended.Load() {
			continue
		}
		if l.dead.Load() || (idle > 0 && l.recv.Load() == 0 && now.Sub(l.born) > idle) {
			l.ended.Store(true)
			go resetClose(l.conn)
			continue
		}
		keptDown = append(keptDown, l)
	}
	clear(c.down[len(keptDown):])
	c.down = keptDown

	wantUp, wantDown := c.wantUpLocked(now), c.wantDownLocked()
	if !c.active(now) {
		wantUp, wantDown = 1, min(wantDown, idleDown)
	}
	for {
		needUp := len(c.upReady)+c.dialingUp < wantUp
		needDown := len(c.down)+c.dialingDown < wantDown
		if !needUp && !needDown {
			return
		}
		ok, wait := c.takeToken(now)
		if ok && now.Before(c.retryAt) {
			c.tokens++ // give it back
			ok, wait = false, c.retryAt.Sub(now)
		}
		if !ok {
			if c.refill == nil {
				c.refill = time.AfterFunc(wait, func() {
					c.mu.Lock()
					c.refill = nil
					c.fillLocked()
					c.mu.Unlock()
				})
			}
			return
		}
		// an up lane first when none is on hand, as writes wait for it
		role := byte(roleDown)
		if needUp && (len(c.upReady)+c.dialingUp == 0 || !needDown) {
			role = roleUp
		}
		if role == roleUp {
			c.dialingUp++
		} else {
			c.dialingDown++
		}
		go c.dialLane(role)
	}
}

// wantUpLocked is how many up lanes to keep ready: enough to cover the ones
// used up while a new one connects, at the rate the transport offers bytes
// (not the rate lanes were used, which a shortage of lanes would hold down),
// and at least activeUp.
func (c *clientConn) wantUpLocked(now time.Time) int {
	if el := now.Sub(c.offerAt); el >= 200*time.Millisecond {
		sample := float64(c.offered.Swap(0)) / el.Seconds()
		rsample := float64(c.received.Swap(0)) / el.Seconds()
		if c.offerAt.IsZero() {
			sample, rsample = 0, 0
		}
		c.offerRate = (c.offerRate + sample) / 2
		c.recvRate = (c.recvRate + rsample) / 2
		c.offerAt = now
	}
	dial := c.dialAvg
	if dial == 0 {
		dial = 300 * time.Millisecond
	}
	perLane := float64(c.cfg.PacketsMin+c.cfg.PacketsMax) / 2 * coalesceMax
	need := int(c.offerRate/perLane*dial.Seconds()*1.5) + 1
	// what already waits in the queue needs lanes too
	need = max(need, int(float64(len(c.outCh))*2/float64(c.cfg.PacketsMin+c.cfg.PacketsMax))+1)
	return min(max(need, activeUp), maxUpReady)
}

// wantDownLocked is how many down lanes to keep open: enough for the bytes
// arriving, as each takes about two connect times to open, fill and end, and
// at most "lanes". Call after wantUpLocked, which updates the rates.
func (c *clientConn) wantDownLocked() int {
	limit := max(int(c.cfg.Lanes), 1)
	budget := float64(c.cfg.BytesMin+c.cfg.BytesMax) / 2
	if budget <= 0 {
		return limit
	}
	dial := c.dialAvg
	if dial == 0 {
		dial = 300 * time.Millisecond
	}
	if c.recvRate >= busyDown {
		// a download: lanes must lead the rate, or the rate is held down by
		// the lanes
		return limit
	}
	need := int(c.recvRate/budget*2*dial.Seconds()*3) + idleDown
	return min(max(need, idleDown), limit)
}

func (c *clientConn) dialLane(role byte) {
	port := c.dest.Port
	if len(c.ports) > 0 {
		port = xnet.Port(c.ports[int(pick(0, int64(len(c.ports)-1)))])
	}
	dest := xnet.TCPDestination(c.dest.Address, port)

	type result struct {
		conn net.Conn
		err  error
	}
	res := make(chan result, 1)
	dialStart := time.Now()
	c.mu.Lock()
	timeout := min(max(3*c.dialAvg, minDialTimeout), maxDialTimeout)
	if c.dialAvg == 0 {
		timeout = maxDialTimeout
	}
	c.mu.Unlock()
	go func() {
		conn, err := c.dial(dest)
		res <- result{conn, err}
	}()
	var r result
	select {
	case r = <-res:
	case <-time.After(timeout):
		r.err = goerrors.New("tcplane: lane dial timeout")
		go func() {
			if late := <-res; late.conn != nil {
				resetClose(late.conn)
			}
		}()
	case <-c.closeCh:
		go func() {
			if late := <-res; late.conn != nil {
				resetClose(late.conn)
			}
		}()
		return
	}

	var l *clientLane
	if r.err == nil {
		if tc, ok := r.conn.(*net.TCPConn); ok {
			_ = tc.SetNoDelay(true)
		}
		l = &clientLane{
			conn:        r.conn,
			role:        role,
			born:        time.Now(),
			budgetPkts:  pick(c.cfg.PacketsMin, c.cfg.PacketsMax),
			budgetBytes: pick(c.cfg.BytesMin, c.cfg.BytesMax),
			lifeLen:     time.Duration(pick(c.cfg.LifeMin, c.cfg.LifeMax)) * time.Millisecond,
		}
		h := laneHeader{session: c.sessID, role: role}
		if role == roleDown {
			h.budget = uint32(min(l.budgetBytes, 1<<32-1))
		}
		rand.Read(h.nonce[:])
		c.keys.seal(l.header[:], h)
		if role == roleDown {
			// a down lane announces itself at once, so the server can use it
			_ = r.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if _, err := r.conn.Write(l.header[:]); err != nil {
				resetClose(r.conn)
				r.err, l = err, nil
			}
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if role == roleUp {
		c.dialingUp--
	} else {
		c.dialingDown--
	}
	if r.err != nil {
		errors.LogDebugInner(context.Background(), r.err, "tcplane: lane to ", dest, " failed")
		c.failures++
		// a failed dial is most often a SYN the firewall dropped after a
		// burst of new connections: open them more slowly (AIMD)
		c.dialRate = max(c.dialRate*0.85, minDialRate)
		if c.failures >= 3 {
			backoff := min(minBackoff<<min(c.failures-3, 6), maxBackoff)
			c.retryAt = time.Now().Add(backoff)
		}
		c.fillLocked()
		return
	}
	c.failures = 0
	c.retryAt = time.Time{}
	c.dialRate = min(c.dialRate+0.25, float64(c.cfg.MaxRate))
	if d := time.Since(dialStart); c.dialAvg == 0 {
		c.dialAvg = d
	} else {
		c.dialAvg = (c.dialAvg*7 + d) / 8
	}
	if c.closed() {
		resetClose(l.conn)
		return
	}
	go c.readLane(l)
	if role == roleUp {
		c.upReady = append(c.upReady, l)
		close(c.readyCh)
		c.readyCh = make(chan struct{})
	} else {
		c.down = append(c.down, l)
	}
}

func (c *clientConn) readLane(l *clientLane) {
	var lb [2]byte
	for {
		p, err := readFrame(l.conn, lb[:])
		if err != nil {
			break
		}
		if len(p) == 0 {
			// the server is done with this down lane
			break
		}
		c.lastRead.Store(time.Now().UnixNano())
		if l.role == roleDown {
			l.first.Do(func() {
				if dl := time.Duration(c.cfg.DownLife) * time.Millisecond; dl > 0 {
					time.AfterFunc(dl, func() { c.endDown(l) })
				}
			})
		}
		l.recv.Add(int64(len(p) + 2))
		c.received.Add(int64(len(p) + 2))
		select {
		case c.readCh <- p:
		case <-c.closeCh:
			return
		}
	}
	l.dead.Store(true)
	if l.role == roleDown {
		c.endDown(l)
	} else {
		resetClose(l.conn)
	}
}

// endDown closes a down lane and opens another in its place.
func (c *clientConn) endDown(l *clientLane) {
	if l.ended.Swap(true) {
		return
	}
	resetClose(l.conn)
	c.mu.Lock()
	for i, d := range c.down {
		if d == l {
			c.down = append(c.down[:i], c.down[i+1:]...)
			break
		}
	}
	c.fillLocked()
	c.mu.Unlock()
}

// retireLocked stops writing on an up lane and resets it after the grace
// period, so replies already in flight on it still arrive.
func (c *clientConn) retireLocked(l *clientLane) {
	if l.retired {
		return
	}
	l.retired = true
	grace := time.Duration(c.cfg.Grace) * time.Millisecond
	if l.dead.Load() || grace <= 0 {
		go resetClose(l.conn)
		return
	}
	time.AfterFunc(grace, func() { resetClose(l.conn) })
}

// upLane returns the up lane the next write goes on, waiting for one if
// needed, and counts the write against it.
func (c *clientConn) upLane() *clientLane {
	timeout := time.NewTimer(writeWait)
	defer timeout.Stop()
	for {
		c.mu.Lock()
		now := time.Now()
		c.lastWrite = now
		if l := c.current; l != nil && !l.spent(now) {
			l.written++
			if l.lifeEnd.IsZero() {
				l.lifeEnd = now.Add(l.lifeLen)
			}
			if len(c.upReady)+c.dialingUp < c.wantUpLocked(now) || len(c.down)+c.dialingDown < c.wantDownLocked() {
				// traffic resumed after an idle spell: open the lanes again
				c.fillLocked()
			}
			c.mu.Unlock()
			return l
		}
		if c.current != nil {
			c.retireLocked(c.current)
			c.current = nil
		}
		for len(c.upReady) > 0 {
			l := c.upReady[0]
			c.upReady[0] = nil
			c.upReady = c.upReady[1:]
			if !l.dead.Load() {
				c.current = l
				break
			}
			go resetClose(l.conn)
		}
		c.fillLocked()
		if c.current != nil {
			c.mu.Unlock()
			continue
		}
		wait := c.readyCh
		c.mu.Unlock()
		select {
		case <-wait:
		case <-timeout.C:
			return nil
		case <-c.closeCh:
			return nil
		}
	}
}

// writer sends queued datagrams on up lanes. Small datagrams that arrive
// within the flush time share one write, and so one packet of the lane's
// budget.
func (c *clientConn) writer() {
	flush := time.Duration(c.cfg.Flush) * time.Millisecond
	var carry []byte
	batch := make([]byte, 0, headerLen+2+maxFrame)
	for {
		var p []byte
		if carry != nil {
			p, carry = carry, nil
		} else {
			select {
			case p = <-c.outCh:
			case <-c.closeCh:
				return
			}
		}
		batch = appendFrame(batch[:0], p)
		if flush > 0 && len(p) < coalesceSmall {
			timer := time.NewTimer(flush)
		collect:
			for len(batch) < coalesceMax {
				select {
				case q := <-c.outCh:
					if len(batch)+2+len(q) > coalesceMax || len(q) >= coalesceSmall {
						carry = q
						break collect
					}
					batch = appendFrame(batch, q)
				case <-timer.C:
					break collect
				case <-c.closeCh:
					timer.Stop()
					return
				}
			}
			timer.Stop()
		}
		l := c.upLane()
		if l == nil {
			if c.closed() {
				return
			}
			errors.LogDebug(context.Background(), "tcplane: no lane ready, dropped datagrams")
			continue
		}
		b := batch
		if !l.hdrSent {
			// the header rides in the same segment as the first write
			b = append(append(make([]byte, 0, headerLen+len(batch)), l.header[:]...), batch...)
			l.hdrSent = true
		}
		_ = l.conn.SetWriteDeadline(time.Now().Add(writeWait))
		if _, err := l.conn.Write(b); err != nil {
			// lost like a UDP datagram; QUIC resends it on the next lane
			l.dead.Store(true)
		}
	}
}

func (c *clientConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c.closed() {
		return 0, net.ErrClosed
	}
	if len(p) > maxFrame {
		return 0, goerrors.New("tcplane: datagram too large")
	}
	if addr != nil {
		c.readAddr.Store(&addr)
	}
	if len(p) == 0 {
		return 0, nil
	}
	b := make([]byte, len(p))
	copy(b, p)
	select {
	case c.outCh <- b:
	default:
		// queue full: dropped, as a full UDP socket buffer would
	}
	c.offered.Add(int64(len(p)))
	return len(p), nil
}

func (c *clientConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case b := <-c.readCh:
		return copy(p, b), *c.readAddr.Load(), nil
	case <-c.closeCh:
		return 0, nil, net.ErrClosed
	case <-c.rd.wait():
		return 0, nil, errTimeout
	}
}

func (c *clientConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closeCh)
		c.mu.Lock()
		if c.refill != nil {
			c.refill.Stop()
		}
		if c.current != nil {
			go resetClose(c.current.conn)
			c.current = nil
		}
		for _, l := range c.upReady {
			go resetClose(l.conn)
		}
		for _, l := range c.down {
			l.ended.Store(true)
			go resetClose(l.conn)
		}
		c.upReady, c.down = nil, nil
		c.mu.Unlock()
	})
	return nil
}

func (c *clientConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4zero}
}

func (c *clientConn) SetDeadline(t time.Time) error {
	return c.SetReadDeadline(t)
}

func (c *clientConn) SetReadDeadline(t time.Time) error {
	c.rd.set(t)
	return nil
}

func (c *clientConn) SetWriteDeadline(time.Time) error {
	return nil
}
