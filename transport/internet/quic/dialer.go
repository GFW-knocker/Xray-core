package quic

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/GFW-knocker/Xray-core/common"
	"github.com/GFW-knocker/Xray-core/common/errors"
	"github.com/GFW-knocker/Xray-core/common/net"
	"github.com/GFW-knocker/Xray-core/common/task"
	"github.com/GFW-knocker/Xray-core/transport/internet"
	"github.com/GFW-knocker/Xray-core/transport/internet/quicdial"
	"github.com/GFW-knocker/Xray-core/transport/internet/stat"
	"github.com/GFW-knocker/Xray-core/transport/internet/tls"
	"github.com/apernet/quic-go"
)

type connectionContext struct {
	rawConn *sysConn
	// tr owns the goroutines reading and writing rawConn; it is closed together
	// with rawConn so a dead connection leaves nothing running behind it.
	tr *quic.Transport
	// GFW-knocker: quic.Conn is a struct containing a sync.Mutex and atomics, so it
	// must be held by pointer -- copying it would duplicate the lock.
	conn *quic.Conn
}

var errConnectionClosed = errors.New("connection closed")

func (c *connectionContext) openStream(destAddr net.Addr) (*interConn, error) {
	if !isActive(c.conn) {
		return nil, errConnectionClosed
	}

	stream, err := c.conn.OpenStream()
	if err != nil {
		return nil, err
	}

	conn := &interConn{
		stream: stream,
		local:  c.conn.LocalAddr(),
		remote: destAddr,
	}

	return conn, nil
}

// close tears the connection down. The socket goes before the transport:
// Transport.Close waits for its read loop, and a closed socket is what makes
// that loop return at once.
func (c *connectionContext) close() {
	if err := c.conn.CloseWithError(0, ""); err != nil {
		errors.LogInfoInner(context.Background(), err, "failed to close connection")
	}
	if err := c.rawConn.Close(); err != nil {
		errors.LogInfoInner(context.Background(), err, "failed to close raw connection")
	}
	if err := c.tr.Close(); err != nil {
		errors.LogInfoInner(context.Background(), err, "failed to close quic transport")
	}
}

// destConnections is the state kept for one destination.
type destConnections struct {
	// dialing is a one-slot semaphore held across a handshake to this
	// destination, so concurrent requests share one new connection instead of
	// each dialing their own. Unlike a mutex, a waiter can give up on its ctx.
	dialing chan struct{}
	// conns is guarded by clientConnections.access.
	conns []*connectionContext
	// quicVersion remembers which quicdial attempt last connected, so the
	// v2->v1 fallback is not re-paid on every dial.
	quicVersion atomic.Int32
}

// clientConnections tracks the QUIC connections of every quic outbound in the
// process.
//
// Lock order: a destination's dialing slot, then access. access is only held
// for map and slice work, never across network I/O, so a slow or dead server
// holds up nothing but other dials to that same server.
type clientConnections struct {
	access  sync.Mutex
	dests   map[net.Destination]*destConnections
	cleanup *task.Periodic
}

func isActive(s *quic.Conn) bool {
	select {
	case <-s.Context().Done():
		return false
	default:
		return true
	}
}

// splitInactive keeps the active connections and appends the rest to dead.
func splitInactive(conns []*connectionContext, dead []*connectionContext) ([]*connectionContext, []*connectionContext) {
	active := make([]*connectionContext, 0, len(conns))
	for _, c := range conns {
		if isActive(c.conn) {
			active = append(active, c)
		} else {
			dead = append(dead, c)
		}
	}
	return active, dead
}

func closeConnections(conns []*connectionContext) {
	if len(conns) > 0 {
		errors.LogInfo(context.Background(), "closing ", len(conns), " inactive quic connection(s)")
	}
	for _, c := range conns {
		c.close()
	}
}

func (s *clientConnections) cleanConnections() error {
	var dead []*connectionContext

	s.access.Lock()
	for _, d := range s.dests {
		d.conns, dead = splitInactive(d.conns, dead)
		if len(d.conns) == 0 {
			// drop the backing array; the entry itself stays for quicVersion
			d.conns = nil
		}
	}
	s.access.Unlock()

	// CloseWithError can wait on the connection's run loop: never under access
	closeConnections(dead)
	return nil
}

// destination returns the state for dest, creating it if needed.
func (s *clientConnections) destination(dest net.Destination) *destConnections {
	s.access.Lock()
	defer s.access.Unlock()

	if s.dests == nil {
		s.dests = make(map[net.Destination]*destConnections)
	}
	d := s.dests[dest]
	if d == nil {
		d = &destConnections{dialing: make(chan struct{}, 1)}
		s.dests[dest] = d
	}
	return d
}

// openStreamOnExisting opens a stream on an active connection to d, newest
// first, and returns nil if none can take one.
func (s *clientConnections) openStreamOnExisting(ctx context.Context, d *destConnections, destAddr net.Addr) *interConn {
	s.access.Lock()
	conns := append([]*connectionContext(nil), d.conns...)
	s.access.Unlock()

	for i := len(conns) - 1; i >= 0; i-- {
		conn, err := conns[i].openStream(destAddr)
		if err == nil {
			return conn
		}
		if err != errConnectionClosed {
			// typically the server's stream limit; another connection may have room
			errors.LogInfoInner(ctx, err, "failed to openStream: ")
		}
	}
	return nil
}

func (s *clientConnections) openConnection(ctx context.Context, destAddr net.Addr, config *Config, tlsConfig *tls.Config, sockopt *internet.SocketConfig) (stat.Connection, error) {
	dest := net.DestinationFromAddr(destAddr)
	d := s.destination(dest)

	if conn := s.openStreamOnExisting(ctx, d, destAddr); conn != nil {
		return conn, nil
	}

	select {
	case d.dialing <- struct{}{}:
	case <-ctx.Done():
		return nil, errors.New("gave up waiting for a quic connection to ", dest).Base(ctx.Err())
	}
	defer func() { <-d.dialing }()

	// whoever held the slot before us may have just connected
	if conn := s.openStreamOnExisting(ctx, d, destAddr); conn != nil {
		return conn, nil
	}

	var dead []*connectionContext
	s.access.Lock()
	d.conns, dead = splitInactive(d.conns, dead)
	s.access.Unlock()
	closeConnections(dead)

	errors.LogInfo(ctx, "dialing quic to ", dest)
	cc, err := dialConnection(ctx, dest, destAddr, config, tlsConfig, sockopt, &d.quicVersion)
	if err != nil {
		return nil, err
	}

	s.access.Lock()
	d.conns = append(d.conns, cc)
	s.access.Unlock()

	return cc.openStream(destAddr)
}

// dialConnection opens a new QUIC connection to dest on its own socket.
func dialConnection(ctx context.Context, dest net.Destination, destAddr net.Addr, config *Config, tlsConfig *tls.Config, sockopt *internet.SocketConfig, quicVersion *atomic.Int32) (*connectionContext, error) {
	rawConn, err := internet.DialSystem(ctx, dest, sockopt)
	if err != nil {
		return nil, errors.New("failed to dial to dest: ", err).AtWarning().Base(err)
	}

	quicConfig := &quic.Config{
		KeepAlivePeriod:      0,
		HandshakeIdleTimeout: 8 * time.Second,
		MaxIdleTimeout:       300 * time.Second,
	}
	// Versions is set per attempt by quicdial.Dial below, which prefers v2 and
	// falls back to v1.

	var udpConn *net.UDPConn
	switch conn := rawConn.(type) {
	case *net.UDPConn:
		udpConn = conn
	case *internet.PacketConnWrapper:
		udpConn, _ = conn.PacketConn.(*net.UDPConn)
	}
	if udpConn == nil {
		// TODO: Support sockopt for QUIC
		rawConn.Close()
		return nil, errors.New("QUIC with sockopt is unsupported").AtWarning()
	}

	sysConn, err := wrapSysConn(udpConn, config)
	if err != nil {
		rawConn.Close()
		return nil, err
	}
	tr := &quic.Transport{
		ConnectionIDLength: 12,
		Conn:               sysConn,
	}

	// The handshake follows ctx's cancellation, so a request that gives up stops
	// it, but not ctx's values: quic-go keeps the dial context (minus its
	// cancellation) as the connection's own for as long as it lives.
	dialCtx, cancel := context.WithCancel(context.Background())
	stop := context.AfterFunc(ctx, cancel)
	conn, err := quicdial.Dial(ctx, quicConfig, quicdial.Plain, quicVersion,
		func(cfg *quic.Config) (*quic.Conn, error) {
			return tr.Dial(dialCtx, destAddr, tlsConfig.GetTLSConfig(tls.WithDestination(dest)), cfg)
		})
	stop()
	cancel()
	if err != nil {
		sysConn.Close()
		tr.Close()
		return nil, err
	}

	return &connectionContext{
		conn:    conn,
		rawConn: sysConn,
		tr:      tr,
	}, nil
}

var client clientConnections

func init() {
	client.dests = make(map[net.Destination]*destConnections)
	client.cleanup = &task.Periodic{
		Interval: time.Minute,
		Execute:  client.cleanConnections,
	}
	common.Must(client.cleanup.Start())
}

func Dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	tlsConfig := tls.ConfigFromStreamSettings(streamSettings)
	if tlsConfig == nil {
		tlsConfig = &tls.Config{
			ServerName:    internalDomain,
			AllowInsecure: true,
		}
	}

	var destAddr *net.UDPAddr
	if dest.Address.Family().IsIP() {
		destAddr = &net.UDPAddr{
			IP:   dest.Address.IP(),
			Port: int(dest.Port),
		}
	} else {
		dialerIp := internet.DestIpAddress()
		if dialerIp != nil {
			destAddr = &net.UDPAddr{
				IP:   dialerIp,
				Port: int(dest.Port),
			}
			errors.LogInfo(ctx, "quic Dial use dialer dest addr: ", destAddr)
		} else {
			addr, err := net.ResolveUDPAddr("udp", dest.NetAddr())
			if err != nil {
				return nil, err
			}
			destAddr = addr
		}
	}

	config := streamSettings.ProtocolSettings.(*Config)

	return client.openConnection(ctx, destAddr, config, tlsConfig, streamSettings.SocketSettings)
}

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
}
