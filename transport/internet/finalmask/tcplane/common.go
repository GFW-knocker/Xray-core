// Package tcplane is a FinalMask UDP mask that carries a UDP transport's
// datagrams over many short-lived TCP connections ("lanes") instead of a UDP
// socket.
//
// It is meant for paths that cut a TCP connection's upstream after a dozen or
// two client packets and that block UDP: every lane carries only a few packets
// before the client switches to a fresh one, and the QUIC connection on top
// (hysteria2, xhttp h3, quic) provides the encryption, reliability, ordering
// and congestion control. A lane that dies is just packet loss to QUIC.
//
// Wire format. A lane starts with a 29-byte header
//
//	nonce(8) | (session(8) role(1) budget(4)) XOR k(nonce) | tag(8)
//
// keyed by the configured password, so it looks random and a lane without the
// password is dropped. The session ID is random per client socket; every lane
// of a session is one address to the QUIC server. After the header both sides
// send frames: [2-byte big-endian length][datagram]. A zero-length frame from
// the server ends a down lane.
//
// Lanes have one of two roles, so that each carries few client packets:
//
//   - An up lane carries the client's datagrams, several per TCP write when
//     they are small, until its write, lifetime or received-byte budget is
//     spent; then the client moves to an up lane it connected in advance.
//   - A down lane carries the server's datagrams. Its header goes out as soon
//     as it connects and names a byte budget; the server spreads its datagrams
//     over the session's down lanes, never past a lane's budget, then ends the
//     lane. The client sends nothing on it but TCP's own ACKs, and opens a
//     new one for each that ends.
//
// With no down lane open the server answers on the up lane the client last
// sent on.
package tcplane

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"sync"
	"time"
)

const (
	headerLen = 29
	roleUp    = 1
	roleDown  = 2
	// maxFrame is the largest datagram a frame can carry.
	maxFrame = 65535
)

type sessionID [8]byte

type keys struct {
	key []byte
}

func newKeys(password string) *keys {
	k := sha256.Sum256([]byte("xray-finalmask-tcplane:" + password))
	return &keys{key: k[:]}
}

func (k *keys) mac(label byte, parts ...[]byte) []byte {
	h := hmac.New(sha256.New, k.key)
	h.Write([]byte{label})
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

type laneHeader struct {
	nonce   [8]byte
	session sessionID
	role    byte
	budget  uint32 // down lanes: bytes the server may send, 0 = no limit
}

// seal writes a lane header into b.
func (k *keys) seal(b []byte, h laneHeader) {
	var plain [13]byte
	copy(plain[0:8], h.session[:])
	plain[8] = h.role
	binary.BigEndian.PutUint32(plain[9:13], h.budget)
	copy(b[0:8], h.nonce[:])
	ks := k.mac('k', h.nonce[:])
	for i := range plain {
		b[8+i] = plain[i] ^ ks[i]
	}
	copy(b[21:29], k.mac('t', h.nonce[:], plain[:])[:8])
}

// open checks a lane header and decodes it.
func (k *keys) open(b []byte) (h laneHeader, ok bool) {
	var plain [13]byte
	copy(h.nonce[:], b[0:8])
	ks := k.mac('k', h.nonce[:])
	for i := range plain {
		plain[i] = b[8+i] ^ ks[i]
	}
	if !hmac.Equal(b[21:29], k.mac('t', h.nonce[:], plain[:])[:8]) {
		return h, false
	}
	copy(h.session[:], plain[0:8])
	h.role = plain[8]
	h.budget = binary.BigEndian.Uint32(plain[9:13])
	return h, h.role == roleUp || h.role == roleDown
}

// appendFrame appends one framed datagram to b.
func appendFrame(b, p []byte) []byte {
	b = binary.BigEndian.AppendUint16(b, uint16(len(p)))
	return append(b, p...)
}

// readFrame reads one frame into a new slice.
func readFrame(r io.Reader, lb []byte) ([]byte, error) {
	if _, err := io.ReadFull(r, lb[:2]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(lb[:2]))
	p := make([]byte, n)
	if _, err := io.ReadFull(r, p); err != nil {
		return nil, err
	}
	return p, nil
}

// pick returns a value in [lo, hi].
func pick(lo, hi int64) int64 {
	if hi <= lo {
		return lo
	}
	return lo + rand.Int64N(hi-lo+1)
}

// resetClose closes a TCP connection with RST, so neither side keeps it in
// TIME_WAIT. Lanes are many and short; FIN handshakes would only add packets.
func resetClose(c net.Conn) {
	if l, ok := c.(interface{ SetLinger(int) error }); ok {
		_ = l.SetLinger(0)
	}
	_ = c.Close()
}

// deadline is a resettable read deadline, as in net.Pipe.
type deadline struct {
	mu     sync.Mutex
	timer  *time.Timer
	cancel chan struct{}
}

func newDeadline() *deadline {
	return &deadline{cancel: make(chan struct{})}
}

func (d *deadline) set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer != nil && !d.timer.Stop() {
		<-d.cancel // the timer fired and closed cancel
	}
	d.timer = nil
	closed := false
	select {
	case <-d.cancel:
		closed = true
	default:
	}
	if t.IsZero() {
		if closed {
			d.cancel = make(chan struct{})
		}
		return
	}
	if dur := time.Until(t); dur > 0 {
		if closed {
			d.cancel = make(chan struct{})
		}
		cancel := d.cancel
		d.timer = time.AfterFunc(dur, func() { close(cancel) })
		return
	}
	if !closed {
		close(d.cancel)
	}
}

func (d *deadline) wait() chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cancel
}

var errTimeout = os.ErrDeadlineExceeded
