package masque

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/GFW-knocker/Xray-core/common/errors"
	"github.com/GFW-knocker/Xray-core/common/net"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// The HTTP/2 carrier drives the frame layer itself rather than going through
// http2.Transport.
//
// The reason is one line in x/net/http2: the transport refuses to send an
// extended CONNECT unless the server advertised SETTINGS_ENABLE_CONNECT_PROTOCOL,
// and Cloudflare's MASQUE edge does not advertise it while answering extended
// CONNECT perfectly well. There is no way to turn that check off, and the
// alternative to this file is vendoring thirteen thousand lines of HTTP/2 to
// delete one `if`. Everything below uses the same package's exported Framer and
// hpack, so the framing is still theirs; only the client policy is ours.
const (
	// What we advertise, and what we hand out again as data is consumed.
	h2InitialWindow = 4 << 20
	// A DATA frame larger than this is refused rather than buffered.
	h2MaxFrameSize = 1 << 16
)

// h2Stream is one HTTP/2 stream, used as the tunnel's bidirectional pipe.
type h2Stream struct {
	conn   net.Conn
	framer *http2.Framer

	writeMu sync.Mutex
	encoder *hpack.Encoder
	headers bytes.Buffer

	// Flow control the peer grants us for sending.
	windowMu   sync.Mutex
	windowCond *sync.Cond
	connWindow int32
	strmWindow int32

	incoming chan []byte
	pending  []byte

	closeOnce sync.Once
	closed    chan struct{}
	readErr   error
}

// openH2Stream performs the client preface, the settings exchange and one
// extended CONNECT, and hands back the stream to carry capsules on.
func openH2Stream(ctx context.Context, conn net.Conn, authority, path, protocol string) (*h2Stream, error) {
	s := &h2Stream{
		conn:       conn,
		framer:     http2.NewFramer(conn, conn),
		connWindow: 65535,
		strmWindow: 65535,
		incoming:   make(chan []byte, 64),
		closed:     make(chan struct{}),
	}
	s.framer.SetMaxReadFrameSize(h2MaxFrameSize)
	s.encoder = hpack.NewEncoder(&s.headers)
	s.windowCond = sync.NewCond(&s.windowMu)

	if _, err := io.WriteString(conn, http2.ClientPreface); err != nil {
		return nil, errors.New("masque: failed to send the HTTP/2 preface").Base(err)
	}
	if err := s.framer.WriteSettings(
		http2.Setting{ID: http2.SettingInitialWindowSize, Val: h2InitialWindow},
		http2.Setting{ID: http2.SettingMaxFrameSize, Val: h2MaxFrameSize},
	); err != nil {
		return nil, errors.New("masque: failed to send HTTP/2 settings").Base(err)
	}
	// Open the connection-level window too; the default 64 KiB would otherwise
	// cap the whole tunnel.
	if err := s.framer.WriteWindowUpdate(0, h2InitialWindow-65535); err != nil {
		return nil, errors.New("masque: failed to open the HTTP/2 window").Base(err)
	}

	// Stream 1: the first client-initiated stream, and the only one we open.
	if err := s.writeRequest(1, authority, path, protocol); err != nil {
		return nil, err
	}

	status, err := s.readResponse(ctx)
	if err != nil {
		return nil, err
	}
	if status < 200 || status > 299 {
		return nil, errors.New("masque: the edge refused the tunnel with status ", status)
	}

	go s.readLoop()
	return s, nil
}

func (s *h2Stream) writeRequest(id uint32, authority, path, protocol string) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	s.headers.Reset()
	// Pseudo-headers first, in the order a client sends them. :protocol is what
	// makes this an extended CONNECT (RFC 8441).
	for _, h := range []hpack.HeaderField{
		{Name: ":method", Value: http.MethodConnect},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: authority},
		{Name: ":path", Value: path},
		{Name: ":protocol", Value: protocol},
		{Name: "capsule-protocol", Value: "?1"},
	} {
		if err := s.encoder.WriteField(h); err != nil {
			return errors.New("masque: failed to encode the CONNECT headers").Base(err)
		}
	}

	if err := s.framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      id,
		BlockFragment: s.headers.Bytes(),
		EndStream:     false,
		EndHeaders:    true,
	}); err != nil {
		return errors.New("masque: failed to send the CONNECT").Base(err)
	}
	return nil
}

// readResponse reads frames until the answer to the CONNECT arrives, handling
// the settings exchange on the way.
func (s *h2Stream) readResponse(ctx context.Context) (int, error) {
	if deadline, ok := ctx.Deadline(); ok {
		s.conn.SetReadDeadline(deadline)
		defer s.conn.SetReadDeadline(time.Time{})
	}

	for {
		frame, err := s.framer.ReadFrame()
		if err != nil {
			return 0, errors.New("masque: no answer to the CONNECT").Base(err)
		}

		switch f := frame.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				s.applySettings(f)
				s.writeMu.Lock()
				err := s.framer.WriteSettingsAck()
				s.writeMu.Unlock()
				if err != nil {
					return 0, errors.New("masque: failed to acknowledge settings").Base(err)
				}
			}

		case *http2.WindowUpdateFrame:
			s.addWindow(f.StreamID, int32(f.Increment))

		case *http2.MetaHeadersFrame:
			return statusOf(f.PseudoValue("status"))

		case *http2.HeadersFrame:
			// The framer only builds MetaHeadersFrame when it has a decoder, so
			// decode this one by hand.
			status, err := s.decodeStatus(f)
			if err != nil {
				return 0, err
			}
			return status, nil

		case *http2.GoAwayFrame:
			return 0, errors.New("masque: the edge sent GOAWAY, error ", uint32(f.ErrCode))

		case *http2.RSTStreamFrame:
			return 0, errors.New("masque: the edge reset the stream, error ", uint32(f.ErrCode))

		case *http2.PingFrame:
			if !f.IsAck() {
				s.writePing(f.Data)
			}
		}
	}
}

func (s *h2Stream) decodeStatus(f *http2.HeadersFrame) (int, error) {
	status := ""
	decoder := hpack.NewDecoder(4096, func(h hpack.HeaderField) {
		if h.Name == ":status" {
			status = h.Value
		}
	})
	if _, err := decoder.Write(f.HeaderBlockFragment()); err != nil {
		return 0, errors.New("masque: the edge's response headers will not decode").Base(err)
	}
	return statusOf(status)
}

func statusOf(value string) (int, error) {
	if value == "" {
		return 0, errors.New("masque: the edge's response carried no :status")
	}
	status := 0
	for _, c := range value {
		if c < '0' || c > '9' {
			return 0, errors.New("masque: the edge's :status is not a number: ", value)
		}
		status = status*10 + int(c-'0')
	}
	return status, nil
}

func (s *h2Stream) applySettings(f *http2.SettingsFrame) {
	f.ForeachSetting(func(setting http2.Setting) error {
		if setting.ID == http2.SettingInitialWindowSize {
			s.windowMu.Lock()
			// A new initial window applies to the stream's remaining allowance.
			s.strmWindow = int32(setting.Val)
			s.windowCond.Broadcast()
			s.windowMu.Unlock()
		}
		return nil
	})
}

func (s *h2Stream) addWindow(streamID uint32, increment int32) {
	s.windowMu.Lock()
	if streamID == 0 {
		s.connWindow += increment
	} else {
		s.strmWindow += increment
	}
	s.windowCond.Broadcast()
	s.windowMu.Unlock()
}

func (s *h2Stream) writePing(data [8]byte) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.framer.WritePing(true, data)
}

// readLoop turns DATA frames into bytes for Read and keeps the connection's
// housekeeping going.
func (s *h2Stream) readLoop() {
	defer close(s.incoming)

	for {
		frame, err := s.framer.ReadFrame()
		if err != nil {
			s.readErr = err
			return
		}

		switch f := frame.(type) {
		case *http2.DataFrame:
			if len(f.Data()) > 0 {
				payload := make([]byte, len(f.Data()))
				copy(payload, f.Data())
				select {
				case s.incoming <- payload:
				case <-s.closed:
					return
				}
				// Hand the window straight back: the tunnel drains as fast as it
				// can and stalling it buys nothing.
				s.writeMu.Lock()
				s.framer.WriteWindowUpdate(0, uint32(len(payload)))
				s.framer.WriteWindowUpdate(f.StreamID, uint32(len(payload)))
				s.writeMu.Unlock()
			}
			if f.StreamEnded() {
				s.readErr = io.EOF
				return
			}

		case *http2.WindowUpdateFrame:
			s.addWindow(f.StreamID, int32(f.Increment))

		case *http2.SettingsFrame:
			if !f.IsAck() {
				s.applySettings(f)
				s.writeMu.Lock()
				s.framer.WriteSettingsAck()
				s.writeMu.Unlock()
			}

		case *http2.PingFrame:
			if !f.IsAck() {
				s.writePing(f.Data)
			}

		case *http2.GoAwayFrame:
			s.readErr = errors.New("masque: the edge sent GOAWAY, error ", uint32(f.ErrCode))
			return

		case *http2.RSTStreamFrame:
			s.readErr = errors.New("masque: the edge reset the stream, error ", uint32(f.ErrCode))
			return
		}
	}
}

// Read implements io.Reader over the stream's DATA frames.
func (s *h2Stream) Read(p []byte) (int, error) {
	for len(s.pending) == 0 {
		payload, ok := <-s.incoming
		if !ok {
			if s.readErr != nil {
				return 0, s.readErr
			}
			return 0, io.EOF
		}
		s.pending = payload
	}
	n := copy(p, s.pending)
	s.pending = s.pending[n:]
	return n, nil
}

// Write sends p as DATA frames, respecting what the peer's flow control allows.
func (s *h2Stream) Write(p []byte) (int, error) {
	written := 0
	for written < len(p) {
		allowed := s.takeWindow(len(p) - written)
		if allowed <= 0 {
			return written, errors.New("masque: the HTTP/2 stream is closed")
		}
		if allowed > h2MaxFrameSize {
			allowed = h2MaxFrameSize
		}

		s.writeMu.Lock()
		err := s.framer.WriteData(1, false, p[written:written+allowed])
		s.writeMu.Unlock()
		if err != nil {
			return written, err
		}
		written += allowed
	}
	return written, nil
}

// takeWindow blocks until the peer allows at least one byte, and returns how
// many of the wanted bytes may go out now.
func (s *h2Stream) takeWindow(want int) int {
	s.windowMu.Lock()
	defer s.windowMu.Unlock()

	for {
		select {
		case <-s.closed:
			return 0
		default:
		}

		available := s.connWindow
		if s.strmWindow < available {
			available = s.strmWindow
		}
		if available > 0 {
			allowed := want
			if int32(allowed) > available {
				allowed = int(available)
			}
			s.connWindow -= int32(allowed)
			s.strmWindow -= int32(allowed)
			return allowed
		}
		s.windowCond.Wait()
	}
}

func (s *h2Stream) Close() error {
	s.closeOnce.Do(func() {
		close(s.closed)
		s.windowMu.Lock()
		s.windowCond.Broadcast()
		s.windowMu.Unlock()
		s.conn.Close()
	})
	return nil
}
