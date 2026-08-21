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

	"github.com/GFW-knocker/Xray-core/common"
	"github.com/GFW-knocker/Xray-core/common/errors"
	"github.com/GFW-knocker/wireguard/conn"
)

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

	net.PacketConn
	closeCh chan struct{}
	mu      sync.Mutex
}

func (b *bind) Open(port uint16) (fns []conn.ReceiveFunc, actualPort uint16, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.PacketConn != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}

	c, err := b.listenFunc()
	if err != nil {
		return nil, 0, err
	}
	b.PacketConn = c
	ch := make(chan struct{})
	b.closeCh = ch

	return []conn.ReceiveFunc{
		func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (n int, err error) {
			for {
				n, addr, err := c.ReadFrom(bufs[0])
				if err != nil {
					if goerrors.Is(err, io.EOF) || goerrors.Is(err, io.ErrClosedPipe) || goerrors.Is(err, net.ErrClosed) {
						select {
						case <-ch:
						default:
							errors.LogErrorInner(context.Background(), err, "unexpected closed")
							if b.downFunc != nil {
								go func() {
									common.Must(b.downFunc())
								}()
							}
						}
						return 0, net.ErrClosed
					}
					errors.LogErrorInner(context.Background(), err, "bind recv err")
					continue
				}
				if n > 3 {
					bufs[0][1] = 0
					bufs[0][2] = 0
					bufs[0][3] = 0
				}
				sizes[0] = n
				eps[0] = &conn.StdNetEndpoint{AddrPort: addr.(*net.UDPAddr).AddrPort()}
				return 1, nil
			}
		},
	}, uint16(c.LocalAddr().(*net.UDPAddr).Port), nil
}

func (b *bind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.PacketConn != nil {
		close(b.closeCh)
		_ = b.PacketConn.Close()
		b.PacketConn = nil
	}
	return nil
}

func (b *bind) SetMark(mark uint32) error {
	return nil
}

func (b *bind) Send(bufs [][]byte, ep conn.Endpoint) (err error) {
	b.mu.Lock()
	c := b.PacketConn
	b.mu.Unlock()

	if c == nil {
		return syscall.EAFNOSUPPORT
	}

	for i := range bufs {
		if len(bufs[i]) > 3 && len(b.reserved) == 3 {
			bufs[i][1] = b.reserved[0]
			bufs[i][2] = b.reserved[1]
			bufs[i][3] = b.reserved[2]
		}
		_, err = c.WriteTo(bufs[i], net.UDPAddrFromAddrPort(ep.(*conn.StdNetEndpoint).AddrPort))
		if err != nil {
			errors.LogErrorInner(context.Background(), err, "bind send err")
			break
		}
	}
	return err
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
	b.mu.Lock()
	c := b.PacketConn
	b.mu.Unlock()

	if c == nil {
		return syscall.EAFNOSUPPORT
	}

	nend, ok := ep.(*conn.StdNetEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}

	for i := range bufs {
		_, err = c.WriteTo(bufs[i], net.UDPAddrFromAddrPort(nend.AddrPort))
		if err != nil {
			errors.LogErrorInner(context.Background(), err, "bind send err")
			break
		}
	}
	return err
}

// --------------------------------------------------------
