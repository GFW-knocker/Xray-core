package freedom

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"math/big"
	"regexp"
	"time"

	"github.com/pires/go-proxyproto"
	"github.com/GFW-knocker/Xray-core/common"
	"github.com/GFW-knocker/Xray-core/common/buf"
	"github.com/GFW-knocker/Xray-core/common/crypto"
	"github.com/GFW-knocker/Xray-core/common/dice"
	"github.com/GFW-knocker/Xray-core/common/errors"
	"github.com/GFW-knocker/Xray-core/common/net"
	"github.com/GFW-knocker/Xray-core/common/platform"
	"github.com/GFW-knocker/Xray-core/common/retry"
	"github.com/GFW-knocker/Xray-core/common/session"
	"github.com/GFW-knocker/Xray-core/common/signal"
	"github.com/GFW-knocker/Xray-core/common/task"
	"github.com/GFW-knocker/Xray-core/common/utils"
	"github.com/GFW-knocker/Xray-core/core"
	"github.com/GFW-knocker/Xray-core/features/policy"
	"github.com/GFW-knocker/Xray-core/features/stats"
	"github.com/GFW-knocker/Xray-core/proxy"
	"github.com/GFW-knocker/Xray-core/transport"
	"github.com/GFW-knocker/Xray-core/transport/internet"
	"github.com/GFW-knocker/Xray-core/transport/internet/stat"


)

var useSplice bool

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		h := new(Handler)
		if err := core.RequireFeatures(ctx, func(pm policy.Manager) error {
			return h.Init(config.(*Config), pm)
		}); err != nil {
			return nil, err
		}
		return h, nil
	}))
	const defaultFlagValue = "NOT_DEFINED_AT_ALL"
	value := platform.NewEnvFlag(platform.UseFreedomSplice).GetValue(func() string { return defaultFlagValue })
	switch value {
	case defaultFlagValue, "auto", "enable":
		useSplice = true
	}
}

// Handler handles Freedom connections.
type Handler struct {
	policyManager policy.Manager
	config        *Config
}

// Init initializes the Handler with necessary parameters.
func (h *Handler) Init(config *Config, pm policy.Manager) error {
	h.config = config
	h.policyManager = pm
	return nil
}

func (h *Handler) policy() policy.Session {
	p := h.policyManager.ForLevel(h.config.UserLevel)
	return p
}

func isValidAddress(addr *net.IPOrDomain) bool {
	if addr == nil {
		return false
	}

	a := addr.AsAddress()
	return a != net.AnyIP && a != net.AnyIPv6
}

// Process implements proxy.Outbound.
func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("target not specified.")
	}
	ob.Name = "freedom"
	ob.CanSpliceCopy = 1
	inbound := session.InboundFromContext(ctx)

	destination := ob.Target
	origTargetAddr := ob.OriginalTarget.Address
	if origTargetAddr == nil {
		origTargetAddr = ob.Target.Address
	}
	dialer.SetOutboundGateway(ctx, ob)
	outGateway := ob.Gateway
	UDPOverride := net.UDPDestination(nil, 0)
	if h.config.DestinationOverride != nil {
		server := h.config.DestinationOverride.Server
		if isValidAddress(server.Address) {
			destination.Address = server.Address.AsAddress()
			UDPOverride.Address = destination.Address
		}
		if server.Port != 0 {
			destination.Port = net.Port(server.Port)
			UDPOverride.Port = destination.Port
		}
	}

	input := link.Reader
	output := link.Writer

	var conn stat.Connection
	err := retry.ExponentialBackoff(5, 100).On(func() error {
		dialDest := destination
		if h.config.DomainStrategy.HasStrategy() && dialDest.Address.Family().IsDomain() {
			strategy := h.config.DomainStrategy
			if destination.Network == net.Network_UDP && origTargetAddr != nil && outGateway == nil {
				strategy = strategy.GetDynamicStrategy(origTargetAddr.Family())
			}
			ips, err := internet.LookupForIP(dialDest.Address.Domain(), strategy, outGateway)
			if err != nil {
				errors.LogInfoInner(ctx, err, "failed to get IP address for domain ", dialDest.Address.Domain())
				if h.config.DomainStrategy.ForceIP() {
					return err
				}
			} else {
				dialDest = net.Destination{
					Network: dialDest.Network,
					Address: net.IPAddress(ips[dice.Roll(len(ips))]),
					Port:    dialDest.Port,
				}
				errors.LogInfo(ctx, "dialing to ", dialDest)
			}
		}

		rawConn, err := dialer.Dial(ctx, dialDest)
		if err != nil {
			return err
		}

		if h.config.ProxyProtocol > 0 && h.config.ProxyProtocol <= 2 {
			version := byte(h.config.ProxyProtocol)
			srcAddr := inbound.Source.RawNetAddr()
			dstAddr := rawConn.RemoteAddr()
			header := proxyproto.HeaderProxyFromAddrs(version, srcAddr, dstAddr)
			if _, err = header.WriteTo(rawConn); err != nil {
				rawConn.Close()
				return err
			}
		}

		conn = rawConn
		return nil
	})
	if err != nil {
		return errors.New("failed to open connection to ", destination).Base(err)
	}
	defer conn.Close()
	errors.LogInfo(ctx, "connection opened to ", destination, ", local endpoint ", conn.LocalAddr(), ", remote endpoint ", conn.RemoteAddr())

	var newCtx context.Context
	var newCancel context.CancelFunc
	if session.TimeoutOnlyFromContext(ctx) {
		newCtx, newCancel = context.WithCancel(context.Background())
	}

	plcy := h.policy()
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, func() {
		cancel()
		if newCancel != nil {
			newCancel()
		}
	}, plcy.Timeouts.ConnectionIdle)

	requestDone := func() error {
		defer timer.SetTimeout(plcy.Timeouts.DownlinkOnly)

		var writer buf.Writer
		if destination.Network == net.Network_TCP {
			if h.config.Fragment != nil {
				errors.LogDebug(ctx, "FRAGMENT", h.config.Fragment.PacketsFrom, h.config.Fragment.PacketsTo, h.config.Fragment.LengthMin, h.config.Fragment.LengthMax,
					h.config.Fragment.IntervalMin, h.config.Fragment.IntervalMax, h.config.Fragment.MaxSplitMin, h.config.Fragment.MaxSplitMax)
				writer = buf.NewWriter(&FragmentWriter{
					fragment: h.config.Fragment,
					writer:   conn,
				})
			} else {
				writer = buf.NewWriter(conn)
			}
		} else {
			writer = NewPacketWriter(conn, h, UDPOverride, destination)
			if h.config.Noises != nil {
				errors.LogDebug(ctx, "NOISE", h.config.Noises)
				writer = &NoisePacketWriter{
					Writer:      writer,
					noises:      h.config.Noises,
					noiseKeepAlive: h.config.NoiseKeepAlive,
					firstWrite:  true,
					UDPOverride: UDPOverride,
					remoteAddr:  net.DestinationFromAddr(conn.RemoteAddr()).Address,
				}
			}
		}

		if err := buf.Copy(input, writer, buf.UpdateActivity(timer)); err != nil {
			return errors.New("failed to process request").Base(err)
		}

		return nil
	}

	responseDone := func() error {
		defer timer.SetTimeout(plcy.Timeouts.UplinkOnly)
		if destination.Network == net.Network_TCP && useSplice && proxy.IsRAWTransportWithoutSecurity(conn) { // it would be tls conn in special use case of MITM, we need to let link handle traffic
			var writeConn net.Conn
			var inTimer *signal.ActivityTimer
			if inbound := session.InboundFromContext(ctx); inbound != nil && inbound.Conn != nil {
				writeConn = inbound.Conn
				inTimer = inbound.Timer
			}
			return proxy.CopyRawConnIfExist(ctx, conn, writeConn, link.Writer, timer, inTimer)
		}
		var reader buf.Reader
		if destination.Network == net.Network_TCP {
			reader = buf.NewReader(conn)
		} else {
			reader = NewPacketReader(conn, UDPOverride, destination)
		}
		if err := buf.Copy(reader, output, buf.UpdateActivity(timer)); err != nil {
			return errors.New("failed to process response").Base(err)
		}
		return nil
	}

	if newCtx != nil {
		ctx = newCtx
	}

	if err := task.Run(ctx, requestDone, task.OnSuccess(responseDone, task.Close(output))); err != nil {
		return errors.New("connection ends").Base(err)
	}

	return nil
}

func NewPacketReader(conn net.Conn, UDPOverride net.Destination, DialDest net.Destination) buf.Reader {
	iConn := conn
	statConn, ok := iConn.(*stat.CounterConnection)
	if ok {
		iConn = statConn.Connection
	}
	var counter stats.Counter
	if statConn != nil {
		counter = statConn.ReadCounter
	}
	if c, ok := iConn.(*internet.PacketConnWrapper); ok {
		isOverridden := false
		if UDPOverride.Address != nil || UDPOverride.Port != 0 {
			isOverridden = true
		}

		return &PacketReader{
			PacketConnWrapper: c,
			Counter:           counter,
			IsOverridden:      isOverridden,
			InitUnchangedAddr: DialDest.Address,
			InitChangedAddr:   net.DestinationFromAddr(conn.RemoteAddr()).Address,
		}
	}
	return &buf.PacketReader{Reader: conn}
}

type PacketReader struct {
	*internet.PacketConnWrapper
	stats.Counter
	IsOverridden      bool
	InitUnchangedAddr net.Address
	InitChangedAddr   net.Address
}

func (r *PacketReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	b := buf.New()
	b.Resize(0, buf.Size)
	n, d, err := r.PacketConnWrapper.ReadFrom(b.Bytes())
	if err != nil {
		b.Release()
		return nil, err
	}
	b.Resize(0, int32(n))
	// if udp dest addr is changed, we are unable to get the correct src addr
	// so we don't attach src info to udp packet, break cone behavior, assuming the dial dest is the expected scr addr
	if !r.IsOverridden {
		address := net.IPAddress(d.(*net.UDPAddr).IP)
		if r.InitChangedAddr == address {
			address = r.InitUnchangedAddr
		}
		b.UDP = &net.Destination{
			Address: address,
			Port:    net.Port(d.(*net.UDPAddr).Port),
			Network: net.Network_UDP,
		}
	}
	if r.Counter != nil {
		r.Counter.Add(int64(n))
	}
	return buf.MultiBuffer{b}, nil
}

// DialDest means the dial target used in the dialer when creating conn
func NewPacketWriter(conn net.Conn, h *Handler, UDPOverride net.Destination, DialDest net.Destination) buf.Writer {
	iConn := conn
	statConn, ok := iConn.(*stat.CounterConnection)
	if ok {
		iConn = statConn.Connection
	}
	var counter stats.Counter
	if statConn != nil {
		counter = statConn.WriteCounter
	}
	if c, ok := iConn.(*internet.PacketConnWrapper); ok {
		// If DialDest is a domain, it will be resolved in dialer
		// check this behavior and add it to map
		resolvedUDPAddr := utils.NewTypedSyncMap[string, net.Address]()
		if DialDest.Address.Family().IsDomain() {
			resolvedUDPAddr.Store(DialDest.Address.Domain(), net.DestinationFromAddr(conn.RemoteAddr()).Address)
		}
		return &PacketWriter{
			PacketConnWrapper: c,
			Counter:           counter,
			Handler:           h,
			UDPOverride:       UDPOverride,
			ResolvedUDPAddr:   resolvedUDPAddr,
			LocalAddr:         net.DestinationFromAddr(conn.LocalAddr()).Address,
		}

	}
	return &buf.SequentialWriter{Writer: conn}
}

type PacketWriter struct {
	*internet.PacketConnWrapper
	stats.Counter
	*Handler
	UDPOverride net.Destination

	// Dest of udp packets might be a domain, we will resolve them to IP
	// But resolver will return a random one if the domain has many IPs
	// Resulting in these packets being sent to many different IPs randomly
	// So, cache and keep the resolve result
	ResolvedUDPAddr *utils.TypedSyncMap[string, net.Address]
	LocalAddr       net.Address
}

func (w *PacketWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for {
		mb2, b := buf.SplitFirst(mb)
		mb = mb2
		if b == nil {
			break
		}
		var n int
		var err error
		if b.UDP != nil {
			if w.UDPOverride.Address != nil {
				b.UDP.Address = w.UDPOverride.Address
			}
			if w.UDPOverride.Port != 0 {
				b.UDP.Port = w.UDPOverride.Port
			}
			if b.UDP.Address.Family().IsDomain() {
				if ip, ok := w.ResolvedUDPAddr.Load(b.UDP.Address.Domain()); ok {
					b.UDP.Address = ip
				} else {
					ShouldUseSystemResolver := true
					if w.Handler.config.DomainStrategy.HasStrategy() {
						ips, err := internet.LookupForIP(b.UDP.Address.Domain(), w.Handler.config.DomainStrategy, w.LocalAddr)
						if err != nil {
							// drop packet if resolve failed when forceIP
							if w.Handler.config.DomainStrategy.ForceIP() {
								b.Release()
								continue
							}
						} else {
							ip = net.IPAddress(ips[dice.Roll(len(ips))])
							ShouldUseSystemResolver = false
						}
					}
					if ShouldUseSystemResolver {
						udpAddr, err := net.ResolveUDPAddr("udp", b.UDP.NetAddr())
						if err != nil {
							b.Release()
							continue
						} else {
							ip = net.IPAddress(udpAddr.IP)
						}
					}
					if ip != nil {
						b.UDP.Address, _ = w.ResolvedUDPAddr.LoadOrStore(b.UDP.Address.Domain(), ip)
					}
				}
			}
			destAddr := b.UDP.RawNetAddr()
			if destAddr == nil {
				b.Release()
				continue
			}
			n, err = w.PacketConnWrapper.WriteTo(b.Bytes(), destAddr)
		} else {
			n, err = w.PacketConnWrapper.Write(b.Bytes())
		}
		b.Release()
		if err != nil {
			buf.ReleaseMulti(mb)
			return err
		}
		if w.Counter != nil {
			w.Counter.Add(int64(n))
		}
	}
	return nil
}

type NoisePacketWriter struct {
	buf.Writer
	noises         []*Noise
	noiseKeepAlive uint32
	firstWrite     bool
	UDPOverride    net.Destination
	remoteAddr     net.Address
	stopChan       chan struct{} // Channel to stop the keepalive goroutine
	ticker         *time.Ticker  // Ticker for periodic noise
}

// MultiBuffer writer with Noise before first packet
func (w *NoisePacketWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if w.firstWrite {
		w.firstWrite = false
		//Do not send Noise for dns requests(just to be safe)
		if w.UDPOverride.Port == 53 {
			return w.Writer.WriteMultiBuffer(mb)
		}
		var noise []byte
		var err error
		if w.remoteAddr.Family().IsDomain() {
			panic("impossible, remoteAddr is always IP")
		}
		for _, n := range w.noises {
			switch n.ApplyTo {
			case "ipv4":
				if w.remoteAddr.Family().IsIPv6() {
					continue
				}
			case "ipv6":
				if w.remoteAddr.Family().IsIPv4() {
					continue
				}
			case "ip":
			default:
				panic("unreachable, applyTo is ip/ipv4/ipv6")
			}
			//User input string or base64 encoded string or hex string
			if n.Packet != nil {
				noise = n.Packet
			} else {
				//Random noise
				noise, err = GenerateRandomBytes(crypto.RandBetween(int64(n.LengthMin),
					int64(n.LengthMax)))
			}
			if err != nil {
				return err
			}
			err = w.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(noise)})
			if err != nil {
				return err
			}

		// Send initial noise
		if err := w.sendNoise(); err != nil {
			return err
		}

		// Start keepalive goroutine
		if w.noiseKeepAlive > 0 {
			w.stopChan = make(chan struct{})
			w.ticker = time.NewTicker(time.Duration(w.noiseKeepAlive) * time.Second)
			go w.keepNoiseAlive()
		}

	}
	return w.Writer.WriteMultiBuffer(mb)
}

func (w *NoisePacketWriter) sendNoise() error {
	var noise []byte
	var err error
	var count int64
	var delay time.Duration

	for _, n := range w.noises {
		//User input string or base64 encoded string
		if n.Packet != nil {
			noise = n.Packet
		} else {
			//Random noise
			noise, err = GenerateRandomBytes(randBetween(int64(n.LengthMin), int64(n.LengthMax)))
		}
		if err != nil {
			return err
		}

		count = randBetween(int64(n.CountMin), int64(n.CountMax))
		if count < 1 {
			count = 1
		} else if count > 100 {
			count = 100
		}

		if n.DelayMin != 0 || n.DelayMax != 0 {
			delay = time.Duration(randBetween(int64(n.DelayMin), int64(n.DelayMax))) * time.Millisecond
		} else {
			delay = time.Duration(0)
		}

		for range count {
			w.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(noise)})
			if delay > 0 {
				time.Sleep(delay)
			}
		}

	}
	return nil
}

func (w *NoisePacketWriter) keepNoiseAlive() {
	for {
		select {
		case <-w.ticker.C:
			if err := w.sendNoise(); err != nil {
				break
			}
		case <-w.stopChan:
			w.ticker.Stop()
			return
		}
	}
}

// Close implements io.Closer
func (w *NoisePacketWriter) Close() error {
	if w.stopChan != nil {
		close(w.stopChan)
	}
	if closer, ok := w.Writer.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

type FragmentWriter struct {
	fragment *Fragment
	writer   io.Writer
	count    uint64
}

var re = regexp.MustCompile("(?i)(\r\nHost:.*\r\n)")

func (f *FragmentWriter) Write(b []byte) (int, error) {
	f.count++

	if f.fragment.FakeHost {

		if f.count < 500 {
			if len(b) >= 5 {
				if (b[0] == 'P' && b[1] == 'O' && b[2] == 'S' && b[3] == 'T' && b[4] == ' ') ||
					(b[0] == 'G' && b[1] == 'E' && b[2] == 'T' && b[3] == ' ') {

					firstMatch := re.FindSubmatch(b)
					if len(firstMatch) > 1 {
						var new_b []byte
						old_h := firstMatch[1]
						new_h := []byte("\r\n" + f.fragment.Host1Header + f.fragment.Host1Domain + string(old_h) + f.fragment.Host2Header + f.fragment.Host2Domain + "\r\n")
						new_b = bytes.Replace(b, old_h, new_h, 1)
						return f.writer.Write(new_b)
					}
				}
			}
		}
		return f.writer.Write(b)
	}

	if f.fragment.PacketsFrom == 0 && f.fragment.PacketsTo == 1 {
		if f.count != 1 || len(b) <= 5 || b[0] != 22 {
			return f.writer.Write(b)
		}
		recordLen := 5 + ((int(b[3]) << 8) | int(b[4]))
		if len(b) < recordLen { // maybe already fragmented somehow
			return f.writer.Write(b)
		}
		data := b[5:recordLen]
		buf := make([]byte, 1024)
		queue := make([]byte, 2048)
		n_queue := int(randBetween(int64(2), int64(4)))
		L_queue := 0
		c_queue := 0
		for from := 0; ; {
			to := from + int(randBetween(int64(f.fragment.LengthMin), int64(f.fragment.LengthMax)))
			if to > len(data) {
				to = len(data)
			}
			l := to - from
			if 5+l > len(buff) {
				buff = make([]byte, 5+l)
			}
			copy(buff[:3], b)
			copy(buff[5:], data[from:to])
			from = to
			buf[3] = byte(l >> 8)
			buf[4] = byte(l)

			if c_queue < n_queue {
				if l > 0 {
					copy(queue[L_queue:], buf[:5+l])
					L_queue = L_queue + 5 + l
				}
				c_queue = c_queue + 1
			} else {
				if l > 0 {
					copy(queue[L_queue:], buf[:5+l])
					L_queue = L_queue + 5 + l
				}

				if L_queue > 0 {
					_, err := f.writer.Write(queue[:L_queue])
					time.Sleep(time.Duration(randBetween(int64(f.fragment.IntervalMin), int64(f.fragment.IntervalMax))) * time.Millisecond)
					if err != nil {
						return 0, err
					}
				}

				L_queue = 0
				c_queue = 0

			}

			if from == len(data) {
				if L_queue > 0 {
					_, err := f.writer.Write(queue[:L_queue])
					time.Sleep(time.Duration(randBetween(int64(f.fragment.IntervalMin), int64(f.fragment.IntervalMax))) * time.Millisecond)
					L_queue = 0
					c_queue = 0

					if err != nil {
						return 0, err
					}
				}
				if len(b) > recordLen {
					n, err := f.writer.Write(b[recordLen:])
					if err != nil {
						return recordLen + n, err
					}
				}
				return len(b), nil
			}
		}

	}

	if f.fragment.PacketsFrom != 0 && (f.count < f.fragment.PacketsFrom || f.count > f.fragment.PacketsTo) {
		return f.writer.Write(b)
	}

	for from := 0; ; {
		to := from + int(randBetween(int64(f.fragment.LengthMin), int64(f.fragment.LengthMax)))
		if to > len(b) {
			to = len(b)
		}
		n, err := f.writer.Write(b[from:to])
		from += n
		time.Sleep(time.Duration(randBetween(int64(f.fragment.IntervalMin), int64(f.fragment.IntervalMax))) * time.Millisecond)
		if err != nil {
			return from, err
		}
		if from >= len(b) {
			return from, nil
		}
	}
}

func randBetween(left int64, right int64) int64 {
	if left == right {
		return left
	}
	bigInt, _ := rand.Int(rand.Reader, big.NewInt(right-left+1))
	return left + bigInt.Int64()
}

func GenerateRandomBytes(n int64) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}
