package hysteria

import (
	"context"
	"time"

	"github.com/GFW-knocker/Xray-core/common"
	"github.com/GFW-knocker/Xray-core/common/buf"
	"github.com/GFW-knocker/Xray-core/common/errors"
	"github.com/GFW-knocker/Xray-core/common/log"
	"github.com/GFW-knocker/Xray-core/common/net"
	"github.com/GFW-knocker/Xray-core/common/protocol"
	"github.com/GFW-knocker/Xray-core/common/session"
	"github.com/GFW-knocker/Xray-core/core"
	"github.com/GFW-knocker/Xray-core/features/policy"
	"github.com/GFW-knocker/Xray-core/features/routing"
	"github.com/GFW-knocker/Xray-core/proxy/hysteria/account"
	"github.com/GFW-knocker/Xray-core/transport"
	"github.com/GFW-knocker/Xray-core/transport/internet"
	"github.com/GFW-knocker/Xray-core/transport/internet/hysteria"
	"github.com/GFW-knocker/Xray-core/transport/internet/stat"
)

type Server struct {
	config        *ServerConfig
	validator     *account.Validator
	policyManager policy.Manager
}

func NewServer(ctx context.Context, config *ServerConfig) (*Server, error) {
	v := core.MustFromContext(ctx)
	p := v.GetFeature(policy.ManagerType()).(policy.Manager)

	streamSettings := session.StreamSettingsFromContext(ctx).(*internet.MemoryStreamConfig)
	if _, ok := streamSettings.ProtocolSettings.(*hysteria.Config); !ok {
		return nil, errors.New("not hysteria transport")
	}

	validator := account.NewValidator()
	for _, user := range config.Users {
		u, err := user.ToMemoryUser()
		if err != nil {
			return nil, errors.New("failed to get hysteria user").Base(err).AtError()
		}

		if err := validator.Add(u); err != nil {
			return nil, errors.New("failed to add user").Base(err).AtError()
		}
	}

	return &Server{
		config:        config,
		validator:     validator,
		policyManager: p,
	}, nil
}

func (s *Server) HysteriaInboundValidator() *account.Validator {
	return s.validator
}

func (s *Server) AddUser(ctx context.Context, user *protocol.MemoryUser) error {
	return s.validator.Add(user)
}

func (s *Server) RemoveUser(ctx context.Context, email string) error {
	return s.validator.DelByEmail(email)
}

func (s *Server) GetUser(ctx context.Context, email string) *protocol.MemoryUser {
	return s.validator.GetByEmail(email)
}

func (s *Server) GetUsers(ctx context.Context) []*protocol.MemoryUser {
	return s.validator.GetAll()
}

func (s *Server) GetUsersCount(context.Context) int64 {
	return s.validator.GetCount()
}

func (s *Server) Network() []net.Network {
	return []net.Network{net.Network_TCP}
}

func (s *Server) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	inbound := session.InboundFromContext(ctx)
	inbound.Name = "hysteria"
	inbound.CanSpliceCopy = 3
	inbound.User = &protocol.MemoryUser{}

	iConn := stat.TryUnwrapStatsConn(conn)

	if v, ok := iConn.(interface{ User() *protocol.MemoryUser }); ok {
		user := v.User()
		if user != nil {
			inbound.User = user
			inbound.VlessRoute = user.Account.(*account.MemoryAccount).VR
		}
	}

	if _, ok := iConn.(*hysteria.InterConn); ok {
		reader := &UDPReader{
			reader: conn,
			df:     &Defragger{},
		}

		b := buf.New()
		b.Resize(0, buf.Size)
		n, addr, err := reader.ReadFrom(b.Bytes())
		if err != nil {
			b.Release()
			return err
		}
		b.Resize(0, int32(n))
		b.UDP = addr

		reader.firstBuf = b

		writer := &UDPWriter{
			writer: conn,
			addr:   addr.NetAddr(),
		}

		return dispatcher.DispatchLink(ctx, *addr, &transport.Link{
			Reader: reader,
			Writer: writer,
		})
	} else {
		sessionPolicy := s.policyManager.ForLevel(inbound.User.Level)

		common.Must(conn.SetReadDeadline(time.Now().Add(sessionPolicy.Timeouts.Handshake)))
		addr, err := ReadTCPRequest(conn)
		if err != nil {
			log.Record(&log.AccessMessage{
				From:   conn.RemoteAddr(),
				To:     "",
				Status: log.AccessRejected,
				Reason: err,
			})
			return errors.New("failed to create request from: ", conn.RemoteAddr()).Base(err)
		}
		common.Must(conn.SetReadDeadline(time.Time{}))

		dest, err := net.ParseDestination("tcp:" + addr)
		if err != nil {
			return err
		}
		ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
			From:   conn.RemoteAddr(),
			To:     dest,
			Status: log.AccessAccepted,
			Reason: "",
			Email:  inbound.User.Email,
		})
		errors.LogInfo(ctx, "tunnelling request to ", dest)

		bufferedWriter := buf.NewBufferedWriter(buf.NewWriter(conn))
		err = WriteTCPResponse(bufferedWriter, true, "")
		if err != nil {
			return errors.New("failed to write response").Base(err)
		}
		if err := bufferedWriter.SetBuffered(false); err != nil {
			return err
		}

		return dispatcher.DispatchLink(ctx, dest, &transport.Link{
			Reader: buf.NewReader(conn),
			Writer: bufferedWriter,
		})
	}
}

func init() {
	common.Must(common.RegisterConfig((*ServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewServer(ctx, config.(*ServerConfig))
	}))
}
