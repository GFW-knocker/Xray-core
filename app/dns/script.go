package dns

import (
	"time"

	"github.com/GFW-knocker/Xray-core/common/errors"
	"github.com/GFW-knocker/Xray-core/common/geodata"
	"github.com/GFW-knocker/Xray-core/common/log"
	xlua "github.com/GFW-knocker/Xray-core/common/lua"
	"github.com/GFW-knocker/Xray-core/common/net"
	"github.com/GFW-knocker/Xray-core/features/dns"
	lua "github.com/yuin/gopher-lua"
)

const scriptExecutionTimeout = 6 * time.Second

type scriptEngine struct {
	program *xlua.Program
	pool    *xlua.Pool
}

func newScriptEngine(script string) (*scriptEngine, error) {
	program, err := xlua.Compile(script)
	if err != nil {
		return nil, err
	}
	return &scriptEngine{program: program}, nil
}

func (e *scriptEngine) start(server *DNS) error {
	pool, err := xlua.NewPool(server.ctx, scriptExecutionTimeout, e.program.NewStateFactory(
		scriptExecutionTimeout*20,
		256,
		func(L *lua.LState) {
			geodata.RegisterLua(L)
			log.RegisterLua(L)
			server.registerLua(L)
		},
		func(L *lua.LState) error {
			if L.GetGlobal("HandleDNSQuery").Type() != lua.LTFunction {
				return errors.New("DNS script must define HandleDNSQuery(...)")
			}
			return nil
		}))
	if err != nil {
		return err
	}

	e.pool = pool
	errors.LogInfo(server.ctx, "DNS script initialized")
	return nil
}

func (e *scriptEngine) close() {
	if e.pool != nil {
		e.pool.Close()
	}
}

func (e *scriptEngine) query(domain string, option dns.IPOption) (ips []net.IP, ttl uint32, queryErr error) {
	if err := e.pool.WithState(nil, 0, func(L *lua.LState) error {
		if err := callLuaQuery(L, domain, option); err != nil {
			return err
		}
		ips, ttl, queryErr = readLuaQueryResult(L)
		return nil
	}); err != nil {
		return nil, 0, err
	}
	return ips, ttl, queryErr
}
