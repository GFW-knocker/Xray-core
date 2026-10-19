package router

import (
	"time"

	"github.com/GFW-knocker/Xray-core/app/dns"
	"github.com/GFW-knocker/Xray-core/common"
	"github.com/GFW-knocker/Xray-core/common/errors"
	"github.com/GFW-knocker/Xray-core/common/geodata"
	"github.com/GFW-knocker/Xray-core/common/log"
	xlua "github.com/GFW-knocker/Xray-core/common/lua"
	"github.com/GFW-knocker/Xray-core/features/routing"
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

func (e *scriptEngine) start(router *Router) error {
	pool, err := xlua.NewPool(router.ctx, scriptExecutionTimeout, e.program.NewStateFactory(
		scriptExecutionTimeout*20,
		256,
		func(L *lua.LState) {
			geodata.RegisterLua(L)
			log.RegisterLua(L)
			router.RegisterLua(L)
			dns.RegisterLua(L, router.dns)
		},
		func(L *lua.LState) error {
			if L.GetGlobal("HandleRoute").Type() != lua.LTFunction {
				return errors.New("routing script must define HandleRoute(...)")
			}
			return nil
		}))
	if err != nil {
		return err
	}

	e.pool = pool
	errors.LogInfo(router.ctx, "routing script initialized")
	return nil
}

func (e *scriptEngine) close() {
	if e.pool != nil {
		e.pool.Close()
	}
}

func (e *scriptEngine) pickRoute(ctx routing.Context) (routing.Route, error) {
	var outboundTag, ruleTag string
	var routeErr error

	if err := e.pool.WithState(nil, 0, func(L *lua.LState) error {
		if err := callLuaRoute(L, ctx); err != nil {
			return err
		}
		outboundTag, ruleTag, routeErr = readLuaRouteResult(L)
		return nil
	}); err != nil {
		return nil, err
	}

	if routeErr != nil {
		return nil, routeErr
	}
	if outboundTag == "" {
		return nil, common.ErrNoClue
	}

	return &Route{Context: ctx, outboundTag: outboundTag, ruleTag: ruleTag}, nil
}
