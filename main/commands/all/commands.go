package all

import (
	"github.com/GFW-knocker/Xray-core/main/commands/all/api"
	"github.com/GFW-knocker/Xray-core/main/commands/all/base64"
	"github.com/GFW-knocker/Xray-core/main/commands/all/convert"
	// TODO: Restore this import and lua.CmdLua when Lua privileged signature authorization is re-enabled.
	// "github.com/GFW-knocker/Xray-core/main/commands/all/lua"
	"github.com/GFW-knocker/Xray-core/main/commands/all/tls"
	"github.com/GFW-knocker/Xray-core/main/commands/base"
)

func init() {
	base.RootCommand.Commands = append(
		base.RootCommand.Commands,
		api.CmdAPI,
		base64.CmdBase64,
		convert.CmdConvert,
		// lua.CmdLua,
		tls.CmdTLS,
		cmdUUID,
		cmdX25519,
		// cmdEd25519,
		cmdWG,
		cmdMLDSA65,
		cmdMLKEM768,
		cmdVLESSEnc,
	)
}
