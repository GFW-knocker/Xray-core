//go:build wasm || openbsd
// +build wasm openbsd

package buf

import (
	"io"
	"syscall"

	"github.com/GFW-knocker/Xray-core/features/stats"
)

func useReadV() bool {
	return false
}

func NewReadVReader(reader io.Reader, rawConn syscall.RawConn, counter stats.Counter) Reader {
	panic("not implemented")
}
