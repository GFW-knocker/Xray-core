// Package crypto provides common crypto libraries for Xray.
package crypto // import "github.com/GFW-knocker/Xray-core/common/crypto"

import (
	"crypto/rand"
	"math/big"

	"github.com/GFW-knocker/Xray-core/common"
)

// [,)
func RandBetween(from int64, to int64) int64 {
	if from > to {
		from, to = to, from
	}
	if d := to - from; d == 0 || d == 1 {
		return from
	}
	bigInt, _ := rand.Int(rand.Reader, big.NewInt(to-from))
	return from + bigInt.Int64()
}

// [,]
func RandBytesBetween(b []byte, from, to byte) {
	common.Must2(rand.Read(b))

	if from > to {
		from, to = to, from
	}

	if to-from == 255 {
		return
	}

	for i := range b {
		b[i] = from + b[i]%(to-from+1)
	}
}
