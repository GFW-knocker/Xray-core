package jtrojan

import (
	"github.com/GFW-knocker/Xray-core/common"
	"github.com/GFW-knocker/Xray-core/common/errors"
	"github.com/GFW-knocker/Xray-core/common/protocol"
	"github.com/GFW-knocker/Xray-core/proxy/trojan"
	"github.com/google/uuid"
)

// AsAccount hands the stock trojan client its usual account, but the key starts
// with the 16 raw UUID bytes instead of the first 16 hex chars of the SHA224.
func (a *Account) AsAccount() (protocol.Account, error) {
	// strict parse on purpose, common/uuid would turn a short password into a v5 UUID
	id, err := uuid.Parse(a.Password)
	if err != nil {
		return nil, errors.New("jtrojan password must be a UUID").Base(err)
	}
	account := common.Must2((&trojan.Account{Password: a.Password}).AsAccount()).(*trojan.MemoryAccount)
	copy(account.Key, id[:])
	return account, nil
}
