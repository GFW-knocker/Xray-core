package conf

import (
	"encoding/json"

	"github.com/GFW-knocker/Xray-core/common/errors"
	"github.com/GFW-knocker/Xray-core/common/protocol"
	"github.com/GFW-knocker/Xray-core/common/serial"
	"github.com/GFW-knocker/Xray-core/common/uuid"
	"github.com/GFW-knocker/Xray-core/proxy/jvmess/outbound"
	"google.golang.org/protobuf/proto"
)

type JVMessOutboundConfig struct {
	Address     *Address               `json:"address"`
	Port        uint16                 `json:"port"`
	Level       uint32                 `json:"level"`
	Email       string                 `json:"email"`
	ID          string                 `json:"id"`
	Security    string                 `json:"security"`
	Experiments string                 `json:"experiments"`
	Receivers   []*VMessOutboundTarget `json:"vnext"`
}

// Build implements Buildable
func (c *JVMessOutboundConfig) Build() (proto.Message, error) {
	config := new(outbound.Config)
	if c.Address != nil {
		c.Receivers = []*VMessOutboundTarget{
			{
				Address: c.Address,
				Port:    c.Port,
				Users:   []json.RawMessage{{}},
			},
		}
	}
	if len(c.Receivers) != 1 {
		return nil, errors.New(`JVMess settings: "vnext" should have one and only one member. Multiple endpoints in "vnext" should use multiple JVMess outbounds and routing balancer instead`)
	}
	for _, rec := range c.Receivers {
		if len(rec.Users) != 1 {
			return nil, errors.New(`JVMess vnext: "users" should have one and only one member. Multiple members in "users" should use multiple JVMess outbounds and routing balancer instead`)
		}
		if rec.Address == nil {
			return nil, errors.New(`JVMess vnext: "address" is not set`)
		}
		spec := &protocol.ServerEndpoint{
			Address: rec.Address.Build(),
			Port:    uint32(rec.Port),
		}
		for _, rawUser := range rec.Users {
			user := new(protocol.User)
			if c.Address != nil {
				user.Level = c.Level
				user.Email = c.Email
			} else {
				if err := json.Unmarshal(rawUser, user); err != nil {
					return nil, errors.New("invalid JVMess user").Base(err)
				}
			}
			account := new(VMessAccount)
			if c.Address != nil {
				account.ID = c.ID
				account.Security = c.Security
				account.Experiments = c.Experiments
			} else {
				if err := json.Unmarshal(rawUser, account); err != nil {
					return nil, errors.New("invalid JVMess user").Base(err)
				}
			}

			u, err := uuid.ParseString(account.ID)
			if err != nil {
				return nil, err
			}
			account.ID = u.String()

			user.Account = serial.ToTypedMessage(account.Build())
			spec.User = user
			break
		}
		config.Receiver = spec
		break
	}
	return config, nil
}
