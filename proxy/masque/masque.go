package masque

import (
	"context"

	"github.com/GFW-knocker/Xray-core/common"
)

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewClient(ctx, config.(*Config))
	}))
}
