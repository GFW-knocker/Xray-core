//go:build !linux

package wireguard

import (
	"errors"
	"net/netip"

	"github.com/GFW-knocker/wireguard/tun"
)

func createKernelTun([]netip.Addr, []netip.Addr, int) (tdev tun.Device, tnet *Net, err error) {
	return nil, nil, errors.New("not implemented")
}

func KernelTunSupported() (bool, error) {
	return false, nil
}
