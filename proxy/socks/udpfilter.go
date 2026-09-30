package socks

import (
	"net"
	"sync"
)

// MahsaNG: restored from before "Socks5 server: More standard UDP ASSOCIATE
// (RFC 1928) (#6149)", together with UDP on the inbound's own port (see
// Server.Network). Android's badvpn tun2socks "--enable-udprelay" sends
// SOCKS5-UDP datagrams straight to the SOCKS port without any UDP ASSOCIATE,
// so without that port every app's UDP (DNS first of all) was dropped.
//
// With password auth, that port only takes datagrams from an IP that has
// completed an authenticated UDP ASSOCIATE; anything else is dropped. As
// before, entries do not expire.

type UDPFilter struct {
	ips sync.Map
}

func (f *UDPFilter) Add(addr net.Addr) bool {
	ip, _, _ := net.SplitHostPort(addr.String())
	f.ips.Store(ip, true)
	return true
}

func (f *UDPFilter) Check(addr net.Addr) bool {
	ip, _, _ := net.SplitHostPort(addr.String())
	_, ok := f.ips.Load(ip)
	return ok
}
