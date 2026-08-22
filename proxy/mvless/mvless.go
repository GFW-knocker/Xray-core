// Package mvless contains the implementation of MVLess protocol and transportation.
//
// MVLess contains both inbound and outbound connections. MVLess inbound is usually used on servers
// together with 'freedom' to talk to final destination, while MVLess outbound is usually used on
// clients with 'socks' for proxying.
package mvless

const (
	None = "none"
	XRV  = "xtls-rprx-vision"
)
