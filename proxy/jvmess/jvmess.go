// Package jvmess contains an outbound-only variant of the VMess protocol.
//
// It is isolated from the vmess package. The request header is sealed with the
// raw account id in place of the time-based authID, see aead.SealHeader.
package jvmess
