package aead

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"

	"github.com/GFW-knocker/Xray-core/common"
	"github.com/GFW-knocker/Xray-core/common/crypto"
)

// SealHeader seals the request header like the stock AEAD layout, except the
// key itself takes the place of the authID: there is no time-based auth value.
func SealHeader(key [16]byte, data []byte) []byte {
	auth := key

	connectionNonce := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, connectionNonce); err != nil {
		panic(err.Error())
	}

	aeadPayloadLengthSerializeBuffer := bytes.NewBuffer(nil)

	headerPayloadDataLen := uint16(len(data))

	common.Must(binary.Write(aeadPayloadLengthSerializeBuffer, binary.BigEndian, headerPayloadDataLen))

	aeadPayloadLengthSerializedByte := aeadPayloadLengthSerializeBuffer.Bytes()
	var payloadHeaderLengthAEADEncrypted []byte

	{
		payloadHeaderLengthAEADKey := KDF16(key[:], KDFSaltConstVMessHeaderPayloadLengthAEADKey, string(auth[:]), string(connectionNonce))

		payloadHeaderLengthAEADNonce := KDF(key[:], KDFSaltConstVMessHeaderPayloadLengthAEADIV, string(auth[:]), string(connectionNonce))[:12]

		payloadHeaderAEAD := crypto.NewAesGcm(payloadHeaderLengthAEADKey)

		payloadHeaderLengthAEADEncrypted = payloadHeaderAEAD.Seal(nil, payloadHeaderLengthAEADNonce, aeadPayloadLengthSerializedByte, auth[:])
	}

	var payloadHeaderAEADEncrypted []byte

	{
		payloadHeaderAEADKey := KDF16(key[:], KDFSaltConstVMessHeaderPayloadAEADKey, string(auth[:]), string(connectionNonce))

		payloadHeaderAEADNonce := KDF(key[:], KDFSaltConstVMessHeaderPayloadAEADIV, string(auth[:]), string(connectionNonce))[:12]

		payloadHeaderAEAD := crypto.NewAesGcm(payloadHeaderAEADKey)

		payloadHeaderAEADEncrypted = payloadHeaderAEAD.Seal(nil, payloadHeaderAEADNonce, data, auth[:])
	}

	outputBuffer := bytes.NewBuffer(nil)

	common.Must2(outputBuffer.Write(auth[:]))                          // 16
	common.Must2(outputBuffer.Write(payloadHeaderLengthAEADEncrypted)) // 2+16
	common.Must2(outputBuffer.Write(connectionNonce))                  // 8
	common.Must2(outputBuffer.Write(payloadHeaderAEADEncrypted))

	return outputBuffer.Bytes()
}
