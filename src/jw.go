package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
)

func byteBufferFromUInt(num uint64) *byteBuffer {
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, num)
	if data == nil {
		return nil
	}
	return &byteBuffer{
		data: bytes.TrimLeft(data, "\x00"),
	}
}

func (b *byteBuffer) base64URL() string {
	code := base64.RawURLEncoding.EncodeToString(b.data)
	return code
}

func getProtectedHeaderJWK(nonce string, url string) string {
	e := byteBufferFromUInt(uint64(privKey.PublicKey.E)).base64URL()
	n := base64.RawURLEncoding.EncodeToString(privKey.PublicKey.N.Bytes())

	jwsHeaderJSON, _ := json.Marshal(protectedHeaderJWK{
		Alg: "RS256",
		Jwk: jwkPubKey{ // replace with interface
			Kty: "RSA", // key type (RSA, EC,...)
			N:   n,
			E:   e,
		},
		Nonce: nonce,
		URL:   url,
	})

	protected := base64.RawURLEncoding.EncodeToString(jwsHeaderJSON)
	return protected
}

func getProtectedHeaderKID(nonce string, kid string, URL string) string {
	jwsHeaderJSON, _ := json.Marshal(protectedHeaderKID{
		Alg:   "RS256",
		Kid:   kid,
		Nonce: nonce,
		URL:   URL,
	})

	protected := base64.RawURLEncoding.EncodeToString(jwsHeaderJSON)
	return protected
}
