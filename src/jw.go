package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
)

type jwkPubKey struct {
	Kty string `json:"kty"` // key type (RSA, EC,...)
	N   string `json:"n"`   // modulus (from public key)
	E   string `json:"e"`   // public exponent (from public key)
}

type protectedHeaderJWK struct {
	Alg   string    `json:"alg"`
	Jwk   jwkPubKey `json:"jwk"`
	Nonce string    `json:"nonce"`
	URL   string    `json:"url"`
}

type protectedHeaderKID struct {
	Alg   string `json:"alg"`
	Kid   string `json:"kid"`
	Nonce string `json:"nonce"`
	URL   string `json:"url"`
}

type byteBuffer struct {
	data []byte
}

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

func getProtectedHeaderJWK(nonce string) string {
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
		URL:   NEW_ACC_URL,
	})

	protected := base64.RawURLEncoding.EncodeToString(jwsHeaderJSON)
	return protected
}

func getProtectedHeaderKID(nonce string, kid string) string {
	jwsHeaderJSON, _ := json.Marshal(protectedHeaderKID{
		Alg:   "RS256",
		Kid:   kid,
		Nonce: nonce,
		URL:   ORDER_URL,
	})

	protected := base64.RawURLEncoding.EncodeToString(jwsHeaderJSON)
	return protected
}
