package main

type message struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type identifiers struct {
	IDs []identifier `json:"identifiers"`
}

type identifier struct {
	Type string `json:"type"`
	Val  string `json:"value"`
}

type order struct {
	Status         string      `json:"status"`
	Expires        string      `json:"expires"`
	Identifiers    identifiers `json:"identifiers"`
	Finalize       string      `json:"finalize"`       // url
	Authorizations []string    `json:"authorizations"` //urls
	Certificate    string      `json:"certificate"`
}

type challenge struct {
	Type   string `json:"type"`
	URL    string `json:"url"`
	Token  string `json:"token"`
	Status string `json:"status"`
}

type authorization struct {
	Status     string      `json:"status"`
	Identifier identifier  `json:"identifier"`
	Challenges []challenge `json:"challenges"`
	Expires    string      `json:"identifier"`
}

type jwkPubKey struct {
	E   string `json:"e"`   // public exponent (from public key)
	Kty string `json:"kty"` // key type (RSA, EC,...)
	N   string `json:"n"`   // modulus (from public key)
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

type CSRencoded struct {
	CSR64 string `json:"csr"`
}

type DIR struct {
	KeyChange  string `json:"keyChange"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
	NewNonce   string `json:"newNonce"`
	RevokeCert string `json:"revokeCert"`
	Meta       string `json:"meta"`
}
