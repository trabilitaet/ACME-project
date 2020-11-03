package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

func sign(byteSlice []byte) (signature string) {
	hashed := sha256.Sum256(byteSlice)

	rng := rand.Reader
	sign, err := privKey.Sign(rng, hashed[:], crypto.SHA256)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from signing: %s\n", err)
		return
	}
	signature = base64.RawURLEncoding.EncodeToString(sign)
	return signature
}

func getNonce() (nonce string) {
	resp, err := http.Head(NONCE_URL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting nonce: %s\n", err)
		return
	}
	nonce = resp.Header.Get("Replay-Nonce")
	return nonce
}

func createAccount(nonce string) (newNonce string, kid string) {
	protected := getProtectedHeaderJWK(nonce)
	payload := base64.RawURLEncoding.EncodeToString([]byte("{\"termsOfServiceAgreed\": true}"))

	request := message{
		Payload:   payload,
		Protected: protected,
		Signature: sign([]byte(protected + "." + payload)),
	}
	reqJSON, _ := json.Marshal(request)
	resp, _ := http.Post(NEW_ACC_URL, "application/jose+json", bytes.NewReader(reqJSON))
	newNonce = resp.Header.Get("Replay-Nonce")
	kid = resp.Header.Get("Location")
	return newNonce, kid
}

func requestCert(nonce string, kid string) (newNonce string, orderURL string) {
	protected := getProtectedHeaderKID(nonce, kid, ORDER_URL)

	var IDS identifiers
	for _, dom := range opts.DOMAIN {
		ID := identifier{
			Type: "dns",
			Val:  dom,
		}
		IDS.IDs = append(IDS.IDs, ID)
	}

	IDJSON, _ := json.Marshal(IDS)
	payload := base64.RawURLEncoding.EncodeToString(IDJSON)

	request := message{
		Payload:   payload,
		Protected: protected,
		Signature: sign([]byte(protected + "." + payload)),
	}
	reqJSON, _ := json.Marshal(request)
	resp, _ := http.Post(ORDER_URL, "application/jose+json", bytes.NewReader(reqJSON))
	newNonce = resp.Header.Get("Replay-Nonce")
	orderURL = resp.Header.Get("Location")
	return newNonce, orderURL
}

func getChallenges(nonce string, kid string, orderURL string) (newNonce string, chall challenge) {
	protected := getProtectedHeaderKID(nonce, kid, orderURL)
	payload := base64.RawURLEncoding.EncodeToString([]byte(""))
	request := message{
		Payload:   payload,
		Protected: protected,
		Signature: sign([]byte(protected + "." + payload)),
	}
	reqJSON, _ := json.Marshal(request)
	resp, _ := http.Post(orderURL, "application/jose+json", bytes.NewReader(reqJSON))
	nonce = resp.Header.Get("Replay-Nonce")

	body, _ := ioutil.ReadAll(resp.Body)
	orders := order{}
	json.Unmarshal(body, &orders)

	auth := orders.Authorizations[0]

	protected = getProtectedHeaderKID(nonce, kid, auth)
	payload = base64.RawURLEncoding.EncodeToString([]byte(""))
	request = message{
		Payload:   payload,
		Protected: protected,
		Signature: sign([]byte(protected + "." + payload)),
	}
	reqJSON, _ = json.Marshal(request)
	resp, _ = http.Post(auth, "application/jose+json", bytes.NewReader(reqJSON))
	newNonce = resp.Header.Get("Replay-Nonce")

	body, _ = ioutil.ReadAll(resp.Body)
	authorization := authorization{}
	json.Unmarshal(body, &authorization)

	for _, c := range authorization.Challenges[:] {
		if c.Type == "dns-01" && opts.PosArgs.CHALLENGE == "dns01" {
			chall = c
		}
		if c.Type == "http-01" && opts.PosArgs.CHALLENGE == "http01" {
			chall = c
		}
	}
	return newNonce, chall
}

func craftKeyAuth(token string) (keyAuth []string) {
	e := byteBufferFromUInt(uint64(privKey.PublicKey.E)).base64URL()
	n := base64.RawURLEncoding.EncodeToString(privKey.PublicKey.N.Bytes())

	JWK := jwkPubKey{ // replace with interface
		E:   e,
		Kty: "RSA", // key type (RSA, EC,...)
		N:   n,
	}

	jwkJSON, _ := json.Marshal(JWK)
	hash := sha256.Sum256(jwkJSON)

	print := base64.RawURLEncoding.EncodeToString(hash[:])
	token = token + "." + print
	keyAuth = append(keyAuth, token)
	return keyAuth
}
