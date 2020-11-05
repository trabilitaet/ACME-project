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
	"time"
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
	protected := getProtectedHeaderJWK(nonce, NEW_ACC_URL)
	payload := base64.RawURLEncoding.EncodeToString([]byte("{\"termsOfServiceAgreed\": true}"))

	request := message{
		Payload:   payload,
		Protected: protected,
		Signature: sign([]byte(protected + "." + payload)),
	}
	reqJSON, _ := json.Marshal(request)
	resp, err := http.Post(NEW_ACC_URL, "application/jose+json", bytes.NewReader(reqJSON))
	if err != nil {
		fmt.Println("ERROR creating account")
		fmt.Println(err)
		return
	}
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
	resp, err := http.Post(ORDER_URL, "application/jose+json", bytes.NewReader(reqJSON))
	if err != nil {
		fmt.Println("ERROR posting order")
		fmt.Println(err)
		body, _ := ioutil.ReadAll(resp.Body)
		fmt.Println("Body:")
		fmt.Println(string(body))
		return
	}
	newNonce = resp.Header.Get("Replay-Nonce")
	orderURL = resp.Header.Get("Location")
	return newNonce, orderURL
}

func doChallenges(nonce string, kid string, orderURL string) (newNonce string, fin string) {
	protected := getProtectedHeaderKID(nonce, kid, orderURL)
	payload := base64.RawURLEncoding.EncodeToString([]byte(""))
	request := message{
		Payload:   payload,
		Protected: protected,
		Signature: sign([]byte(protected + "." + payload)),
	}
	reqJSON, _ := json.Marshal(request)
	resp, err := http.Post(orderURL, "application/jose+json", bytes.NewReader(reqJSON))
	if err != nil {
		fmt.Println("ERROR getting order")
		fmt.Println("from: ", orderURL)
		fmt.Println(err)
		return
	}
	nonce = resp.Header.Get("Replay-Nonce")

	body, _ := ioutil.ReadAll(resp.Body)
	orders := order{}
	json.Unmarshal(body, &orders)
	fmt.Println("Orders:")
	fmt.Println(string(body))

	var Tokens []string
	var URLs []string
	for index, _ := range orders.Authorizations {

		auth := orders.Authorizations[index]

		protected = getProtectedHeaderKID(nonce, kid, auth)
		payload = base64.RawURLEncoding.EncodeToString([]byte(""))
		request = message{
			Payload:   payload,
			Protected: protected,
			Signature: sign([]byte(protected + "." + payload)),
		}
		reqJSON, _ = json.Marshal(request)
		resp, err = http.Post(auth, "application/jose+json", bytes.NewReader(reqJSON))
		if err != nil {
			fmt.Println("ERROR getting auth")
			fmt.Println(err)
			return
		}
		nonce = resp.Header.Get("Replay-Nonce")

		body, _ = ioutil.ReadAll(resp.Body)
		authorization := authorization{}
		json.Unmarshal(body, &authorization)
		fmt.Printf("Challenges for auth %v", index)
		fmt.Println(string(body))

		//select appropriate challenge

		if opts.PosArgs.CHALLENGE == "dns01" {
			for _, c := range authorization.Challenges[:] {
				if c.Type == "dns-01" {
					Tokens = append(Tokens, c.Token)
				}
			}
			DNSChall(Tokens)
		}
		if opts.PosArgs.CHALLENGE == "http01" {
			for _, c := range authorization.Challenges[:] {
				if c.Type == "http-01" {
					Tokens = append(Tokens, c.Token)
					URLs = append(URLs, c.URL)
				}
			}
		}

	}
	go HTTPChall(URLs, Tokens)
	time.Sleep(3 * time.Second)
	return resp.Header.Get("Replay-Nonce"), orders.Finalize
}

func craftKeyAuth(token string) (keyAuth []string) {
	e := byteBufferFromUInt(uint64(privKey.PublicKey.E)).base64URL()
	n := base64.RawURLEncoding.EncodeToString(privKey.PublicKey.N.Bytes())

	JWK := jwkPubKey{
		E:   e,
		Kty: "RSA",
		N:   n,
	}

	jwkJSON, _ := json.Marshal(JWK)
	hash := sha256.Sum256(jwkJSON)

	print := base64.RawURLEncoding.EncodeToString(hash[:])
	token = token + "." + print
	keyAuth = append(keyAuth, token)
	return keyAuth
}
