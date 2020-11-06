package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
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

func postAsGet(nonce string, URL string, payload []byte, kid string) (newNonce string, location string, body []byte) {
	var protected64 string
	if kid == "" {
		fmt.Println("No kid, constructing JWK")
		protected64 = getProtectedHeaderJWK(nonce, URL)
	} else {
		protected64 = getProtectedHeaderKID(nonce, kid, URL)
	}
	payload64 := base64.RawURLEncoding.EncodeToString(payload)

	request := message{
		Payload:   payload64,
		Protected: protected64,
		Signature: sign([]byte(protected64 + "." + payload64)),
	}
	reqJSON, _ := json.Marshal(request)
	fmt.Println("POST: ", string(reqJSON))
	resp, err := http.Post(URL, "application/jose+json", bytes.NewReader(reqJSON))
	if err != nil {
		fmt.Println("ERROR posting to: ", URL)
		fmt.Println(err)
		body, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Println("Body:--------------------------")
			fmt.Println(string(body))
			return newNonce, location, []byte("")
		}
		return
	}
	newNonce = resp.Header.Get("Replay-Nonce")
	location = resp.Header.Get("Location")
	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return newNonce, location, []byte("")
	}

	return newNonce, location, body
}

func createAccount(nonce string) (newNonce string, kid string) {
	payload := []byte("{\"termsOfServiceAgreed\": true}")
	newNonce, location, _ := postAsGet(nonce, NEW_ACC_URL, payload, "")
	return newNonce, location
}

func requestCert(nonce string, kid string) (newNonce string, orderURL string) {
	var IDS identifiers
	for _, dom := range opts.DOMAIN {
		ID := identifier{
			Type: "dns",
			Val:  dom,
		}
		IDS.IDs = append(IDS.IDs, ID)
	}
	IDJSON, _ := json.Marshal(IDS)
	newNonce, location, _ := postAsGet(nonce, ORDER_URL, IDJSON, kid)
	return newNonce, location
}

func getChallenges(nonce string, kid string, orderURL string) (newNonce string, fin string) {
	newNonce, _, ordersJSON := postAsGet(nonce, orderURL, []byte(""), kid)

	orders := order{}
	json.Unmarshal(ordersJSON, &orders)
	fmt.Println("Orders:")
	// fmt.Println(orders)

	for index, _ := range orders.Authorizations {
		var authJSON []byte
		newNonce, _, authJSON = postAsGet(newNonce, orders.Authorizations[index], []byte(""), kid)

		authorization := authorization{}
		json.Unmarshal(authJSON, &authorization)
		fmt.Printf("Challenges for auth %v\n", index)
		// fmt.Println(authorization) //print all challenges

		//select appropriate challenge
		for _, c := range authorization.Challenges[:] {
			if c.Type == "dns-01" && opts.PosArgs.CHALLENGE == "dns01" {
				challenges = append(challenges, c)
			}
			if c.Type == "http-01" && opts.PosArgs.CHALLENGE == "http01" {
				challenges = append(challenges, c)
			}
		}
		fmt.Println(challenges)
	}
	return newNonce, orders.Finalize
}

func doChallenge(nonce string, c challenge, kid string) (newNonce string) {
	// check challenge status
	// fmt.Println("Challenge Status: ", chall.Status)
	fmt.Println("Challenge Status: ", c)
	// if not done, do challenge
	if c.Type == "dns-01" {
		// get current challenge
		DNSChall(c.Token)
		time.Sleep(5 * time.Second)
		var body []byte
		newNonce, _, body = postAsGet(nonce, c.URL, []byte("{}"), kid)
		fmt.Println("RESPONSE:\n", string(body))
	} else {
		HTTPChall(c.Token)
		//wait until http server started
		time.Sleep(5 * time.Second)
		//start challenge
		var body []byte
		newNonce, _, body = postAsGet(nonce, c.URL, []byte("{}"), kid)
		fmt.Println("RESPONSE:\n", string(body))
	}
	return newNonce
}

func craftKeyAuth(token string) (keyAuth string) {
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
	keyAuth = token + "." + print
	return keyAuth
}

func sendCSR(nonce string, kid string, finalize string) (newNonce string) {
	template := x509.CertificateRequest{
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKeyAlgorithm: x509.RSA,
		PublicKey:          privKey.PublicKey,
		Subject: pkix.Name{
			CommonName:         opts.DOMAIN[0],
			Country:            []string{"CH"},
			Organization:       []string{"project"},
			OrganizationalUnit: []string{"acme"},
			Locality:           []string{"ZH"},
			Province:           []string{"ZH"},
		},
		DNSNames: opts.DOMAIN,
	}

	//create DER encoded CSR
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &template, privKey)
	// pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})

	csrJSON, _ := json.Marshal(CSRencoded{csr})
	fmt.Println(string(csrJSON))
	csr64 := base64.RawURLEncoding.EncodeToString(csrJSON)
	fmt.Println(csr64)
	newNonce, _, body := postAsGet(nonce, finalize, []byte(csr64), kid)
	fmt.Println(string(body))
	return newNonce
}
