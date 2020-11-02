package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

var NEW_ACC_URL string
var NONCE_URL string
var ORDER_URL string
var privKey *rsa.PrivateKey

func init() {
	pemKey, _ := ioutil.ReadFile("data/acme-key")
	block, _ := pem.Decode([]byte(pemKey))
	privKey, _ = x509.ParsePKCS1PrivateKey(block.Bytes)
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	NEW_ACC_URL = "https://" + opts.DIR_URL + ":14000/sign-me-up"
	NONCE_URL = "https://" + opts.DIR_URL + ":14000/nonce-plz"
	ORDER_URL = "https://" + opts.DIR_URL + ":14000/order-plz"
}

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

func requestCert(nonce string, kid string) (newNonce string, orderID string) {
	protected := getProtectedHeaderKID(nonce, kid)

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
	orderID = resp.Header.Get("Location")
	return newNonce, orderID
}

func getCertificate() {
	nonce := getNonce()
	nonce, kid := createAccount(nonce)
	nonce, orderID := requestCert(nonce, kid)

	fmt.Println(nonce)
	fmt.Println(orderID)

	//complete challenge

	//create(?)/submit CSR

	//download certificate

	//start https server
	// go servHttps()
}
