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

const DIR_URL = "localhost"
const NEW_ACC_URL = "https://" + DIR_URL + ":14000/sign-me-up"
const NONCE_URL = "https://" + DIR_URL + ":14000/nonce-plz"
const ORDER_URL = "https://" + DIR_URL + ":14000/order-plz"
const CHALL_URL = "https://" + DIR_URL + ":14000/order-plz" //????

var DOMAINS []string
var privKey *rsa.PrivateKey

func init() {
	pemKey, _ := ioutil.ReadFile("data/acme-key")
	block, _ := pem.Decode([]byte(pemKey))
	privKey, _ = x509.ParsePKCS1PrivateKey(block.Bytes)
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	DOMAINS = append(DOMAINS, "netsec.ethz.ch")
	DOMAINS = append(DOMAINS, "syssec.ethz.ch")
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
	fmt.Println(resp)
	fmt.Println("-------------------------------------")
	return newNonce, kid
}

func requestCert(nonce string, kid string) (newNonce string, orderID string) {
	protected := getProtectedHeaderKID(nonce, kid)

	var IDS identifiers
	for _, dom := range DOMAINS {
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
	// fmt.Println(string(reqJSON))
	resp, _ := http.Post(ORDER_URL, "application/jose+json", bytes.NewReader(reqJSON))
	newNonce = resp.Header.Get("Replay-Nonce")
	orderID = resp.Header.Get("Location")
	fmt.Println(resp)
	return newNonce, orderID
}

// func challengeReady() {
// 	resp, _ := http.Post(CHALL_URL, "application/jose+json", bytes.NewReader(reqJSON))
// }

func main() {
	nonce := getNonce()
	nonce, kid := createAccount(nonce)
	nonce, orderURL := requestCert(nonce, kid)
	resp, err := http.Get(orderURL)
	fmt.Println(resp, "\n", err)
	// resp, err = http.Post(orderURL, "application/jose+json", bytes.NewReader([]byte("{}")))
	// fmt.Println(resp, "\n", err)

	//COMPLETE CHALLENGE--------------------------------------
	// The client indicates to the server that it is ready for the challenge
	//   validation by sending an empty JSON body ("{}") carried in a POST
	//   request to the challenge URL (not the authorization URL).
	// POST /acme/chall/prV_B7yEyA4 HTTP/1.1
	//   Host: example.com
	//   Content-Type: application/jose+json

	//   {
	//     "protected": base64url({
	//       "alg": "ES256",
	//       "kid": "https://example.com/acme/acct/evOfKhNU60wg",
	//       "nonce": "Q_s3MWoqT05TrdkM2MTDcw",
	//       "url": "https://example.com/acme/chall/prV_B7yEyA4"
	//     }),
	//     "payload": base64url({}),
	//     "signature": "9cbg5JO1Gf5YLjjz...SpkUfcdPai9uVYYQ"
	//   }

	//create(?)/SUBMIT CSR-------------------------------------
	// crypto/x509
	//  func CreateCertificateRequest
	// POST /acme/order/TOlocE8rfgo/finalize

	//DOWNLOAD CERTIFICATE-------------------------------------
	// sends a POST-as-GET request to the certificate URL
	// POST /acme/cert/mAt3xBGaobw HTTP/1.1
	//   Host: example.com
	//   Content-Type: application/jose+json
	//   Accept: application/pem-certificate-chain

	//   {
	//     "protected": base64url({
	//       "alg": "ES256",
	//       "kid": "https://example.com/acme/acct/evOfKhNU60wg",
	//       "nonce": "uQpSjlRb4vQVCjVYAyyUWg",
	//       "url": "https://example.com/acme/cert/mAt3xBGaobw"
	//     }),
	//     "payload": "",
	//     "signature": "nuSDISbWG8mMgE7H...QyVUL68yzf3Zawps"
	//   } -> answer is certificate chain

	//START HTTPS SERVER--------------------------------------
	// go servHttps()
}
