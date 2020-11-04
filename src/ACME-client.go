package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
)

var NEW_ACC_URL string
var NONCE_URL string
var ORDER_URL string
var ACME_DIR string

var privKey *rsa.PrivateKey

func init() {
	pemKey, _ := ioutil.ReadFile("data/acme-key")
	block, _ := pem.Decode([]byte(pemKey))
	privKey, _ = x509.ParsePKCS1PrivateKey(block.Bytes)
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	NEW_ACC_URL = "https://" + opts.DIR_URL + ":14000/sign-me-up"
	NONCE_URL = "https://" + opts.DIR_URL + ":14000/nonce-plz"
	ORDER_URL = "https://" + opts.DIR_URL + ":14000/order-plz"
	ACME_DIR = "https://" + opts.DIR_URL + ":14000/dir"
}

func getCertificate() {
	nonce := getNonce()
	nonce, kid := createAccount(nonce)
	nonce, orderURL := requestCert(nonce, kid)
	nonce, chall := getChallenges(nonce, kid, orderURL)

	if opts.PosArgs.CHALLENGE == "http01" {
		go HTTPChall(chall.URL, chall.Token)
	}
	if opts.PosArgs.CHALLENGE == "dns01" {
		go DNSChall(chall.Token)
	}
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
