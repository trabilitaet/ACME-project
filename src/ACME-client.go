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
var challenges []challenge

func init() {
	pemData, _ := ioutil.ReadFile("data/acme-key")
	block, _ := pem.Decode([]byte(pemData))
	privKey, _ = x509.ParsePKCS1PrivateKey(block.Bytes)
	// http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	pemData, _ = ioutil.ReadFile("project/pebble.minica.pem")
	block, _ = pem.Decode([]byte(pemData))
	pebbleCert, _ := x509.ParseCertificate(block.Bytes)
	certpool := x509.NewCertPool()
	certpool.AddCert(pebbleCert)
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: certpool, ServerName: "pebble"}

	NEW_ACC_URL = "https://" + opts.DIR_URL + ":14000/sign-me-up"
	NONCE_URL = "https://" + opts.DIR_URL + ":14000/nonce-plz"
	ORDER_URL = "https://" + opts.DIR_URL + ":14000/order-plz"
	ACME_DIR = "https://" + opts.DIR_URL + ":14000/dir"
}

func getCertificate() {
	fmt.Println("GETTING NONCE-------------")
	nonce := getNonce()
	fmt.Println("CREATING ACCOUNT-------------")
	nonce, kid := createAccount(nonce)
	fmt.Println("REQUESTING CERT-------------")
	nonce, orderURL := requestCert(nonce, kid)
	fmt.Println(orderURL)
	fmt.Println("DOING CHALLENGES-------------")
	nonce, finalize := getChallenges(nonce, kid, orderURL)

	for _, challenge := range challenges {
		nonce = doChallenge(nonce, challenge, kid)
	}

	fmt.Println(finalize)

	fmt.Println("SUBMITTING CSR-------------")
	// time.Sleep(10 * time.Second)
	// nonce = sendCSR(nonce, kid, finalize)

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
