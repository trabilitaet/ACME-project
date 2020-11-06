package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"
)

var NEW_ACC_URL string
var NONCE_URL string
var ORDER_URL string

var privKey *rsa.PrivateKey
var tlsKey *rsa.PrivateKey
var challenges []challenge
var orderURL string
var certURL string

func ACMEinit() {
	pemData, _ := ioutil.ReadFile("data/acme-key")
	block, _ := pem.Decode([]byte(pemData))
	privKey, _ = x509.ParsePKCS1PrivateKey(block.Bytes)

	pemData, _ = ioutil.ReadFile("data/tls-key")
	block, _ = pem.Decode([]byte(pemData))
	tlsKey, _ = x509.ParsePKCS1PrivateKey(block.Bytes)

	pemData, _ = ioutil.ReadFile("project/pebble.minica.pem")
	block, _ = pem.Decode([]byte(pemData))
	pebbleCert, _ := x509.ParseCertificate(block.Bytes)
	certpool := x509.NewCertPool()
	certpool.AddCert(pebbleCert)
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: certpool, ServerName: "pebble"}

	resp, err := http.Get(opts.DIR_URL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting URLs: %s\n", err)
		return
	}
	body, _ := ioutil.ReadAll(resp.Body)

	dir := DIR{}
	json.Unmarshal(body, &dir)
	fmt.Println(dir)

	NEW_ACC_URL = dir.NewAccount
	NONCE_URL = dir.NewNonce
	fmt.Println("NONCE_URL:", NONCE_URL)
	ORDER_URL = dir.NewOrder
}

func getCertificate() {
	fmt.Println("GETTING NONCE-------------")
	nonce := getNonce()
	fmt.Println("CREATING ACCOUNT-------------")
	nonce, kid := createAccount(nonce)
	fmt.Println("REQUESTING CERT-------------")
	nonce, orderURL = requestCert(nonce, kid)
	fmt.Println(orderURL)
	fmt.Println("DOING CHALLENGES-------------")
	nonce, finalize := getChallenges(nonce, kid)
	for _, challenge := range challenges {
		nonce = doChallenge(nonce, challenge, kid)
	}

	fmt.Println("SUBMITTING CSR-------------")
	time.Sleep(2 * time.Second)
	status := 0
	for i := 0; i < 15; i++ {
		nonce, status = getStatus(nonce, kid)
		time.Sleep(time.Second)
		if status == 1 {
			break
		}
	}
	nonce = sendCSR(nonce, kid, finalize)

	fmt.Println("DOWNLOAD CERTIFICATE----------------------")
	nonce, _, ordersJSON := postAsGet(nonce, orderURL, []byte(""), kid)
	nonce, status = getStatus(nonce, kid)
	fmt.Println(string(ordersJSON))
	nonce, _, newCertificate := postAsGet(nonce, certURL, []byte(""), kid)
	fmt.Println("DOWNLOADING CERT FROM:", certURL)
	// fmt.Println(string(newCertificate))

	f, _ := os.Create("data/certificate.pem")
	f.WriteString(string(newCertificate))
	f.Close()

	//START HTTPS SERVER--------------------------------------
	go servHTTPS(newCertificate)
}
