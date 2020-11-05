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
	fmt.Println("GETTING NONCE-------------")
	nonce := getNonce()
	fmt.Println("CREATING ACCOUNT-------------")
	nonce, kid := createAccount(nonce)
	fmt.Println("REQUESTING CERT-------------")
	nonce, orderURL := requestCert(nonce, kid)
	fmt.Println(orderURL)
	fmt.Println("DOING CHALLENGES-------------")
	nonce, finalize := doChallenges(nonce, kid, orderURL)

	fmt.Println(finalize)

	// fmt.Println("SUBMITTING CSR-------------")
	// template := x509.CertificateRequest{
	// 	// Raw:                      []byte // Complete ASN.1 DER content (CSR, signature algorithm and signature).
	// 	// RawTBSCertificateRequest: []byte // Certificate request info part of raw ASN.1 DER content.
	// 	// RawSubjectPublicKeyInfo:  []byte // DER encoded SubjectPublicKeyInfo.
	// 	// RawSubject:               []byte // DER encoded Subject.
	// 	// Version:            int
	// 	// Signature:          []byte
	// 	SignatureAlgorithm: x509.SHA256WithRSA,
	// 	PublicKeyAlgorithm: x509.RSA,
	// 	PublicKey:          privKey.PublicKey,

	// 	Subject: pkix.Name{
	// 		CommonName:         opts.DOMAIN[0],
	// 		Country:            []string{"CH"},
	// 		Organization:       []string{"project"},
	// 		OrganizationalUnit: []string{"acme"},
	// 		Locality:           []string{"ZH"},
	// 		Province:           []string{"ZH"},
	// 	},

	// 	// Attributes: []pkix.AttributeTypeAndValueSET
	// 	// Extensions: []pkix.Extension
	// 	// ExtraExtensions: []pkix.Extension
	// 	DNSNames: opts.DOMAIN,
	// 	// EmailAddresses: []string
	// 	// IPAddresses:    []net.IP
	// 	// URIs:           []*url.URL // Go 1.10
	// }

	// //create DER encoded CSR
	// csr, _ := x509.CreateCertificateRequest(rand.Reader, &template, privKey)
	// // pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})

	// fmt.Println(kid)
	// protected := getProtectedHeaderKID(nonce, kid, finalize)
	// csrJSON, _ := json.Marshal(CSRencoded{csr})
	// payload := base64.RawURLEncoding.EncodeToString(csrJSON)

	// request := message{
	// 	Payload:   payload,
	// 	Protected: protected,
	// 	Signature: sign([]byte(protected + "." + payload)),
	// }
	// reqJSON, _ := json.Marshal(request)
	// fmt.Println(string(reqJSON))
	// resp, err := http.Post(finalize, "application/jose+json", bytes.NewReader(reqJSON))
	// if err != nil {
	// 	fmt.Println("ERROR posting order")
	// 	fmt.Println(err)
	// 	return
	// }
	// fmt.Println(resp)

	// body, _ := ioutil.ReadAll(resp.Body)
	// fmt.Println("Body:")
	// fmt.Println(string(body))
	// fmt.Println(string(reqJSON))

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
