package main

import (
	"fmt"
)

func init() {
	pemKey, _ := ioutil.ReadFile("data/acme-key")
	block, _ := pem.Decode([]byte(pemKey))
	privKey, _ = x509.ParsePKCS1PrivateKey(block.Bytes)

	NEW_ACC_URL = "https://" + DIR_URL + ":14000/sign-me-up"
	NONCE_URL = "https://" + DIR_URL + ":14000/nonce-plz"
	ORDER_URL = "https://" + DIR_URL + ":14000/order-plz"
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
	resp, _ := http.Post(ORDER_URL, "application/jose+json", bytes.NewReader(reqJSON))
	newNonce = resp.Header.Get("Replay-Nonce")
	orderID = resp.Header.Get("Location")
	return newNonce, orderID
}

func getCertificate() {
	nonce := getNonce()
	nonce, kid := createAccount(nonce)
	nonce, orderID = requestCert(nonce, kid)

	fmt.Println(nonce)
	fmt.Println(orderID)

	//complete challenge

	//create(?)/submit CSR

	//download certificate

	//start https server
	// go servHttps()
}
