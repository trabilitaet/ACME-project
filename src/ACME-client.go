package main

import (
	"fmt" //string formatting, print
	//"net/http"
	//"github.com/jessevdk/go-flags" // argparse
)


func main() {
//TODO:
// parse arguments to get domain,aliases,...
// generate public/private key pair (?maybe use existing)
// request certificate from ACME server using CSR (PKCS#10 )
// sign CSR using server cert?
// request revocal of certificate
// check the ACME server's certificate -> if invalid, do not request again
	fmt.Print("test")

}