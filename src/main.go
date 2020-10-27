package main

import (
	// "encoding/json"
	"fmt"                          //string formatting, print
	"github.com/jessevdk/go-flags" // argparse
	// "io/ioutil"
	"time"
)

var stop = false

var opts struct {
	DIR_URL      string   `long:"dir" description:"is the directory URL of the ACME server that should be used." required:"true"`
	IPv4_ADDRESS string   `long:"record" description:"is the IPv4 address which must be returned by your DNS server for all A-record queries." required:"true"`
	DOMAIN       []string `long:"domain" description:"is the domain for  which to request the certificate. If multiple --domain flags are present, a single certificate for multiple domains should be requested. Wildcard domains have no special flag and are simply denoted by, e.g., *.example.net." required:"true"`
	REVOKATION   bool     `long:"revoke" description:"If present, your application should immediately revoke the certificate after obtaining it. In both cases, your application should start its HTTPS server and set it up to use the newly obtained certificate."`
	PosArgs      struct {
		CHALLENGE string
	} `positional-args:"yes" required:"true"`
}

// func wait_for_shutdown() {
// 	// TODO:
// 	// TCP port 5003
// 	// GET /shutdown -> terminate application
// }

func init() {
	fmt.Println("Started main")
	flags.Parse(&opts)
	fmt.Println("Dir: ", opts.DIR_URL)
	fmt.Println("IP: ", opts.IPv4_ADDRESS)
	fmt.Println("Domain: ", opts.DOMAIN)
	fmt.Println("Revoke: ", opts.REVOKATION)
	fmt.Println("Challenge type: ", opts.PosArgs.CHALLENGE)
	// file, _ := json.MarshalIndent(opts, "", " ")
	// _ = ioutil.WriteFile("data/options.json", file, 0644)
}

func main() {
	// go wait_for_shutdown()
	//start dns server + http in case of http challenge
	go servDNS()
	// go serv_http()
	// create account at ACME server
	// POST to newaccount URL

	for !stop {
		time.Sleep(2 * time.Second)
	}
	//wait until certificate is here
	//start https server

}
