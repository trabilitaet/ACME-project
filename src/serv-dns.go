package main

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"

	"github.com/miekg/dns"
)

const DNSPort = 10053

// const challPref = "_acme-challenge."
var prefix = ""
var keyAuth256 []string

// TODO:
// * basic: serve DNS requests DONE
// 		- reply to A record queries with IP from args
// * reply to challenges `dns-01`
// 	-provisioning a DNS record under domain name
// 	-provision HTTP resource under a URI
// * sign a nonce with private key (?)
// UDP port 10053

//The DNS protocol uses two types of DNS messages, queries and replies;
// both have the same format. Each message consists of a header and four sections:
// question, answer, authority, and an additional space.
// A header field (flags) controls the content of these four sections.

func craftResponse(query *dns.Msg) dns.Msg {
	response := new(dns.Msg)
	response.SetReply(query)
	responseHeader := dns.MsgHdr{
		Id:                 query.MsgHdr.Id,
		Response:           true,
		Opcode:             query.MsgHdr.Opcode,
		Authoritative:      true,
		Truncated:          false,
		RecursionDesired:   false,
		RecursionAvailable: false,
		Zero:               false,
		AuthenticatedData:  false,
		CheckingDisabled:   false,
		Rcode:              0,
	}
	response.MsgHdr = responseHeader

	var rr dns.RR
	if prefix == "" {
		rr = &dns.A{
			Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0},
			A:   net.ParseIP(opts.IPv4_ADDRESS),
		}
		response.Answer = append(response.Answer, rr)
	} else {
		name := prefix + query.Question[0].Name
		t := &dns.TXT{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0},
			Txt: keyAuth256,
		}
		response.Answer = append(response.Extra, t)
	}

	return *response
}

func servDNS() {
	addr := net.UDPAddr{
		Port: DNSPort,
		IP:   net.ParseIP("0.0.0.0"),
	}
	udp, _ := net.ListenUDP("udp", &addr)

	// infinite loop to wait for requests
	fmt.Println("DNS running on: ", addr)
	for {
		packet := make([]byte, 1024)               // binary
		_, returnAddr, err := udp.ReadFrom(packet) //blocking call
		fmt.Println("received DNS request")
		if err != nil {
			fmt.Println(err)
			fmt.Println(packet)
		} else {
			var msg dns.Msg
			msg.Unpack(packet) //convert to extract headers and flags
			fmt.Println(msg.String())
			var response dns.Msg = craftResponse(&msg)
			fmt.Println("--------response--------")
			fmt.Println(response.String())

			outPacket, _ := response.Pack()
			udp.WriteTo(outPacket, returnAddr)
		}

	}
}

func DNSChall(token string) {
	prefix = "_acme-challenge."
	digest := sha256.Sum256([]byte(craftKeyAuth(token)))
	digest64 := base64.RawURLEncoding.EncodeToString(digest[:])
	keyAuth256 = append(keyAuth256, digest64)
}
