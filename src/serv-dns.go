package main

import (
	"fmt"
	"net"

	"github.com/miekg/dns"
)

const DNSPort = 11053

// const challPref = "_acme-challenge."
var prefix = ""
var keyAuth []string

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
	rr = &dns.A{
		Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0},
		A:   net.ParseIP(opts.IPv4_ADDRESS),
	}
	response.Answer = append(response.Answer, rr)

	name := prefix + query.Question[0].Name
	t := &dns.TXT{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0},
		Txt: keyAuth,
	}
	response.Extra = append(response.Extra, t)
	return *response
}

func servDNS() {
	//Listen on UDP Port 11053 of localhost
	addr := net.UDPAddr{
		Port: DNSPort,
		IP:   net.ParseIP("127.0.0.1"),
	}
	udp, _ := net.ListenUDP("udp", &addr)

	// infinite loop to wait for requests
	for {
		packet := make([]byte, 1024)             // binary
		_, returnAddr, _ := udp.ReadFrom(packet) //blocking call

		var msg dns.Msg
		msg.Unpack(packet) //convert to extract headers and flags

		var response dns.Msg = craftResponse(&msg)
		fmt.Println("--------response--------")
		fmt.Println(response.String())

		outPacket, _ := response.Pack()
		udp.WriteTo(outPacket, returnAddr)
	}
}

func DNSChall(token string) {
	prefix = "_acme-challenge."
	keyAuth = craftKeyAuth(token)
}
