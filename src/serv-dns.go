package main

import (
	"fmt"
	"github.com/miekg/dns"
	"net"
)

const DNSPort = 11053

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
	fmt.Println(query.String())
	response := new(dns.Msg)
	//header flags
	// QR 	Indicates if the message is a query (0) or a reply (1) 	1
	// OPCODE 	The type can be QUERY (standard query, 0), IQUERY (inverse query, 1),
	// 		or STATUS (server status request, 2) 	4
	// AA 	Authoritative Answer, in a response, indicates if
	// 		the DNS server is authoritative for the queried hostname 	1
	// TC 	TrunCation, indicates that this message was truncated due to
	// 		excessive length 	1
	// RD 	Recursion Desired, indicates if the client means a recursive query 	1
	// RA 	Recursion Available, in a response, indicates if the replying DNS
	// 		server supports recursion 	1
	// Z 	Zero, reserved for future use 	3
	// RCODE 	Response code, can be NOERROR (0), FORMERR (1, Format error),
	// 		SERVFAIL (2), NXDOMAIN (3, Nonexistent domain), etc.[33] 	4
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
		fmt.Print("packet received\n")

		var msg dns.Msg
		msg.Unpack(packet) //convert to extract headers and flags
		// fmt.Println(msg.String())

		var response dns.Msg = craftResponse(&msg)
		// fmt.Println("--------response--------")
		// fmt.Println(response.String())

		outPacket, _ := response.Pack()
		udp.WriteTo(outPacket, returnAddr)

		// var sent dns.Msg
		// sent.Unpack(outPacket) //convert to extract headers and flags
		// fmt.Print("packet sent: \n")
		// fmt.Println(sent.String())
	}
}
