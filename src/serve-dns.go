package main

import (
	"fmt"
	"net"
)

const DNSPort = 11053
// TODO:
// * basic: serve DNS requests
// * reply to challenges `dns-01`
// 	-provisioning a DNS record under domain name
// 	-provision HTTP resource under a URI
// * sign a nonce with private key
// UDP port 10053
// suggest localhost for all requests? port?

func main() {
	//Listen on UDP Port 11053 of localhost
	addr := net.UDPAddr{
		Port: DNSPort,
		IP:   net.ParseIP("127.0.0.1"),
	}
	udp, _ := net.ListenUDP("udp", &addr)

	// infinite loop to wait for requests
	for {
	    packet := make([]byte, 1024) // binary
		len, addr, _ := udp.ReadFrom(packet)
		fmt.Print("packet received\n")
		fmt.Println(packet)
		fmt.Println(len)
		fmt.Println(addr)
	}
}
