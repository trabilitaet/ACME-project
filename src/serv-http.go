package main

import (
	"fmt"

	"github.com/gin-gonic/gin"
)

var url string

var challengeRunning = true
var httpRunner *gin.Engine

func HTTPinit() {
	httpRunner = gin.Default()
	go runner()
}

// TODO:
// TCP port 5003
// GET /shutdown -> terminate application
func waitForShutdown() {
	s := gin.Default()
	s.GET("/shutdown", func(c *gin.Context) {
		stop = true
	})

	s.Run("0.0.0.0:5003")
}

func runner() {
	for !stop {
		httpRunner.Run("0.0.0.0:5002")
	}
}

func HTTPChall(token string) {
	fmt.Println("starting http challenge server")

	keyAuth := craftKeyAuth(token)
	fmt.Println("TOKEN: ", keyAuth)
	url := "/.well-known/acme-challenge/" + token

	fmt.Println("serving at: ", url)
	httpRunner.GET(url, func(c *gin.Context) {
		c.Data(200, "application/octet-stream", []byte(keyAuth))
	})

}

func servHTTPS(certificate []byte) {
	s := gin.Default()
	s.GET("/", func(c *gin.Context) {
		c.Data(200, "application/octet-stream", certificate)
	})

	for !stop {
		s.RunTLS(":5001", "./data/certificate.pem", "./data/acme-key")
		// s.Run(":5001")
	}
}
