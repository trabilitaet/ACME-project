package main

import (
	"fmt"

	"github.com/gin-gonic/gin"
)

var url string

var challengeRunning = true
var r *gin.Engine

func init() {
	r = gin.Default()
	go r.Run(":5002")
}

// TODO:
// TCP port 5003
// GET /shutdown -> terminate application
func waitForShutdown() {
	s := gin.Default()
	s.GET("/shutdown", func(c *gin.Context) {
		stop = true
	})

	s.Run(":5003")
}

func HTTPChall(token string) {
	fmt.Println("starting http challenge server")

	keyAuth := craftKeyAuth(token)
	fmt.Println("TOKEN: ", keyAuth)
	url := "/.well-known/acme-challenge/" + token

	fmt.Println("serving at: ", url)
	r.GET(url, func(c *gin.Context) {
		c.Data(200, "application/octet-stream", []byte(keyAuth))
	})

}
