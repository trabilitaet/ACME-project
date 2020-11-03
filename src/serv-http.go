package main

import (
	"github.com/gin-gonic/gin"
)

var url string

// TODO:
// TCP port 5003
// GET /shutdown -> terminate application
func waitForShutdown() {
	r := gin.Default()

	r.GET("/shutdown", func(c *gin.Context) {
		stop = true
	})

	r.Run(":5003")
}

func servHttp() {
	r := gin.Default()
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})

	r.Run(":5002")
}

func HTTPChall(url string, token string) {
	keyAuth = craftKeyAuth(token)
	r := gin.Default()
	r.GET(url, func(c *gin.Context) {
		c.JSON(200, gin.H{
			"token": keyAuth,
		})
	})
	r.Run(":5002")
}
