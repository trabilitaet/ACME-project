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

//TODO:
// complete HTTPS challenges 'http-01'
// TCP port 5002
func servHttp() {

	r := gin.Default()

	// receive token
	// place token for subsequent get ?
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})

	r.Run(":5002")
}
