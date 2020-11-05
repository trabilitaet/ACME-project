package main

import (
	"fmt"

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

// func servHttp() {
// 	r := gin.Default()
// 	r.GET("/ping", func(c *gin.Context) {
// 		c.JSON(200, gin.H{
// 			"message": "pong",
// 		})
// 	})

// 	r.Run(":5002")
// }

func HTTPChall(urls []string, tokens []string) {
	r := gin.Default()
	fmt.Println("starting http server")

	for i, url := range urls {
		keyAuth := craftKeyAuth(tokens[i])
		fmt.Println("serving at: ", url[14:])
		r.GET(url[14:], func(c *gin.Context) {
			c.JSON(200, gin.H{
				"token": keyAuth,
			})
		})
	}

	r.Run(":5002")
}
