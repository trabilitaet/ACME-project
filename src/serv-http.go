package main

import (
	"fmt"
	"net/http"
)

//TODO:
// complete HTTPS challenges 'http-01'
// TCP port 5002

func hello(w http.ResponseWriter, req *http.Request) {

    fmt.Fprintf(w, "hello\n")
}


func main() {

	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/", fs)

    http.ListenAndServe(":8090", nil)
}