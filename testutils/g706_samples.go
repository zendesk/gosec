package testutils

import "github.com/securego/gosec/v2"

// SampleCodeG706 - Log injection via taint analysis
var SampleCodeG706 = []CodeSample{
	{[]string{`
package main

import (
	"log"
	"net/http"
)

func handler(r *http.Request) {
	username := r.URL.Query().Get("user")
	log.Printf("User logged in: %s", username)
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import (
	"log"
	"os"
)

func logArgs() {
	input := os.Args[1]
	log.Println("Processing:", input)
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import (
	"log"
)

func safeLog() {
	// Safe - no user input
	log.Println("Application started")
}
`}, 0, gosec.NewConfig()},
	// Test: json.Marshal sanitizer
	{[]string{`
package main

import (
	"encoding/json"
	"log"
	"net/http"
)

func handler(r *http.Request) {
	data := r.FormValue("data")
	jsonData, _ := json.Marshal(data)
	log.Printf("Received: %s", jsonData)
}
`}, 0, gosec.NewConfig()},
	// Test: strconv sanitizer
	{[]string{`
package main

import (
	"log"
	"net/http"
	"strconv"
)

func handler(r *http.Request) {
	id := r.FormValue("id")
	num, _ := strconv.Atoi(id)
	log.Printf("Processing ID: %d", num)
}
`}, 0, gosec.NewConfig()},
}
