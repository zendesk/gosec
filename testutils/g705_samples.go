package testutils

import "github.com/securego/gosec/v2"

// SampleCodeG705 - XSS via taint analysis
var SampleCodeG705 = []CodeSample{
	{[]string{`
package main

import (
	"fmt"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	fmt.Fprintf(w, "<h1>Hello %s</h1>", name)
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import (
	"net/http"
)

func writeHandler(w http.ResponseWriter, r *http.Request) {
	data := r.FormValue("data")
	w.Write([]byte(data))
}
`}, 1, gosec.NewConfig()},
	{[]string{`
package main

import (
	"fmt"
	"net/http"
	"html"
)

func safeHandler(w http.ResponseWriter, r *http.Request) {
	// Safe - escaped output
	name := r.URL.Query().Get("name")
	fmt.Fprintf(w, "<h1>Hello %s</h1>", html.EscapeString(name))
}
`}, 0, gosec.NewConfig()},
	{[]string{`
package main

import (
	"fmt"
	"net/http"
)

func staticHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "<h1>Hello World</h1>")
}
`}, 0, gosec.NewConfig()},
	// Test: json.Marshal sanitizer
	{[]string{`
package main

import (
	"encoding/json"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	data := r.FormValue("data")
	jsonData, _ := json.Marshal(data)
	w.Write(jsonData)
}
`}, 0, gosec.NewConfig()},
	// Test: strconv sanitizer
	{[]string{`
package main

import (
	"net/http"
	"strconv"
)

func handler(w http.ResponseWriter, r *http.Request) {
	id := r.FormValue("id")
	num, _ := strconv.Atoi(id)
	w.Write([]byte(strconv.Itoa(num)))
}
`}, 0, gosec.NewConfig()},
}
