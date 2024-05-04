package main

import (
	"fmt"
	"github.com/gorilla/mux"
	"net/http"
)

func main() {
	cfg := Config{
		Address:     "127.0.0.1:8443",
		CACertFiles: []string{"certs/ca.crt"},
		CertFile:    "certs/tls.crt",
		KeyFile:     "certs/tls.key",
	}
	srv := NewGenericServer(cfg)

	r := mux.NewRouter()
	r.HandleFunc("/ssl", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "ssl")
	})

	go func() {
		http.HandleFunc("/hi", func(writer http.ResponseWriter, request *http.Request) {
			fmt.Fprintf(writer, "Hello, World!")
		})
		fmt.Println("Server is listening on port 8080...")
		err := http.ListenAndServe(":8080", nil)
		if err != nil {
			return
		}
	}()

	srv.ListenAndServe(r)
}
