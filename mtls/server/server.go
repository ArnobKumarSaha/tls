package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

func main() {
	server := http.Server{
		Addr:    ":9090",
		TLSConfig: &tls.Config{ // tlsConfig is not needed if we don't verify the clients
			ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs:  getTrustedCAs(),
			MinVersion: tls.VersionTLS12,
			// Certificates: getServerCertificates(),
		},
		Handler: getHandler(),
	}

	// With tls
	if err := server.ListenAndServeTLS("../cert/server.crt", "../cert/server.key"); err != nil {
		log.Fatalf("error listening to port: %v", err)
	}

	// this below technique give error `http: server gave HTTP response to HTTPS client`
	// populate server.TLSConfig.Certificates = getServerCertificates(), and call like below
	//if err := server.ListenAndServe(); err != nil {
	//	log.Fatalf("error listening to port: %v", err)
	//}
}

func getTrustedCAs() *x509.CertPool {
	// load CA certificate file and add it to list of client CAs
	caCertFile, err := ioutil.ReadFile("../cert/ca.crt")
	if err != nil {
		log.Fatalf("error reading CA certificate: %v", err)
	}
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(caCertFile)
	return certPool
}

func getHandler() *http.ServeMux {
	// set up handler to listen to root path
	handler := http.NewServeMux()
	handler.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		log.Println("new request")
		fmt.Fprintf(writer, "hello world \n")
	})
	return handler
}

// certificates have to be presented to the clients.
func getServerCertificates() []tls.Certificate {
	certificate, err := tls.LoadX509KeyPair("../cert/server.crt", "../cert/server.key")
	if err != nil {
		log.Fatalf("could not load certificate: %v", err)
	}
	return []tls.Certificate{certificate}
}