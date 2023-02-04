package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

func main(){
	client := http.Client{
		Timeout: time.Minute * 3,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: getTrustedCAs(),
				Certificates: getClientCertificates(),
			},
		},
	}
	makeRequest(client)
}

// ca.crt is being used as a root CA.
// server.crt (or some CA from its certificate chain) has to be signed with this ca
func getTrustedCAs() *x509.CertPool {
	cert, err := ioutil.ReadFile("../cert/ca.crt")
	if err != nil {
		log.Fatalf("could not open certificate file: %v", err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(cert)
	return caCertPool
}

// certificates have to be presented to the server, if server's clientAuth is set to tls.RequireAndVerifyClientCert
func getClientCertificates() []tls.Certificate {
	certificate, err := tls.LoadX509KeyPair("../cert/client.crt", "../cert/client.key")
	if err != nil {
		log.Fatalf("could not load certificate: %v", err)
	}
	return []tls.Certificate{certificate}
}

func makeRequest(client http.Client)  {
	resp,err := client.Get("https://server.test:9090")
	if err != nil {
		log.Fatalf("error making get request: %v", err)
	}

	body,err := ioutil.ReadAll(resp.Body)
	if err != nil{
		log.Fatalf("error reading response: %v", err)
	}
	fmt.Println(string(body))
}