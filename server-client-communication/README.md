## CA
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout ./ca.key -out ./ca.crt -subj "/CN=mongo/O=kubedb"

## Server
openssl req -newkey rsa:2048 -nodes -keyout tls.key -out tls.csr -subj "/CN=127.0.0.1"
openssl x509 -req -in tls.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out tls.crt -days 365 -extfile altsubj.ext

## Client
openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr -subj "/CN=clients"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365 -extfile altsubj.ext



## CURL
`curl  https://127.0.0.1:8443/ssl -X GET  --cacert certs/ca.crt`

Note that,  In the above command , We can skip `--cert client-cert.pem --key client-key.pem` this part, if 
the server was running  with
- wither directly like this `srv.ListenAndServeTLS(s.cfg.CertFile, s.cfg.KeyFile))`
- or, svr.TLSConfig.ClientAuth = tls.NoClientCert(this is the default value) is set. 

In other cases, like VerifyClientCertIfGiven / RequestClientCert, client flags are mandatory in curl command.


### Update Your newly created CA
```bash
cd /usr/local/share/ca-certificates
sudo vim test-ca.crt

sudo update-ca-certificates
```

## After updating the default CA directory

curl  https://127.0.0.1:8443/ssl -X GET 

##  Other Info
`HEAD` is exactly same as `curl -I`. It just gets the header.