## Only generate the private key:
`openssl genrsa -out ca.key 2048`

#### Generate corresponding public key
`openssl rsa -in private.key -pubout -out public.key`

## Generate both caKey & caCert:
`openssl req -newkey rsa:2048 -nodes -x509 -days 365 -out ca.crt -keyout ca.key`

-newkey <algo:bit> = generate a new private key

-nodes = Don't encrypt the output key

-x509 = output should be of x509 structure

-days DAY = validity of the certificate

-out = output file of certificate

-keyout = output file of the key

-subj "/CN=mongo/O=kubedb"  # Prompt will open, if not given.

# Create a signing request(CSR):

### private key pre-exists
`openssl req -new -key server.key -days 365 -out server.csr`
-new = A new request

### create csr as well as the private key
`openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr`

### without using promt
`openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/C=CN/ST=GD/L=SZ/O=Acme, Inc./CN=*.example.com"`

# Sign an existing CSR :
### without SAN
`openssl x509  -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -sha256`

-req = input is a certificate request

-in = input csr file
-CAcreateserial = create serial if doesn't exist


### Using SAN(subject alternative name)
`echo "subjectAltName=DNS:some.host" > altsubj.ext`
`openssl x509  -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -sha256 -extfile altsubj.ext`

### self-signed
`openssl x509 -req -in example.csr -signkey example.key -out example.crt -days 3650 -sha256 -extfile altsubj.ext`
-signkey = to sign self cert



NB: According to [RFC 6125](https://www.rfc-editor.org/rfc/rfc6125#section-6.4.4), If SAN is present then CN should not be checked.

