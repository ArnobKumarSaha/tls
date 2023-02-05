## Check a private key
`openssl rsa -in private.key -check`

## Check a public key
`openssl pkey -inform PEM -pubin -in public.key -noout
`

## Check a CSR
`openssl req -text -noout -verify -in CSR.csr`

## Check a certificate
`openssl x509 -in certificate.crt -text -noout`


NB: [More debug & conversion related commands](https://gist.github.com/davewongillies/7050080#debugging-using-openssl)