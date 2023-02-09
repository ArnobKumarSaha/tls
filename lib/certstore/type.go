package certstore

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"github.com/spf13/afero"
)

type CertStore struct {
	fs           afero.Fs
	dir          string
	organization []string
	prefix       string
	ca           string
	caKey        *rsa.PrivateKey
	caCert       *x509.Certificate
}

func NewCertStore(fs afero.Fs, dir string, organization ...string) (*CertStore, error) {
	err := fs.MkdirAll(dir, 0755)
	if err != nil {
		return nil, fmt.Errorf("%v error happened when failed to create dir %s ", err, dir)
	}
	return &CertStore{fs: fs, dir: dir, ca: "ca", organization: append([]string(nil), organization...)}, nil
}

// Getters

func (s *CertStore) Location() string {
	return s.dir
}

func (s *CertStore) CAName() string {
	return s.ca
}

func (s *CertStore) CACert() *x509.Certificate {
	return s.caCert
}

func (s *CertStore) CACertBytes() []byte {
	return encodeCertPEM(s.caCert)
}

func (s *CertStore) CAKey() *rsa.PrivateKey {
	return s.caKey
}

func (s *CertStore) CAKeyBytes() []byte {
	return encodePrivateKeyPEM(s.caKey)
}
