package certstore

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/spf13/afero"
	"k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/keyutil"
	"path/filepath"
	"strings"
)

func (s *CertStore) certFileKeyFileExists(name string, prefix ...string) bool {
	if err := s.setPrefix(prefix...); err != nil {
		panic(err)
	}

	if _, err := s.fs.Stat(s.CertFile(name)); err == nil {
		if _, err := s.fs.Stat(s.KeyFile(name)); err == nil {
			return true
		}
	}
	return false
}

func (s *CertStore) CertFile(name string) string {
	filename := strings.ToLower(name) + ".crt"
	if s.prefix != "" {
		filename = s.prefix + filename
	}
	return filepath.Join(s.dir, filename)
}

func (s *CertStore) KeyFile(name string) string {
	filename := strings.ToLower(name) + ".key"
	if s.prefix != "" {
		filename = s.prefix + filename
	}
	return filepath.Join(s.dir, filename)
}

func (s *CertStore) Write(name string, crt *x509.Certificate, key *rsa.PrivateKey) error {
	if err := afero.WriteFile(s.fs, s.CertFile(name), encodeCertPEM(crt), 0644); err != nil {
		return fmt.Errorf("failed to write `%s`: %v \n", s.CertFile(name), err)
	}
	if err := afero.WriteFile(s.fs, s.KeyFile(name), encodePrivateKeyPEM(key), 0600); err != nil {
		return fmt.Errorf("failed to write `%s`: %v \n", s.KeyFile(name), err)
	}
	return nil
}

func (s *CertStore) Read(name string) (*x509.Certificate, *rsa.PrivateKey, error) {
	crtBytes, err := afero.ReadFile(s.fs, s.CertFile(name))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read certificate `%s` : %v \n", s.CertFile(name), err)
	}
	crt, err := cert.ParseCertsPEM(crtBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate `%s`: %v \n", s.CertFile(name), err)
	}

	keyBytes, err := afero.ReadFile(s.fs, s.KeyFile(name))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read private key `%s`: %v \n", s.KeyFile(name), err)
	}
	key, err := keyutil.ParsePrivateKeyPEM(keyBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse private key `%s`: %v \n", s.KeyFile(name), err)
	}
	return crt[0], key.(*rsa.PrivateKey), nil
}

func encodePrivateKeyPEM(key *rsa.PrivateKey) []byte {
	block := pem.Block{
		Type:  keyutil.RSAPrivateKeyBlockType,
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	return pem.EncodeToMemory(&block)
}

func encodeCertPEM(c *x509.Certificate) []byte {
	block := pem.Block{
		Type:  cert.CertificateBlockType,
		Bytes: c.Raw,
	}
	return pem.EncodeToMemory(&block)
}
