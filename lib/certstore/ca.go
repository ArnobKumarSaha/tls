package certstore

import (
	"crypto/rsa"
	"fmt"
	"github.com/spf13/afero"
	"k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/keyutil"
	"net"
	"os"
	"strings"
)

func (s *CertStore) LoadCA(prefix ...string) error {
	if err := s.setPrefix(prefix...); err != nil {
		return err
	}

	if s.certFileKeyFileExists(s.ca, prefix...) {
		var err error
		s.caCert, s.caKey, err = s.Read(s.ca)
		return err
	}

	// only ca key found, extract ca cert from it.
	if _, err := s.fs.Stat(s.KeyFile(s.ca)); err == nil {
		keyBytes, err := afero.ReadFile(s.fs, s.KeyFile(s.ca))
		if err != nil {
			return fmt.Errorf("failed to read private key `%s`: %v \n", s.KeyFile(s.ca), err)
		}
		key, err := keyutil.ParsePrivateKeyPEM(keyBytes)
		if err != nil {
			return fmt.Errorf("failed to parse private key `%s`: %v \n", s.KeyFile(s.ca), err)
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("private key `%s` is not a rsa private key", s.KeyFile(s.ca))
		}
		return s.createCAFromKey(rsaKey)
	}

	return os.ErrNotExist
}

func (s *CertStore) NewCA(prefix ...string) error {
	if err := s.setPrefix(prefix...); err != nil {
		return err
	}

	key, err := newPrivateKey()
	if err != nil {
		return fmt.Errorf("failed to generate private key, %v", err)
	}
	return s.createCAFromKey(key)
}

func (s *CertStore) setPrefix(prefix ...string) error {
	switch len(prefix) {
	case 0:
		s.prefix = ""
	case 1:
		s.prefix = strings.ToLower(strings.Trim(strings.TrimSpace(prefix[0]), "-")) + "-"
	default:
		return fmt.Errorf("multiple ca prefix given: %v", prefix)
	}
	return nil
}

func (s *CertStore) createCAFromKey(key *rsa.PrivateKey) error {
	var err error

	cfg := cert.Config{
		CommonName:   s.ca,
		Organization: s.organization,
		AltNames: cert.AltNames{
			DNSNames: []string{s.ca},
			IPs:      []net.IP{net.ParseIP("127.0.0.1")},
		},
	}
	crt, err := cert.NewSelfSignedCACert(cfg, key)
	if err != nil {
		return fmt.Errorf("failed to generate self-signed certificate %v", err)
	}
	err = s.Write(s.ca, crt, key)
	if err != nil {
		return err
	}

	s.caCert = crt
	s.caKey = key
	return nil
}
