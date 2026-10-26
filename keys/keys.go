// Package keys generates and parses DKIM signing keys.
package keys

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// Generate returns a 1024 bit RSA key pair as PEM and its DKIM DNS record value.
// With id the key is derived from fmt.Sprint(id...) and is the same on every call.
func Generate(id ...any) (private, public, dns []byte) {

	//rsa
	var privateKey *rsa.PrivateKey
	var err error
	switch len(id) > 0 {
	case true:
		privateKey, err = customPrivateKey(fmt.Sprint(id...), 1024)
	default:
		privateKey, err = rsa.GenerateKey(rand.Reader, 1024) //2048 4096
	}
	if err != nil {
		// unreachable with a working system random source and a fixed key size
		panic(fmt.Sprintf("keys: generate key: %v", err))
	}

	derStream := x509.MarshalPKCS1PrivateKey(privateKey)
	priBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: derStream}

	//private
	private = pem.EncodeToMemory(priBlock)
	publicKey := &privateKey.PublicKey
	derPkix, _ := x509.MarshalPKIXPublicKey(publicKey)
	publicBlock := &pem.Block{Type: "PUBLIC KEY", Bytes: derPkix}

	//public
	public = pem.EncodeToMemory(publicBlock)
	dns = bytes.ReplaceAll(public, []byte("\n"), []byte(""))
	dns = bytes.TrimPrefix(dns, []byte("-----BEGIN PUBLIC KEY-----"))
	dns = bytes.TrimSuffix(dns, []byte("-----END PUBLIC KEY-----"))
	dns = bytes.TrimSpace(dns)
	dns = fmt.Appendf(nil, `"v=DKIM1; k=rsa; p=%s"`, dns)
	return
}

// ParseSigner parses a PEM private key: PKCS#1 RSA or PKCS#8 RSA/Ed25519.
func ParseSigner(private []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(private)
	if block == nil {
		return nil, errors.New("no PEM data")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("unsupported key type %T", key)
	}
	return signer, nil
}
