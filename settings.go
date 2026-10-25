package send

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

type Settings struct {
	Domain   string
	Private  []byte
	Public   []byte
	DKIM     string
	Selector string //dkim
	Volume   string
	Err      func(err error)

	signer *rsa.PrivateKey
	mx     *MX
}

func (a *Settings) createSigner() (err error) {
	block, _ := pem.Decode(a.Private)
	a.signer, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	return
}
