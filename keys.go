package send

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// "v=DMARC1; p=reject; ruf=mailto:ruf@domain.com; rua=mailto:rua@domain.com;"
func (a *Engine) SetSelector(selector string) *Engine {
	a.dns.selector = selector
	return a
}

// idempodent ver
func GenerateKeys(id ...any) (private, public, dns []byte) {

	//rsa
	var privateKey *rsa.PrivateKey
	switch len(id) > 0 {
	case true:
		privateKey, _ = customPrivateKey(fmt.Sprint(id...), 1024)
	default:
		privateKey, _ = rsa.GenerateKey(rand.Reader, 1024) //2048 4096
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

func (a *Engine) Help() (lines []string) {
	lines = append(lines, fmt.Sprintf("DNS Verification for %s", a.domain))
	lines = append(lines, fmt.Sprintf("%s._domainkey IN TXT %s", a.dns.selector, a.dns.dkim))
	lines = append(lines, `@ IN TXT "v=spf1 mx a ~all"`)
	lines = append(lines, `_dmarc IN TXT "v=DMARC1; p=quarantine; rua=mailto:a@domain.com;"`)
	return
}

func (a *Engine) createSigner() {
	block, _ := pem.Decode(a.keys.private)
	var err error
	a.keys.signer, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
}

func (a *Engine) CustomSigner(private []byte) (res *rsa.PrivateKey) {
	block, _ := pem.Decode(private)
	res, _ = x509.ParsePKCS1PrivateKey(block.Bytes)
	return
}
