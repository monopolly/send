package send

import (
	"crypto"
	"crypto/rsa"
	"fmt"

	"github.com/monopolly/send/keys"
)

// "v=DMARC1; p=reject; ruf=mailto:ruf@domain.com; rua=mailto:rua@domain.com;"
func (a *Engine) SetSelector(selector string) *Engine {
	a.selector = selector
	return a
}

// GenerateKeys returns a 1024 bit RSA key pair and its DKIM DNS record, see keys.Generate.
func GenerateKeys(id ...any) (private, public, dns []byte) {
	return keys.Generate(id...)
}

// ParseSigner parses a PEM private key, see keys.ParseSigner.
func ParseSigner(private []byte) (crypto.Signer, error) {
	return keys.ParseSigner(private)
}

func (a *Engine) Help() (lines []string) {
	lines = append(lines, fmt.Sprintf("DNS Verification for %s", a.domain))
	lines = append(lines, fmt.Sprintf("%s._domainkey IN TXT %s", a.selector, a.dkim))
	lines = append(lines, `@ IN TXT "v=spf1 mx a ~all"`)
	lines = append(lines, fmt.Sprintf(`_dmarc IN TXT "v=DMARC1; p=quarantine; rua=mailto:a@%s;"`, a.domain))
	return
}

// PublicKey returns the PEM public key the engine was created with.
func (a *Engine) PublicKey() []byte {
	return a.public
}

// CustomSigner parses a PEM RSA private key; nil if it is invalid or not RSA.
func (a *Engine) CustomSigner(private []byte) (res *rsa.PrivateKey) {
	signer, err := keys.ParseSigner(private)
	if err != nil {
		return nil
	}
	res, _ = signer.(*rsa.PrivateKey)
	return
}
