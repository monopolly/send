package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"testing"
)

func TestGenerateDeterministic(t *testing.T) {
	p1, pub1, dns1 := Generate("1", "2", "3")
	p2, pub2, dns2 := Generate("1", "2", "3")
	if string(p1) != string(p2) || string(pub1) != string(pub2) || string(dns1) != string(dns2) {
		t.Error("same seed gives different keys")
	}

	p3, _, _ := Generate("other")
	if string(p1) == string(p3) {
		t.Error("different seeds give the same key")
	}

	r1, _, _ := Generate()
	r2, _, _ := Generate()
	if string(r1) == string(r2) {
		t.Error("random keys are equal")
	}
}

// DNS records of existing domains depend on the derived key: it must never change.
func TestGenerateStable(t *testing.T) {
	private, _, _ := Generate("example.com")
	sum := sha256.Sum256(private)
	const want = "2cf54a018d716ad914d88d8314d8ed4d78d98936cd42a55b903ae8d90f962969"
	if got := hex.EncodeToString(sum[:]); got != want {
		t.Errorf("derived key changed: sha256 %s, want %s", got, want)
	}
}

func TestParseSigner(t *testing.T) {
	pkcs1, _, _ := Generate("example.org")
	if s, err := ParseSigner(pkcs1); err != nil {
		t.Errorf("pkcs1: %v", err)
	} else if _, ok := s.(*rsa.PrivateKey); !ok {
		t.Errorf("pkcs1: %T", s)
	}

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	der, _ := x509.MarshalPKCS8PrivateKey(rsaKey)
	if _, err := ParseSigner(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); err != nil {
		t.Errorf("pkcs8 rsa: %v", err)
	}

	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	der, _ = x509.MarshalPKCS8PrivateKey(edKey)
	if s, err := ParseSigner(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); err != nil {
		t.Errorf("pkcs8 ed25519: %v", err)
	} else if _, ok := s.(ed25519.PrivateKey); !ok {
		t.Errorf("pkcs8 ed25519: %T", s)
	}

	for _, bad := range [][]byte{nil, []byte("garbage"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("x")})} {
		if _, err := ParseSigner(bad); err == nil {
			t.Errorf("ParseSigner(%q): expected error", bad)
		}
	}
}
