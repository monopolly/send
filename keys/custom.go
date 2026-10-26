package keys

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
)

// customReader is a deterministic byte stream: sha256(seed || counter) blocks.
type customReader struct {
	seed    []byte
	counter uint64
	buffer  []byte
}

func newReader(seed string) *customReader {
	return &customReader{seed: []byte(seed)}
}

func (dr *customReader) Read(p []byte) (n int, err error) {
	for len(dr.buffer) < len(p) {
		h := sha256.New()
		h.Write(dr.seed)
		binary.Write(h, binary.BigEndian, dr.counter)
		dr.counter++
		dr.buffer = h.Sum(dr.buffer)
	}
	n = copy(p, dr.buffer)
	dr.buffer = dr.buffer[n:]
	return n, nil
}

// генерирует детерминированный RSA ключ
// The algorithm must not change: DNS records of existing keys depend on it.
func customPrivateKey(seed string, bits int) (*rsa.PrivateKey, error) {
	if bits < 512 {
		return nil, fmt.Errorf("key size too small: %d", bits)
	}

	reader := newReader(seed)
	p := deterministicPrime(reader, bits/2)
	q := deterministicPrime(reader, bits/2)

	// Убеждаемся, что p != q
	if p.Cmp(q) == 0 {
		q = deterministicPrime(newReader(seed+"-alt"), bits/2)
	}

	one := big.NewInt(1)
	e := big.NewInt(65537)
	for {
		// φ(n) = (p-1) * (q-1), d = e^(-1) mod φ(n)
		totient := new(big.Int).Mul(new(big.Int).Sub(p, one), new(big.Int).Sub(q, one))
		d := new(big.Int).ModInverse(e, totient)
		if d != nil {
			key := &rsa.PrivateKey{
				PublicKey: rsa.PublicKey{N: new(big.Int).Mul(p, q), E: 65537},
				D:         d,
				Primes:    []*big.Int{p, q},
			}
			key.Precompute()
			if err := key.Validate(); err != nil {
				return nil, err
			}
			return key, nil
		}
		// e divides φ(n): take the next prime from the same stream
		for {
			q = deterministicPrime(reader, bits/2)
			if p.Cmp(q) != 0 {
				break
			}
		}
	}
}

// deterministicPrime reads candidates from reader until one is prime.
func deterministicPrime(reader *customReader, bits int) *big.Int {
	for {
		candidate := oddNumber(reader, bits)
		if candidate.ProbablyPrime(40) {
			return candidate
		}
	}
}

// oddNumber reads an odd number of exactly bits bits.
func oddNumber(reader *customReader, bits int) *big.Int {
	buf := make([]byte, (bits+7)/8)
	reader.Read(buf)
	num := new(big.Int).SetBytes(buf)

	// старший бит для нужной битности, младший для нечётности
	num.SetBit(num, bits-1, 1)
	num.SetBit(num, 0, 1)

	// обрезаем до нужного количества битов
	mask := new(big.Int).Lsh(big.NewInt(1), uint(bits))
	mask.Sub(mask, big.NewInt(1))
	return num.And(num, mask)
}
