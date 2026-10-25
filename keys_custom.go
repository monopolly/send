package send

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"math/big"
)

type customReader struct {
	seed    []byte
	counter uint64
	buffer  []byte
	hasher  hash.Hash
}

func newReader(seed string) *customReader {
	return &customReader{
		seed:    []byte(seed),
		counter: 0,
		buffer:  make([]byte, 0),
		hasher:  sha256.New(),
	}
}

func (dr *customReader) Read(p []byte) (n int, err error) {
	needed := len(p)

	for len(dr.buffer) < needed {
		dr.hasher.Reset()
		dr.hasher.Write(dr.seed)
		binary.Write(dr.hasher, binary.BigEndian, dr.counter)
		dr.counter++

		newData := dr.hasher.Sum(nil)
		dr.buffer = append(dr.buffer, newData...)
	}

	n = copy(p, dr.buffer[:needed])
	dr.buffer = dr.buffer[needed:]
	return n, nil
}

// генерирует детерминированный RSA ключ
func customPrivateKey(seed string, bits int) (*rsa.PrivateKey, error) {
	if bits < 512 {
		return nil, fmt.Errorf("key size too small: %d", bits)
	}

	reader := newReader(seed)

	// Генерируем два простых числа детерминированно
	p, err := generateDeterministicPrime(reader, bits/2)
	if err != nil {
		return nil, err
	}

	q, err := generateDeterministicPrime(reader, bits/2)
	if err != nil {
		return nil, err
	}

	// Убеждаемся, что p != q
	if p.Cmp(q) == 0 {
		// Если совпали, генерируем новое q с другим seed
		reader2 := newReader(seed + "-alt")
		q, err = generateDeterministicPrime(reader2, bits/2)
		if err != nil {
			return nil, err
		}
	}

	// Вычисляем модуль n = p * q
	n := new(big.Int).Mul(p, q)

	// Вычисляем функцию Эйлера φ(n) = (p-1) * (q-1)
	pMinus1 := new(big.Int).Sub(p, big.NewInt(1))
	qMinus1 := new(big.Int).Sub(q, big.NewInt(1))
	totient := new(big.Int).Mul(pMinus1, qMinus1)

	// Выбираем публичную экспоненту (обычно 65537)
	e := big.NewInt(65537)

	// Вычисляем приватную экспоненту d = e^(-1) mod φ(n)
	d := new(big.Int).ModInverse(e, totient)
	if d == nil {
		return nil, fmt.Errorf("failed to compute modular inverse")
	}

	// Предварительно вычисляем китайские коэффициенты для оптимизации
	dp := new(big.Int).Mod(d, pMinus1)
	dq := new(big.Int).Mod(d, qMinus1)
	qinv := new(big.Int).ModInverse(q, p)

	return &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: n,
			E: 65537,
		},
		D:      d,
		Primes: []*big.Int{p, q},
		Precomputed: rsa.PrecomputedValues{
			Dp:        dp,
			Dq:        dq,
			Qinv:      qinv,
			CRTValues: []rsa.CRTValue{},
		},
	}, nil
}

// generateDeterministicPrime генерирует детерминированное простое число
func generateDeterministicPrime(reader io.Reader, bits int) (*big.Int, error) {
	if bits < 2 {
		return nil, fmt.Errorf("prime size must be at least 2 bits")
	}

	// Создаем детерминированный источник на основе reader
	dr := reader.(*customReader)

	for {
		// Генерируем кандидата в простые числа
		candidate, err := generateOddNumber(dr, bits)
		if err != nil {
			return nil, err
		}

		// Проверяем на простоту
		if candidate.ProbablyPrime(40) { // 40 итераций для высокой уверенности
			return candidate, nil
		}
	}
}

// generateOddNumber генерирует нечетное число заданной битности
func generateOddNumber(reader *customReader, bits int) (*big.Int, error) {
	if bits < 2 {
		return nil, fmt.Errorf("number of bits must be at least 2")
	}

	// Вычисляем сколько байт нужно
	byteLen := (bits + 7) / 8

	// Читаем случайные байты
	buf := make([]byte, byteLen)
	_, err := reader.Read(buf)
	if err != nil {
		return nil, err
	}

	// Создаем big.Int из байтов
	num := new(big.Int).SetBytes(buf)

	// Устанавливаем старший бит в 1 (чтобы обеспечить нужную битность)
	num.Or(num, new(big.Int).Lsh(big.NewInt(1), uint(bits-1)))

	// Устанавливаем младший бит в 1 (делаем нечетным)
	num.Or(num, big.NewInt(1))

	// Обрезаем до нужного количества битов
	mask := new(big.Int).Lsh(big.NewInt(1), uint(bits))
	mask.Sub(mask, big.NewInt(1))
	num.And(num, mask)

	return num, nil
}
