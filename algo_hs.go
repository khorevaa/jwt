package jwt

import (
	"crypto"
	"crypto/hmac"
	"hash"
	"sync"
)

// NewAlgorithmHS returns a new HMAC-based algorithm.
func NewAlgorithmHS(alg AlgorithmName, key []byte) (Algorithm, error) {
	if len(key) == 0 {
		return nil, ErrInvalidKey
	}

	hash, err := getHashHMAC(alg)
	if err != nil {
		return nil, err
	}

	a := &hsAlg{
		alg:  alg,
		hash: hash,
		key:  key,
		hashPool: &sync.Pool{New: func() interface{} {
			return hmac.New(hash.New, key)
		}},
	}
	return a, nil
}

func getHashHMAC(alg AlgorithmName) (crypto.Hash, error) {
	switch alg {
	case HS256:
		return crypto.SHA256, nil
	case HS384:
		return crypto.SHA384, nil
	case HS512:
		return crypto.SHA512, nil
	default:
		return 0, ErrUnsupportedAlg
	}
}

type hsAlg struct {
	alg      AlgorithmName
	hash     crypto.Hash
	key      []byte
	hashPool *sync.Pool
}

func (h hsAlg) AlgorithmName() AlgorithmName {
	return h.alg
}

func (h hsAlg) SignSize() int {
	return h.hash.Size()
}

func (h hsAlg) Sign(payload []byte) ([]byte, error) {
	return h.sign(payload)
}

func (h hsAlg) Verify(payload, signature []byte) error {
	if len(signature) != h.SignSize() {
		return ErrInvalidSignature
	}
	signed, err := h.sign(payload)
	if err != nil {
		return err
	}
	if !hmac.Equal(signature, signed) {
		return ErrInvalidSignature
	}
	return nil
}

func (h hsAlg) sign(payload []byte) ([]byte, error) {
	hasher := h.hashPool.Get().(hash.Hash)
	defer func() {
		hasher.Reset()
		h.hashPool.Put(hasher)
	}()

	_, err := hasher.Write(payload)
	if err != nil {
		return nil, err
	}
	return hasher.Sum(nil), nil
}
