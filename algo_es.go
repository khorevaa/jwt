package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"math/big"
)

// NewAlgorithmES returns a new ECDSA-based algorithm.
func NewAlgorithmES(alg AlgorithmName, private *ecdsa.PrivateKey, public *ecdsa.PublicKey) (Algorithm, error) {
	if private == nil || public == nil {
		return nil, errors.New("jwt: both keys cannot be nil")
	}

	hash, keySize, curveBits, err := getParamsES(alg)
	if err != nil {
		return nil, err
	}

	a := &esAlg{
		alg:        alg,
		hash:       hash,
		privateKey: private,
		publickey:  public,
		keySize:    keySize,
		curveBits:  curveBits,
	}
	return a, nil
}

// NewSignerES returns a new ECDSA-based signer.
func NewSignerES(alg AlgorithmName, key *ecdsa.PrivateKey) (Signer, error) {
	return NewAlgorithmES(alg, key, nil)
}

// NewVerifierES returns a new ECDSA-based verifier.
func NewVerifierES(alg AlgorithmName, key *ecdsa.PublicKey) (Verifier, error) {
	return NewAlgorithmES(alg, nil, key)
}

func getParamsES(alg AlgorithmName) (crypto.Hash, int, int, error) {
	switch alg {
	case ES256:
		return crypto.SHA256, 32, 256, nil
	case ES384:
		return crypto.SHA384, 48, 384, nil
	case ES512:
		return crypto.SHA512, 66, 521, nil
	default:
		return 0, 0, 0, ErrUnsupportedAlg
	}
}

type esAlg struct {
	alg        AlgorithmName
	hash       crypto.Hash
	publickey  *ecdsa.PublicKey
	privateKey *ecdsa.PrivateKey
	keySize    int
	curveBits  int
}

func (h esAlg) AlgorithmName() AlgorithmName {
	return h.alg
}

func (h esAlg) SignSize() int {
	return (h.privateKey.Curve.Params().BitSize + 7) / 4
}

func (h esAlg) Sign(payload []byte) ([]byte, error) {
	signed, err := h.sign(payload)
	if err != nil {
		return nil, err
	}

	r, s, err := ecdsa.Sign(rand.Reader, h.privateKey, signed)
	if err != nil {
		return nil, err
	}

	keyBytes := h.SignSize() / 2

	rBytes, sBytes := r.Bytes(), s.Bytes()
	signature := make([]byte, keyBytes*2)
	copy(signature[keyBytes-len(rBytes):], rBytes)
	copy(signature[keyBytes*2-len(sBytes):], sBytes)
	return signature, nil
}

func (h esAlg) Verify(payload, signature []byte) error {
	if len(signature) != 2*h.keySize {
		return ErrInvalidSignature
	}

	signed, err := h.sign(payload)
	if err != nil {
		return err
	}

	r := big.NewInt(0).SetBytes(signature[:h.keySize])
	s := big.NewInt(0).SetBytes(signature[h.keySize:])

	if !ecdsa.Verify(h.publickey, signed, r, s) {
		return ErrInvalidSignature
	}
	return nil
}

func (h esAlg) sign(payload []byte) ([]byte, error) {
	hasher := h.hash.New()

	_, err := hasher.Write(payload)
	if err != nil {
		return nil, err
	}
	signed := hasher.Sum(nil)
	return signed, nil
}
