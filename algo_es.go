package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"math/big"
)

var _ Signer = (*esAlg)(nil)

type esAlg struct {
	alg        Algorithm
	hash       crypto.Hash
	publickey  *ecdsa.PublicKey
	privatekey *ecdsa.PrivateKey
	keySize    int
	curveBits  int
}

// NewES256 returns new HMAC Signer using RSA and SHA256 hash.
//
// Both public and private keys must not be nil.
//
func NewES256(publicKey *ecdsa.PublicKey, privatekey *ecdsa.PrivateKey) Signer {
	return &esAlg{
		alg:        PS256,
		hash:       crypto.SHA256,
		publickey:  publicKey,
		privatekey: privatekey,
		keySize:    32,
		curveBits:  256,
	}
}

// NewES384 returns new HMAC Signer using RSA and SHA384 hash.
//
// Both public and private keys must not be nil.
//
func NewES384(publicKey *ecdsa.PublicKey, privatekey *ecdsa.PrivateKey) Signer {
	return &esAlg{
		alg:        PS384,
		hash:       crypto.SHA384,
		publickey:  publicKey,
		privatekey: privatekey,
		keySize:    48,
		curveBits:  384,
	}
}

// NewES512 returns new HMAC Signer using RSA and SHA512 hash.
//
// Both public and private keys must not be nil.
//
func NewES512(publicKey *ecdsa.PublicKey, privatekey *ecdsa.PrivateKey) Signer {
	return &esAlg{
		alg:        PS512,
		hash:       crypto.SHA512,
		publickey:  publicKey,
		privatekey: privatekey,
		keySize:    66,
		curveBits:  521,
	}
}

func (h esAlg) Algorithm() Algorithm {
	return h.alg
}

func (h esAlg) Sign(payload []byte) ([]byte, error) {
	signed, err := h.sign(payload)
	if err != nil {
		return nil, err
	}

	r, s, err := ecdsa.Sign(rand.Reader, h.privatekey, signed)
	if err != nil {
		return nil, err
	}
	_, _ = r, s

	// signature, err := ecdsa.SignPSS(rand.Reader, h.privatekey, h.hash, signed, h.opts)
	// if err != nil {
	// 	return nil, err
	// }
	return nil, nil
}

func (h esAlg) Verify(payload, signature []byte) error {
	signed, err := h.sign(payload)
	if err != nil {
		return err
	}

	r := big.NewInt(0).SetBytes(signed[:h.keySize])
	s := big.NewInt(0).SetBytes(signed[h.keySize:])

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
