package jwt

import (
	"crypto/ed25519"
	"errors"
)

// NewAlgorithmEdDSA returns a new ed25519-based algorithm.
func NewAlgorithmEdDSA(private ed25519.PrivateKey, public ed25519.PublicKey) (Algorithm, error) {
	if private == nil && public == nil {
		return nil, errors.New("jwt: both keys cannot be nil")
	}

	a := &edDSAAlg{
		privateKey: private,
		publicKey:  public,
	}
	return a, nil
}

// NewSignerEdDSA returns a new ed25519-based signer.
func NewSignerEdDSA(key ed25519.PrivateKey) (Signer, error) {
	return NewAlgorithmEdDSA(key, nil)
}

// NewVerifierEdDSA returns a new ed25519-based verifier.
func NewVerifierEdDSA(key ed25519.PublicKey) (Verifier, error) {
	return NewAlgorithmEdDSA(nil, key)
}

type edDSAAlg struct {
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
}

func (h edDSAAlg) AlgorithmName() AlgorithmName {
	return EdDSA
}

func (h edDSAAlg) SignSize() int {
	return ed25519.SignatureSize
}

func (h edDSAAlg) Sign(payload []byte) ([]byte, error) {
	return ed25519.Sign(h.privateKey, payload), nil
}

func (h edDSAAlg) Verify(payload, signature []byte) error {
	if !ed25519.Verify(h.publicKey, payload, signature) {
		return ErrInvalidSignature
	}
	return nil
}
