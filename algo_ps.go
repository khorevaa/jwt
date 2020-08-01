package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
)

// NewAlgorithmPS returns a new RSA-PSS-based algorithm.
func NewAlgorithmPS(alg AlgorithmName, private *rsa.PrivateKey, public *rsa.PublicKey) (Algorithm, error) {
	if private == nil && public == nil {
		return nil, errors.New("jwt: both keys cannot be nil")
	}

	hash, opts, err := getParamsPS(alg)
	if err != nil {
		return nil, err
	}

	a := &psAlg{
		alg:        alg,
		hash:       hash,
		privateKey: private,
		publicKey:  public,
		opts:       opts,
	}
	return a, nil
}

// NewSignerPS returns a new RSA-PSS-based signer.
func NewSignerPS(alg AlgorithmName, key *rsa.PrivateKey) (Signer, error) {
	return NewAlgorithmPS(alg, key, nil)
}

// NewVerifierPS returns a new RSA-PSS-based signer.
func NewVerifierPS(alg AlgorithmName, key *rsa.PublicKey) (Verifier, error) {
	return NewAlgorithmPS(alg, nil, key)
}

func getParamsPS(alg AlgorithmName) (crypto.Hash, *rsa.PSSOptions, error) {
	switch alg {
	case PS256:
		return crypto.SHA256, optsPS256, nil
	case PS384:
		return crypto.SHA384, optsPS384, nil
	case PS512:
		return crypto.SHA512, optsPS512, nil
	default:
		return 0, nil, ErrUnsupportedAlg
	}
}

var (
	optsPS256 = &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       crypto.SHA256,
	}

	optsPS384 = &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       crypto.SHA384,
	}

	optsPS512 = &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       crypto.SHA512,
	}
)

type psAlg struct {
	alg        AlgorithmName
	hash       crypto.Hash
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
	opts       *rsa.PSSOptions
}

func (h psAlg) SignSize() int {
	return h.privateKey.Size()
}

func (h psAlg) AlgorithmName() AlgorithmName {
	return h.alg
}

func (h psAlg) Sign(payload []byte) ([]byte, error) {
	signed, err := h.sign(payload)
	if err != nil {
		return nil, err
	}

	signature, err := rsa.SignPSS(rand.Reader, h.privateKey, h.hash, signed, h.opts)
	if err != nil {
		return nil, err
	}
	return signature, nil
}

func (h psAlg) Verify(payload, signature []byte) error {
	signed, err := h.sign(payload)
	if err != nil {
		return err
	}

	err = rsa.VerifyPSS(h.publicKey, h.hash, signed, signature, h.opts)
	if err != nil {
		return ErrInvalidSignature
	}
	return nil
}

func (h psAlg) sign(payload []byte) ([]byte, error) {
	hasher := h.hash.New()

	_, err := hasher.Write(payload)
	if err != nil {
		return nil, err
	}
	signed := hasher.Sum(nil)
	return signed, nil
}
