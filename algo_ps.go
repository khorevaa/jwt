package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
)

var _ Signer = (*psAlg)(nil)

type psAlg struct {
	alg        Algorithm
	hash       crypto.Hash
	publickey  *rsa.PublicKey
	privatekey *rsa.PrivateKey
	opts       *rsa.PSSOptions
}

// NewPS256 returns new HMAC Signer using RSA and SHA256 hash.
//
// Both public and private keys must not be nil.
//
func NewPS256(publicKey *rsa.PublicKey, privatekey *rsa.PrivateKey, opts *rsa.PSSOptions) Signer {
	return &psAlg{
		alg:        PS256,
		hash:       crypto.SHA256,
		publickey:  publicKey,
		privatekey: privatekey,
		opts:       opts,
	}
}

// NewPS384 returns new HMAC Signer using RSA and SHA384 hash.
//
// Both public and private keys must not be nil.
//
func NewPS384(publicKey *rsa.PublicKey, privatekey *rsa.PrivateKey, opts *rsa.PSSOptions) Signer {
	return &psAlg{
		alg:        PS384,
		hash:       crypto.SHA384,
		publickey:  publicKey,
		privatekey: privatekey,
		opts:       opts,
	}
}

// NewPS512 returns new HMAC Signer using RSA and SHA512 hash.
//
// Both public and private keys must not be nil.
//
func NewPS512(publicKey *rsa.PublicKey, privatekey *rsa.PrivateKey, opts *rsa.PSSOptions) Signer {
	return &psAlg{
		alg:        PS512,
		hash:       crypto.SHA512,
		publickey:  publicKey,
		privatekey: privatekey,
		opts:       opts,
	}
}

func (h psAlg) Algorithm() Algorithm {
	return h.alg
}

func (h psAlg) Sign(payload []byte) ([]byte, error) {
	signed, err := h.sign(payload)
	if err != nil {
		return nil, err
	}

	signature, err := rsa.SignPSS(rand.Reader, h.privatekey, h.hash, signed, h.opts)
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

	err = rsa.VerifyPSS(h.publickey, h.hash, signed, signature, h.opts)
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
