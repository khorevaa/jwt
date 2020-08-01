package jwt

import (
	_ "crypto/sha256" // to register a hash
	_ "crypto/sha512" // to register a hash
)

// Algorithm is a JWT sign and verify algorithm.
//
type Algorithm interface {
	Signer
	Verifier
}

// Signer is used to sign tokens.
type Signer interface {
	AlgorithmName() AlgorithmName
	SignSize() int
	Sign(payload []byte) ([]byte, error)
}

// Verifier is used to verify tokens.
type Verifier interface {
	AlgorithmName() AlgorithmName
	Verify(payload, signature []byte) error
}

// AlgorithmName for signing and verifying.
type AlgorithmName string

func (a AlgorithmName) String() string { return string(a) }

// AlgorithmName names for signing and verifying.
const (
	EdDSA AlgorithmName = "EdDSA"

	HS256 AlgorithmName = "HS256"
	HS384 AlgorithmName = "HS384"
	HS512 AlgorithmName = "HS512"

	RS256 AlgorithmName = "RS256"
	RS384 AlgorithmName = "RS384"
	RS512 AlgorithmName = "RS512"

	ES256 AlgorithmName = "ES256"
	ES384 AlgorithmName = "ES384"
	ES512 AlgorithmName = "ES512"

	PS256 AlgorithmName = "PS256"
	PS384 AlgorithmName = "PS384"
	PS512 AlgorithmName = "PS512"
)
