package jwt

import "errors"

// Algorithm, parse and other related errors.
var (
	// ErrInvalidKey indicates that key is not valid.
	ErrInvalidKey = errors.New("jwt: key is not valid")

	// ErrInvalidKey indicates that both keys are nil, which cannot be accepted.
	ErrBothKeysAreNil = errors.New("jwt: both keys cannot be nil")

	// ErrUnsupportedAlg indicates that given algorithm is not supported.
	ErrUnsupportedAlg = errors.New("jwt: algorithm is not supported")

	// ErrInvalidSignature indicates that signature is not valid.
	ErrInvalidSignature = errors.New("jwt: signature is not valid")

	// ErrInvalidFormat indicates that token format is not valid.
	ErrInvalidFormat = errors.New("jwt: token format is not valid")

	// ErrAlgorithmMismatch indicates that token is signed by another algorithm.
	ErrAlgorithmMismatch = errors.New("jwt: token is signed by another algorithm")

	// ErrAudienceInvalidFormat indicates that audience format is not valid.
	ErrAudienceInvalidFormat = errors.New("jwt: audience format is not valid")

	// ErrDateInvalidFormat indicates that date format is not valid.
	ErrDateInvalidFormat = errors.New("jwt: date is not valid")
)
