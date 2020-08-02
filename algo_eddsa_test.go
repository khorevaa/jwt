package jwt

import (
	"crypto/ed25519"
	"testing"
)

// example from RFC 8037, appendix A.1
var ed25519Private = ed25519.PrivateKey([]byte{
	0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
	0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
	0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
	0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
	// public key suffix
	0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
	0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
	0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
	0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
})

var ed25519Private2 = ed25519.PrivateKey([]byte{
	0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
	0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
	0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
	0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
	// public key suffix
	0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
	0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
	0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
	0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
})

// example from RFC 8037, appendix A.1
var ed25519Public = ed25519.PublicKey([]byte{
	0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
	0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
	0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
	0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
})

func TestEdDSA(t *testing.T) {
	f := func(alg Algorithm, claims interface{}) {
		t.Helper()

		tokenBuilder := NewBuilder(alg)
		token, err := tokenBuilder.Build(claims)
		if err != nil {
			t.Errorf("want nil, got %#v", err)
		}

		err = alg.Verify(token.Payload(), token.Signature())
		if err != nil {
			t.Errorf("want no err, got: %#v", err)
		}
	}

	f(
		mustAlgo(NewAlgorithmEdDSA(ed25519Private, ed25519Public)),
		&RegisteredClaims{},
	)

	f(
		mustAlgo(NewAlgorithmEdDSA(ed25519Private, ed25519Public)),
		&customClaims{
			TestField: "foo",
		},
	)
}

func TestEdDSA_InvalidSignature(t *testing.T) {
	f := func(alg Algorithm, claims interface{}) {
		t.Helper()

		tokenBuilder := NewBuilder(alg)
		token, err := tokenBuilder.Build(claims)
		if err != nil {
			t.Errorf("want nil, got %#v", err)
		}

		err = alg.Verify(token.Payload(), token.Signature())
		if err == nil {
			t.Errorf("want %#v, got nil", ErrInvalidSignature)
		}
	}

	f(
		mustAlgo(NewAlgorithmEdDSA(ed25519Private2, ed25519Public)),
		&RegisteredClaims{},
	)

	f(
		mustAlgo(NewAlgorithmEdDSA(ed25519Private2, ed25519Public)),
		&customClaims{
			TestField: "foo",
		},
	)
}
