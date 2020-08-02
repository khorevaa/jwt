package jwt

import (
	"testing"
)

func TestPS256_WithValidSignature(t *testing.T) {
	f := func(alg Algorithm, claims interface{}) {
		t.Helper()

		tokenBuilder := NewBuilder(alg)
		token, _ := tokenBuilder.Build(claims)

		err := alg.Verify(token.Payload(), token.Signature())
		if err != nil {
			t.Errorf("want no err, got: %#v", err)
		}
	}

	f(
		mustAlgo(NewAlgorithmPS(PS256, rsaPrivateKey1, rsaPublicKey1)),
		&RegisteredClaims{},
	)
	f(
		mustAlgo(NewAlgorithmPS(PS384, rsaPrivateKey1, rsaPublicKey1)),
		&RegisteredClaims{},
	)
	f(
		mustAlgo(NewAlgorithmPS(PS512, rsaPrivateKey1, rsaPublicKey1)),
		&RegisteredClaims{},
	)

	f(
		mustAlgo(NewAlgorithmPS(PS256, rsaPrivateKey1, rsaPublicKey1)),
		&customClaims{
			TestField: "foo",
		},
	)
	f(
		mustAlgo(NewAlgorithmPS(PS384, rsaPrivateKey1, rsaPublicKey1)),
		&customClaims{
			TestField: "bar",
		},
	)
	f(
		mustAlgo(NewAlgorithmPS(PS512, rsaPrivateKey1, rsaPublicKey1)),
		&customClaims{
			TestField: "baz",
		},
	)
}

func TestPS384_WithInvalidSignature(t *testing.T) {
	f := func(alg Algorithm, claims interface{}) {
		t.Helper()

		tokenBuilder := NewBuilder(alg)
		token, _ := tokenBuilder.Build(claims)

		err := alg.Verify(token.Payload(), token.Signature())
		if err == nil {
			t.Errorf("want %v, got nil", ErrInvalidSignature)
		}
	}
	f(
		mustAlgo(NewAlgorithmPS(PS256, rsaPrivateKey1, rsaPublicKey2)),
		&RegisteredClaims{},
	)
	f(
		mustAlgo(NewAlgorithmPS(PS384, rsaPrivateKey1, rsaPublicKey2)),
		&RegisteredClaims{},
	)
	f(
		mustAlgo(NewAlgorithmPS(PS512, rsaPrivateKey1, rsaPublicKey2)),
		&RegisteredClaims{},
	)

	f(
		mustAlgo(NewAlgorithmPS(PS256, rsaPrivateKey1, rsaPublicKey2)),
		&customClaims{
			TestField: "foo",
		},
	)
	f(
		mustAlgo(NewAlgorithmPS(PS384, rsaPrivateKey1, rsaPublicKey2)),
		&customClaims{
			TestField: "bar",
		},
	)
	f(
		mustAlgo(NewAlgorithmPS(PS512, rsaPrivateKey1, rsaPublicKey2)),
		&customClaims{
			TestField: "baz",
		},
	)
}
