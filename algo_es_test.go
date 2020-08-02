package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

var ecdsaPublicKey256 *ecdsa.PublicKey
var ecdsaPublicKey384 *ecdsa.PublicKey
var ecdsaPublicKey521 *ecdsa.PublicKey
var ecdsaPrivateKey256 *ecdsa.PrivateKey
var ecdsaPrivateKey384 *ecdsa.PrivateKey
var ecdsaPrivateKey521 *ecdsa.PrivateKey

var ecdsaOtherPublicKey256 *ecdsa.PublicKey
var ecdsaOtherPublicKey384 *ecdsa.PublicKey
var ecdsaOtherPublicKey521 *ecdsa.PublicKey
var ecdsaOtherPrivateKey256 *ecdsa.PrivateKey
var ecdsaOtherPrivateKey384 *ecdsa.PrivateKey
var ecdsaOtherPrivateKey521 *ecdsa.PrivateKey

func init() {
	ecdsaPrivateKey256, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecdsaPublicKey256 = &ecdsaPrivateKey256.PublicKey

	ecdsaPrivateKey384, _ = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	ecdsaPublicKey384 = &ecdsaPrivateKey384.PublicKey

	ecdsaPrivateKey521, _ = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	ecdsaPublicKey521 = &ecdsaPrivateKey521.PublicKey

	ecdsaOtherPrivateKey256, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecdsaOtherPublicKey256 = &ecdsaOtherPrivateKey256.PublicKey

	ecdsaOtherPrivateKey384, _ = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	ecdsaOtherPublicKey384 = &ecdsaOtherPrivateKey384.PublicKey

	ecdsaOtherPrivateKey521, _ = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	ecdsaOtherPublicKey521 = &ecdsaOtherPrivateKey521.PublicKey
}

func TestES256_WithValidSignature(t *testing.T) {
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
		mustAlgo(NewAlgorithmES(ES256, ecdsaPrivateKey256, ecdsaPublicKey256)),
		&RegisteredClaims{},
	)
	f(
		mustAlgo(NewAlgorithmES(ES384, ecdsaPrivateKey384, ecdsaPublicKey384)),
		&RegisteredClaims{},
	)
	f(
		mustAlgo(NewAlgorithmES(ES512, ecdsaPrivateKey521, ecdsaPublicKey521)),
		&RegisteredClaims{},
	)

	f(
		mustAlgo(NewAlgorithmES(ES256, ecdsaPrivateKey256, ecdsaPublicKey256)),
		&customClaims{
			TestField: "foo",
		},
	)
	f(
		mustAlgo(NewAlgorithmES(ES384, ecdsaPrivateKey384, ecdsaPublicKey384)),
		&customClaims{
			TestField: "bar",
		},
	)
	f(
		mustAlgo(NewAlgorithmES(ES512, ecdsaPrivateKey521, ecdsaPublicKey521)),
		&customClaims{
			TestField: "baz",
		},
	)
}

func TestES384_WithInvalidSignature(t *testing.T) {
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
		mustAlgo(NewAlgorithmES(ES256, ecdsaPrivateKey256, ecdsaOtherPublicKey256)),
		&RegisteredClaims{},
	)
	f(
		mustAlgo(NewAlgorithmES(ES384, ecdsaPrivateKey384, ecdsaOtherPublicKey384)),
		&RegisteredClaims{},
	)
	f(
		mustAlgo(NewAlgorithmES(ES512, ecdsaPrivateKey521, ecdsaOtherPublicKey521)),
		&RegisteredClaims{},
	)

	f(
		mustAlgo(NewAlgorithmES(ES256, ecdsaPrivateKey256, ecdsaOtherPublicKey256)),
		&customClaims{
			TestField: "foo",
		},
	)
	f(
		mustAlgo(NewAlgorithmES(ES384, ecdsaPrivateKey384, ecdsaOtherPublicKey384)),
		&customClaims{
			TestField: "bar",
		},
	)
	f(
		mustAlgo(NewAlgorithmES(ES512, ecdsaPrivateKey521, ecdsaOtherPublicKey521)),
		&customClaims{
			TestField: "baz",
		},
	)
}
