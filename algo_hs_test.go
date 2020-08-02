package jwt

import (
	"testing"
)

func TestHMAC(t *testing.T) {
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
		mustAlgo(NewAlgorithmHS(HS256, []byte("key1"))),
		&RegisteredClaims{},
	)
	f(
		mustAlgo(NewAlgorithmHS(HS384, []byte("key2"))),
		&RegisteredClaims{},
	)
	f(
		mustAlgo(NewAlgorithmHS(HS512, []byte("key3"))),
		&RegisteredClaims{},
	)

	f(
		mustAlgo(NewAlgorithmHS(HS256, []byte("key1"))),
		&customClaims{
			TestField: "foo",
		},
	)
	f(
		mustAlgo(NewAlgorithmHS(HS384, []byte("key2"))),
		&customClaims{
			TestField: "bar",
		},
	)
	f(
		mustAlgo(NewAlgorithmHS(HS512, []byte("key3"))),
		&customClaims{
			TestField: "baz",
		},
	)
}

func TestHMAC_InvalidSignature(t *testing.T) {
	f := func(fn func([]byte) Algorithm, claims interface{}) {
		t.Helper()

		key1, key2 := []byte("key"), []byte("another-key")
		alg1 := fn(key1)
		alg2 := fn(key2)

		tokenBuilder := NewBuilder(alg1)
		token, err := tokenBuilder.Build(claims)
		if err != nil {
			t.Errorf("want nil, got %#v", err)
		}

		err = alg2.Verify(token.Payload(), token.Signature())
		if err == nil {
			t.Errorf("want %#v, got nil", ErrInvalidSignature)
		}
	}
	f(
		func(key []byte) Algorithm {
			return mustAlgo(NewAlgorithmHS(HS256, key))
		},
		&RegisteredClaims{},
	)
	f(
		func(key []byte) Algorithm {
			return mustAlgo(NewAlgorithmHS(HS384, key))
		},
		&RegisteredClaims{},
	)
	f(
		func(key []byte) Algorithm {
			return mustAlgo(NewAlgorithmHS(HS512, key))
		},
		&RegisteredClaims{},
	)

	f(
		func(key []byte) Algorithm {
			return mustAlgo(NewAlgorithmHS(HS256, key))
		},
		&customClaims{
			TestField: "foo",
		},
	)
	f(
		func(key []byte) Algorithm {
			return mustAlgo(NewAlgorithmHS(HS384, key))
		},
		&customClaims{
			TestField: "bar",
		},
	)
	f(
		func(key []byte) Algorithm {
			return mustAlgo(NewAlgorithmHS(HS512, key))
		},
		&customClaims{
			TestField: "baz",
		},
	)
}
