package jwt

import "testing"

func TestSignerAlg(t *testing.T) {
	f := func(alg Algorithm, want AlgorithmName) {
		t.Helper()

		if alg := alg.AlgorithmName(); alg != want {
			t.Errorf("got %#v, want %#v", alg, want)
		}
	}

	hmacKey := []byte("key")
	f(mustAlgo(NewAlgorithmHS(HS256, hmacKey)), HS256)
	f(mustAlgo(NewAlgorithmHS(HS384, hmacKey)), HS384)
	f(mustAlgo(NewAlgorithmHS(HS512, hmacKey)), HS512)

	rsaPriv := rsaPrivateKey1
	f(mustAlgo(NewAlgorithmRS(RS256, rsaPriv, nil)), RS256)
	f(mustAlgo(NewAlgorithmRS(RS384, rsaPriv, nil)), RS384)
	f(mustAlgo(NewAlgorithmRS(RS512, rsaPriv, nil)), RS512)

	f(mustAlgo(NewAlgorithmPS(PS256, rsaPriv, nil)), PS256)
	f(mustAlgo(NewAlgorithmPS(PS384, rsaPriv, nil)), PS384)
	f(mustAlgo(NewAlgorithmPS(PS512, rsaPriv, nil)), PS512)

	ecdsaPriv := ecdsaPrivateKey256
	f(mustAlgo(NewAlgorithmES(ES256, ecdsaPriv, nil)), ES256)
	f(mustAlgo(NewAlgorithmES(ES384, ecdsaPriv, nil)), ES384)
	f(mustAlgo(NewAlgorithmES(ES512, ecdsaPriv, nil)), ES512)
}

func TestVerifierAlg(t *testing.T) {
	f := func(alg Algorithm, want AlgorithmName) {
		t.Helper()
		if alg := alg.AlgorithmName(); alg != want {
			t.Errorf("got %#v, want %#v", alg, want)
		}
	}

	hmacKey := []byte("key")
	f(mustAlgo(NewAlgorithmHS(HS256, hmacKey)), HS256)
	f(mustAlgo(NewAlgorithmHS(HS384, hmacKey)), HS384)
	f(mustAlgo(NewAlgorithmHS(HS512, hmacKey)), HS512)

	rsaPub := rsaPublicKey1
	f(mustAlgo(NewAlgorithmRS(RS256, nil, rsaPub)), RS256)
	f(mustAlgo(NewAlgorithmRS(RS384, nil, rsaPub)), RS384)
	f(mustAlgo(NewAlgorithmRS(RS512, nil, rsaPub)), RS512)

	f(mustAlgo(NewAlgorithmPS(PS256, nil, rsaPub)), PS256)
	f(mustAlgo(NewAlgorithmPS(PS384, nil, rsaPub)), PS384)
	f(mustAlgo(NewAlgorithmPS(PS512, nil, rsaPub)), PS512)

	ecdsaPub := ecdsaPublicKey256
	f(mustAlgo(NewAlgorithmES(ES256, nil, ecdsaPub)), ES256)
	f(mustAlgo(NewAlgorithmES(ES384, nil, ecdsaPub)), ES384)
	f(mustAlgo(NewAlgorithmES(ES512, nil, ecdsaPub)), ES512)
}

func TestAlgorithmErrOnNilKey(t *testing.T) {
	f := func(_ Algorithm, err error) {
		t.Helper()

		if err == nil {
			t.Error("should have an error")
		}
	}

	f(NewAlgorithmEdDSA(nil, nil))

	f(NewAlgorithmHS(HS256, nil))
	f(NewAlgorithmHS(HS384, nil))
	f(NewAlgorithmHS(HS512, nil))

	f(NewAlgorithmRS(RS256, nil, nil))
	f(NewAlgorithmRS(RS384, nil, nil))
	f(NewAlgorithmRS(RS512, nil, nil))

	f(NewAlgorithmES(ES256, nil, nil))
	f(NewAlgorithmES(ES384, nil, nil))
	f(NewAlgorithmES(ES512, nil, nil))

	f(NewAlgorithmPS(PS256, nil, nil))
	f(NewAlgorithmPS(PS384, nil, nil))
	f(NewAlgorithmPS(PS512, nil, nil))
}
