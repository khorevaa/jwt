package jwt

import (
	"encoding/base64"
	"errors"
	"testing"
)

func TestBuild(t *testing.T) {
	f := func(alg Algorithm, claims interface{}, want string) {
		t.Helper()

		token, err := Build(alg, claims)
		if err != nil {
			t.Error(err)
		}

		raw := string(token.Bytes())
		if raw != want {
			t.Errorf("want %v,\n got %v", want, raw)
		}
	}

	f(
		mustAlgo(NewAlgorithmHS(HS256, []byte("test-key-256"))),
		&RegisteredClaims{
			ID:       "just an id",
			Audience: Audience([]string{"audience"}),
		},
		`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJqdXN0IGFuIGlkIiwiYXVkIjoiYXVkaWVuY2UifQ.t5oEdZGp0Qbth7lo5fZlV_o4-r9gMoYBSktXbarjWoo`,
	)
}

func TestBuildHeader(t *testing.T) {
	f := func(alg Algorithm, header Header, want string) {
		t.Helper()

		token, err := NewBuilder(alg).Build(&RegisteredClaims{})
		if err != nil {
			t.Error(err)
		}

		want = toBase64(want)
		raw := string(token.RawHeader())
		if raw != want {
			t.Errorf("\nwant %v,\n got %v", want, raw)
		}
	}

	key := []byte("key")
	f(
		mustAlgo(NewAlgorithmHS(HS256, key)),
		Header{Algorithm: HS256, Type: "JWT"},
		`{"alg":"HS256","typ":"JWT"}`,
	)
	f(
		mustAlgo(NewAlgorithmHS(HS384, key)),
		Header{Algorithm: HS384, Type: "JWT"},
		`{"alg":"HS384","typ":"JWT"}`,
	)
	f(
		mustAlgo(NewAlgorithmHS(HS512, key)),
		Header{Algorithm: HS512, Type: "JWT"},
		`{"alg":"HS512","typ":"JWT"}`,
	)

	f(
		mustAlgo(NewAlgorithmRS(RS256, rsaPrivateKey1, nil)),
		Header{Algorithm: RS256, Type: "JWT"},
		`{"alg":"RS256","typ":"JWT"}`,
	)
	f(
		mustAlgo(NewAlgorithmRS(RS384, rsaPrivateKey1, nil)),
		Header{Algorithm: RS384, Type: "JWT"},
		`{"alg":"RS384","typ":"JWT"}`,
	)
	f(
		mustAlgo(NewAlgorithmRS(RS512, rsaPrivateKey1, nil)),
		Header{Algorithm: RS512, Type: "JWT"},
		`{"alg":"RS512","typ":"JWT"}`,
	)
}

func TestBuildMalformed(t *testing.T) {
	f := func(alg Algorithm, claims interface{}) {
		t.Helper()

		_, err := Build(alg, claims)
		if err == nil {
			t.Error("want err, got nil")
		}
	}

	f(
		badSigner{},
		nil,
	)
	f(
		mustAlgo(NewAlgorithmHS(HS256, []byte("test-key"))),
		badSigner.AlgorithmName,
	)
}

func toBase64(s string) string {
	buf := make([]byte, base64EncodedLen(len(s)))
	base64.RawURLEncoding.Encode(buf, []byte(s))
	return string(buf)
}

type badSigner struct{}

func (badSigner) SignSize() int {
	return 0
}
func (badSigner) AlgorithmName() AlgorithmName {
	return "bad"
}
func (badSigner) Sign(payload []byte) ([]byte, error) {
	return nil, errors.New("error by design")
}
func (badSigner) Verify(payload, signature []byte) error {
	return errors.New("error by design")
}
