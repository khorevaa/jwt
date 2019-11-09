package jwt

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	t.Skip()
	f := func(raw string, want *Token, wantError bool) {

		token, err := ParseString(raw)
		if err != nil && !wantError {
			t.Fatalf("unexpected err %v", err)
		}
		if err == nil && wantError {
			t.Fatal("expected error")
		}

		dot1 := strings.IndexByte(raw, '.')
		dot2 := strings.LastIndexByte(raw, '.')
		gotHeader := raw[:dot1]
		// gotClaims := raw[dot1+1 : dot2]
		gotSignature := raw[dot2+1:]
		gotPayload := raw[:dot2]
		// t.Logf("head %#v\nclaims %#v\nsign %#v\npay %#v", gotHeader, gotClaims, gotSignature, gotPayload)

		if string(token.RawHeader()) != gotHeader {
			t.Errorf("raw header: got %v, want %v", string(token.RawHeader()), gotHeader)
		}
		if token.header != want.header {
			t.Errorf("header: got %v, want %v", token.header, want.header)
		}

		if string(token.Payload()) != gotPayload {
			t.Errorf("payload: got %v, want %v", string(token.Payload()), gotPayload)
		}

		if toBase64(string(token.Signature())) != gotSignature {
			t.Errorf("signature: got %v, want %v", toBase64(string(token.Signature())), (gotSignature))
		}
	}

	// f(
	// 	``,
	// 	&Token{},
	// 	true,
	// )
	// f(
	// 	`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhZG1pbiIsImp0aSI6InJhbmRvbS11bmlxdWUtc3RyaW5nIn0.dv9-XpY9P8ypm1uWQwB6eKvq3jeyodLA7brhjsf4JVs`,
	// 	&Token{
	// 		header: Header{
	// 			Algorithm: HS256,
	// 			Type:      "JWT",
	// 		},
	// 	},
	// 	false,
	// )
	// f(
	// 	`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhZG1pbiIsImp0aSI6InJhbmRvbS11bmlxdWUtc3RyaW5nIn0`,
	// 	&Token{},
	// 	true,
	// )
	f(
		`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhZG1pbi_LL_IsImp0aSI6InJhbmRvbS11bmlxdWUtc3RyaW5nIn0.dv9-XpY9P8ypm1uWQwB6eKvq3jeyodLA7brhjsf4JVs`,
		&Token{
			header: Header{
				Algorithm: HS256,
				Type:      "JWT",
			},
		},
		true,
	)
}
