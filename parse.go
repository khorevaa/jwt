package jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
)

var base64Decode = base64.RawURLEncoding.Decode

// ParseString decodes a token.
func ParseString(token string) (*Token, error) {
	return Parse([]byte(token))
}

// Parse decodes a token from a raw bytes.
func Parse(token []byte) (*Token, error) {
	dot1 := bytes.IndexByte(token, '.')
	dot2 := bytes.LastIndexByte(token, '.')
	if dot2 <= dot1 {
		return nil, ErrInvalidFormat
	}

	buf := make([]byte, len(token))

	headerN, err := base64Decode(buf, token[:dot1])
	if err != nil {
		return nil, ErrInvalidFormat
	}

	claimsN, err := base64Decode(buf[headerN:], token[dot1+1:dot2])
	if err != nil {
		return nil, ErrInvalidFormat
	}
	//claims := buf[headerN : headerN+claimsN]

	signN, err := base64Decode(buf[headerN+claimsN:], token[dot2+1:])
	if err != nil {
		return nil, ErrInvalidFormat
	}
	signature := buf[headerN+claimsN : headerN+claimsN+signN]

	var header Header
	if err := json.Unmarshal(buf[:headerN], &header); err != nil {
		return nil, ErrInvalidFormat
	}

	tok := &Token{
		raw:       token,
		payload:   token[:dot2],
		signature: signature,
		header:    header,
		//claims:    claims,
	}
	return tok, nil
}

// ParseAndVerifyString decodes a token and verifies it's signature.
func ParseAndVerifyString(token string, alg Algorithm) (*Token, error) {
	return ParseAndVerify([]byte(token), alg)
}

// ParseAndVerify decodes a token and verifies it's signature.
func ParseAndVerify(token []byte, alg Algorithm) (*Token, error) {
	tok, err := Parse(token)
	if err != nil {
		return nil, err
	}
	if tok.Header().Algorithm != alg.AlgorithmName() {
		return nil, ErrAlgorithmMismatch
	}
	if err := alg.Verify(tok.Payload(), tok.Signature()); err != nil {
		return nil, err
	}
	return tok, nil
}
