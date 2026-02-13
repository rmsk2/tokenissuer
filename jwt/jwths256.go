package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
)

type Hs256 struct {
	hmacSecret []byte
}

func NewHs256(k []byte) *Hs256 {
	return &Hs256{
		hmacSecret: k,
	}
}

func (h *Hs256) Sign(refVal []byte) []byte {
	mac := hmac.New(sha256.New, h.hmacSecret)
	mac.Write([]byte(refVal))
	hmac := mac.Sum(nil)

	return hmac
}

func (h *Hs256) Verify(refVal []byte, signature []byte) bool {
	mac := hmac.New(sha256.New, h.hmacSecret)
	mac.Write([]byte(refVal))
	expectedMAC := mac.Sum(nil)

	return hmac.Equal(signature, expectedMAC)
}

func NewHs256JwtSigner(secret []byte) *JwtSigner {
	t := NewHs256(secret)
	return NewJwtSigner(AlgHs256, t)
}

func NewHs256JwtVerifier(secret []byte) *JwtVerifier {
	t := NewHs256(secret)
	return NewJwtVerifier(AlgHs256, t)
}
