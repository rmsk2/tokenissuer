package jwt

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
)

// Generate private key in PKCS8 format directly
// openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out private_key.pem
//
// Extract the public key
// openssl pkey -in private_key.pem -pubout -out public_key.pem

type Es256Signer struct {
	privateKey *ecdsa.PrivateKey
}

type Es256Verifier struct {
	publicKey *ecdsa.PublicKey
}

func NewEs256SignerVerified(raw []byte) (*Es256Signer, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("No correct PEM data")
	}

	priKeyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	priKey, ok := priKeyAny.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("Incorrect Private Key type")
	}

	return &Es256Signer{
		privateKey: priKey,
	}, nil
}

func NewEs256Signer(raw []byte) *Es256Signer {
	res, err := NewEs256SignerVerified(raw)
	if err != nil {
		panic(fmt.Errorf("Unable to parse private key: %v", err))
	}

	return res
}

func (e *Es256Signer) Sign(refVal []byte) []byte {
	h := sha256.New()
	h.Write([]byte(refVal))
	hash := h.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, e.privateKey, hash)
	if err != nil {
		panic(fmt.Errorf("Signature error: %v", err))
	}

	sig := r.FillBytes(make([]byte, 32))
	sig = append(sig, s.FillBytes(make([]byte, 32))...)

	return sig
}

func NewEs256VerifierVerified(raw []byte) (*Es256Verifier, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("No correct PEM data")
	}

	pubKeyAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	pubKey, ok := pubKeyAny.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("Incorrect Public Key type")
	}

	return &Es256Verifier{
		publicKey: pubKey,
	}, nil
}

func NewEs256Verifier(raw []byte) *Es256Verifier {
	res, err := NewEs256VerifierVerified(raw)
	if err != nil {
		panic(fmt.Errorf("Unable to parse public key: %v", err))
	}

	return res
}

func (e *Es256Verifier) Verify(refVal []byte, signature []byte) bool {
	if len(signature) != 64 {
		return false
	}

	h := sha256.New()
	h.Write([]byte(refVal))
	hash := h.Sum(nil)

	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])

	return ecdsa.Verify(e.publicKey, hash, r, s)
}

func NewEs256JwtSigner(raw []byte) *JwtSigner {
	t := NewEs256Signer(raw)
	return NewJwtSigner(AlgEs256, t)
}

func NewEs256JwtVerifier(raw []byte) *JwtVerifier {
	t := NewEs256Verifier(raw)
	return NewJwtVerifier(AlgEs256, t)
}
