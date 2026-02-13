package jwt

import (
	"fmt"
	"strings"
	"testing"
)

const es256TestToken = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA"
const es256TestPubKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9
q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==
-----END PUBLIC KEY-----`

const priKeyRawTest string = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcxQjkAyuafpnzfAA
OLJRTsl5tguEdwqx1lA789+JDr6hRANCAAT0rtwTPkCRNKtnOjKDwG+F9UqY80Cf
+q4x11PmZciHqXXRhPlhlZmJYzJxLdoLxgXQzNLSXCHTUBepATQ/HsAc
-----END PRIVATE KEY-----`

const pubKeyRawTest string = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9K7cEz5AkTSrZzoyg8BvhfVKmPNA
n/quMddT5mXIh6l10YT5YZWZiWMycS3aC8YF0MzS0lwh01AXqQE0Px7AHA==
-----END PUBLIC KEY-----`

const hmacTestKey string = "a-string-secret-at-least-256-bits-long"
const hmacTestToken string = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30"

func TestVerifyEs256Token(t *testing.T) {
	verifier := NewEs256JwtVerifier([]byte(es256TestPubKey))

	claims, err := verifier.VerifyJwt(es256TestToken)

	if err != nil {
		t.Errorf("VerifyJwt failed: %v", err)
	}

	fmt.Printf("claims: %v\n", claims)
}

func TestVerifyHs256Token(t *testing.T) {
	verifier := NewHs256JwtVerifier([]byte(hmacTestKey))

	claims, err := verifier.VerifyJwt(hmacTestToken)
	if err != nil {
		t.Errorf("VerifyJwt failed: %v", err)
	}

	fmt.Printf("claims: %v\n", claims)
}

func TestVerifyEs256TokenFail(t *testing.T) {
	verifier := NewEs256JwtVerifier([]byte(es256TestPubKey))

	modifiedToken := strings.Builder{}
	modifiedToken.WriteString(string([]byte(es256TestToken)[:len(es256TestToken)-2]))
	modifiedToken.WriteByte(96)
	modifiedToken.WriteByte(65)
	modToken := modifiedToken.String()

	if len(modToken) != len(es256TestToken) {
		t.Errorf("Wrong test length")
	}

	_, err := verifier.VerifyJwt(modToken)

	if err == nil {
		t.Errorf("Invalid signature was verified successfully!")
	}
}

func TestVerifyHs256TokenFail(t *testing.T) {
	verifier := NewHs256JwtVerifier([]byte(hmacTestKey))

	modifiedToken := strings.Builder{}
	modifiedToken.WriteString(string([]byte(hmacTestToken)[:len(hmacTestToken)-2]))
	modifiedToken.WriteByte(96)
	modifiedToken.WriteByte(65)
	modToken := modifiedToken.String()

	if len(modToken) != len(hmacTestToken) {
		t.Errorf("Wrong test length")
	}

	_, err := verifier.VerifyJwt(modToken)

	if err == nil {
		t.Errorf("Invalid signature was verified successfully!")
	}
}

func TestCreateAndVerifyEs256Token(t *testing.T) {
	creator := NewEs256JwtSigner([]byte(priKeyRawTest))
	verifier := NewEs256JwtVerifier([]byte(pubKeyRawTest))

	claims := MakeClaims("Testsubject", "Testadience", "unit_test")
	token, err := creator.CreateJwt(claims)
	if err != nil {
		t.Errorf("Failure: %v", err)
	}

	parsedClaims, err := verifier.VerifyJwt(token)
	if err != nil {
		t.Errorf("Failure: %v", err)
	}

	subj, ok := parsedClaims["sub"]
	if !ok || subj != "Testsubject" {
		t.Errorf("Wrong subject")
	}

	aud, ok := parsedClaims["aud"]
	if !ok || aud != "Testadience" {
		t.Errorf("Wrong subject")
	}

	iss, ok := parsedClaims["iss"]
	if !ok || iss != "unit_test" {
		t.Errorf("Wrong subject")
	}
}

func TestCreateAndVerifyHs256Token(t *testing.T) {
	creator := NewHs256JwtSigner([]byte(hmacTestKey))
	verifier := NewHs256JwtVerifier([]byte(hmacTestKey))

	claims := MakeClaims("Testsubject", "Testadience", "unit_test")
	token, err := creator.CreateJwt(claims)
	if err != nil {
		t.Errorf("Failure: %v", err)
	}

	parsedClaims, err := verifier.VerifyJwt(token)
	if err != nil {
		t.Errorf("Failure: %v", err)
	}

	subj, ok := parsedClaims["sub"]
	if !ok || subj != "Testsubject" {
		t.Errorf("Wrong subject")
	}

	aud, ok := parsedClaims["aud"]
	if !ok || aud != "Testadience" {
		t.Errorf("Wrong subject")
	}

	iss, ok := parsedClaims["iss"]
	if !ok || iss != "unit_test" {
		t.Errorf("Wrong subject")
	}
}
