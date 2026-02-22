package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"tokenissuer/jwt"

	httpSwagger "github.com/swaggo/http-swagger/v2"
)

const programVersion = "1.3.0"
const tokIssFileRoot = "TOK_ISS_FILE_ROOT"
const tokIssAllowedAudiences = "TOK_ISS_ALLOWED_AUDIENCES"

const tokIssFileCert = "TOK_ISS_FILE_CERT"
const tokIssFileKey = "TOK_ISS_FILE_KEY"
const tokIssNameIssuer = "TOK_ISS_NAME"
const tokIssuerSecrets = "TOK_ISS_ENV_SECRETS"
const tokIssuerType = "TOK_ISS_TYPE"
const issuerVerb = "POST"

var fileNameRoot = "private-tls-ca.pem"
var fileNameCert = "server.crt"
var fileNameKey = "server.pem"
var issuerName = "daheim_token_issuer"

const issuerPath = "/jwt/issue"

var globalIssuerGen jwt.SignerGen = jwt.NewHs256JwtSigner
var globalAlgoToUse = jwt.AlgHs256
var secretMap map[string][]byte = map[string][]byte{}
var allowedAudiences map[string]bool = map[string]bool{}

type TokenResult struct {
	Token string `json:"token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
}

type IssueRequest struct {
	IntendedAudience string `json:"audience"  example:"myservice"`
	Algorithm        string `json:"algorithm" example:"HS256" enums:"HS256,HS384,ES256,ES384"`
}

func registerHandlerWithCors(method string, url string, handlerWithIssuerFunc func(http.ResponseWriter, *http.Request, jwt.SignerGen), genIssuerFunc jwt.SignerGen) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		handlerWithIssuerFunc(w, r, genIssuerFunc)
	}

	http.HandleFunc(fmt.Sprintf("%s %s", method, url), handler)
	corsHandler := func(w http.ResponseWriter, r *http.Request) {
		corsFunc(w, r, method)
	}
	http.HandleFunc(fmt.Sprintf("OPTIONS %s", url), corsHandler)
}

func corsFunc(w http.ResponseWriter, _ *http.Request, method string) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, Authorization, accept, origin, Cache-Control")
	w.Header().Set("Access-Control-Allow-Methods", fmt.Sprintf("%s, OPTIONS", method))

	log.Print("CORS request answered")

	http.Error(w, "No Content", http.StatusNoContent)
}

// @Summary     Issue JWT
// @Description Issues a signed JWT. The `algorithm` field must match the server's configured algorithm (TOK_ISS_TYPE).
// @Tags        token
// @Accept      json
// @Produce     json
// @Param       request body IssueRequest true "Issue request"
// @Success     200 {object} TokenResult
// @Failure     400 {string} string "Invalid request or algorithm mismatch"
// @Failure     500 {string} string "Internal error"
// @Router      /jwt/issue [post]
func issuerFunc(w http.ResponseWriter, r *http.Request, genIssuer jwt.SignerGen) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	// There has to be a client cert as we use ClientAuth: tls.RequireAndVerifyClientCert in
	// tlsConfig
	subject := r.TLS.PeerCertificates[0].Subject.CommonName

	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Println("Unable to read body")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var i IssueRequest
	err = json.Unmarshal(body, &i)
	if err != nil {
		log.Printf("Unable to parse body: '%s'", string(body))
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if i.Algorithm != globalAlgoToUse {
		log.Printf("Algorithm mismatch: requested '%s', configured '%s'", i.Algorithm, globalAlgoToUse)
		http.Error(w, "Algorithm mismatch", http.StatusBadRequest)
		return
	}

	audience := i.IntendedAudience

	if !allowedAudiences[audience] {
		log.Printf("Unknown audience '%s' wanted by user '%s'", audience, subject)
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	secret, ok := secretMap[audience]
	if !ok {
		log.Printf("No secret found for audience: %s", audience)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	tokenIssuer := genIssuer(secret)
	claims := jwt.MakeClaims(subject, audience, issuerName)

	token, err := tokenIssuer.CreateJwt(claims)
	if err != nil {
		log.Printf("Unable to create JWT: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	result := TokenResult{
		Token: token,
	}

	data, err := json.Marshal(&result)
	if err != nil {
		log.Printf("Error serializing response: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	log.Printf("Issued JWT for audience '%s' to '%s'", audience, subject)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Write([]byte(data))
}

func evalEnvironment() error {
	var ok bool

	temp, ok := os.LookupEnv(tokIssNameIssuer)
	if ok {
		issuerName = temp
	}

	temp, ok = os.LookupEnv(tokIssuerType)
	if ok {
		switch temp {
		case jwt.AlgEs256:
			globalIssuerGen = jwt.NewEs256JwtSigner
			globalAlgoToUse = jwt.AlgEs256
		case jwt.AlgEs384:
			globalIssuerGen = jwt.NewEs384JwtSigner
			globalAlgoToUse = jwt.AlgEs384
		case jwt.AlgHs384:
			globalIssuerGen = jwt.NewHs384JwtSigner
			globalAlgoToUse = jwt.AlgHs384
		default:
			globalIssuerGen = jwt.NewHs256JwtSigner
		}
	}

	temp, ok = os.LookupEnv(tokIssFileRoot)
	if ok {
		fileNameRoot = temp
	}

	temp, ok = os.LookupEnv(tokIssFileCert)
	if ok {
		fileNameCert = temp
	}

	temp, ok = os.LookupEnv(tokIssFileKey)
	if ok {
		fileNameKey = temp
	}

	tempAudiences, ok := os.LookupEnv(tokIssAllowedAudiences)
	if !ok {
		return fmt.Errorf("no list of audiences found")
	}
	allowedAudiencesList := strings.Split(tempAudiences, " ")

	tempSecretsEnvVars, ok := os.LookupEnv(tokIssuerSecrets)
	if !ok {
		return fmt.Errorf("no list of secrets found")
	}
	secretsEnvVarList := strings.Split(tempSecretsEnvVars, " ")

	if len(allowedAudiencesList) != len(secretsEnvVarList) {
		return fmt.Errorf("number of allowed audiences and number of secrets differs")
	}

	allowedAudiences = map[string]bool{}
	secretMap = map[string][]byte{}

	for i := range len(allowedAudiencesList) {
		aud := allowedAudiencesList[i]
		secEnvVar := secretsEnvVarList[i]

		allowedAudiences[aud] = true

		s, ok := os.LookupEnv(secEnvVar)
		if !ok {
			return fmt.Errorf("enviroment variable '%s' not found", secEnvVar)
		}

		bytesSecret := []byte(s)
		secretMap[aud] = bytesSecret

		if (globalAlgoToUse == jwt.AlgEs256) || (globalAlgoToUse == jwt.AlgEs384) {
			_, err := jwt.LoadEcdsaPrivateKey(bytesSecret)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// @title       Token Issuer API
// @version     1.3.0
// @description Issues signed JWTs to mTLS-authenticated clients.
// @description The client certificate CN becomes the `sub` claim.
// @description The signing algorithm is server-configured via TOK_ISS_TYPE; the client must specify the same algorithm in the request.
// @description All connections require mTLS. "Try it out" works if a client cert is installed in your browser/OS cert store.
func main() {
	err := evalEnvironment()
	if err != nil {
		log.Fatal("Unable to eval environment: ", err)
	}

	log.Printf("Version: %s", programVersion)
	log.Printf("Issuer name: '%s'", issuerName)
	log.Printf("Allowed audiences:")
	for i := range allowedAudiences {
		log.Println(i)
	}
	log.Printf("Signature algorithm: %s", globalAlgoToUse)

	caCert, err := os.ReadFile(fileNameRoot)
	if err != nil {
		log.Fatal("Error reading root certificate: ", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		log.Fatal("Failed to parse root certificate")
	}

	tlsConfig := &tls.Config{
		ClientCAs:  caCertPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS12,
	}

	server := &http.Server{
		Addr:      ":4443",
		TLSConfig: tlsConfig,
	}

	http.HandleFunc("/swagger/", httpSwagger.Handler(
		httpSwagger.URL("/swagger/doc.json"),
	))
	registerHandlerWithCors(issuerVerb, issuerPath, issuerFunc, globalIssuerGen)

	err = server.ListenAndServeTLS(fileNameCert, fileNameKey)
	if err != nil {
		panic(err)
	}
}
