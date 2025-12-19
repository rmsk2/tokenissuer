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
	"tokenissuer/tools"
)

const tokIssFileRoot = "TOK_ISS_FILE_ROOT"
const tokIssAllowedAudiences = "TOK_ISS_ALLOWED_AUDIENCES"
const tokIssHmacSecret = "TOK_ISS_HMAC_SECRET"
const tokIssFileCert = "TOK_ISS_FILE_CERT"
const tokIssFileKey = "TOK_ISS_FILE_KEY"
const tokIssNameIssuer = "TOK_ISS_NAME"
const issuerVerb = "POST"

var fileNameRoot = "private-tls-ca.pem"
var fileNameCert = "server.crt"
var fileNameKey = "server.pem"
var issuerName = "daheim_token_issuer"
var hmacSecret = ""

type TokenResult struct {
	Token string `json:"token"`
}

type IssueRequest struct {
	IntendedAudience string `json:"audience"`
}

var allowedAudiences map[string]bool = map[string]bool{
	"gschmarri": true,
}

func registerHandlerWithCors(method string, url string, handler func(http.ResponseWriter, *http.Request)) {
	http.HandleFunc(fmt.Sprintf("%s %s", method, url), handler)
	http.HandleFunc(fmt.Sprintf("OPTIONS %s", url), corsFunc)
}

func corsFunc(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, Authorization, accept, origin, Cache-Control")
	w.Header().Set("Access-Control-Allow-Methods", fmt.Sprintf("%s, OPTIONS", issuerVerb))

	log.Print("CORS request answered")

	http.Error(w, "No Content", http.StatusNoContent)
}

func issuerFunc(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	tokenIssuer := tools.NewHs256Jwt([]byte(hmacSecret))
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

	audience := i.IntendedAudience

	if !allowedAudiences[audience] {
		log.Printf("Unknown audience '%s' wanted by user '%s'", audience, subject)
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	claims := tools.MakeClaims(subject, audience, issuerName)

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

	log.Printf("Issued JWT HMAC token for audience '%s' to '%s'", audience, subject)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Write([]byte(data))
}

func evalEnvironment() error {
	var ok bool
	hmacSecret, ok = os.LookupEnv(tokIssHmacSecret)
	if !ok {
		return fmt.Errorf("hmac secret not found in environment")
	}

	temp, ok := os.LookupEnv(tokIssNameIssuer)
	if ok {
		issuerName = temp
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

	temp, ok = os.LookupEnv(tokIssAllowedAudiences)
	if ok {
		allowedAudiences = map[string]bool{}

		for j := range strings.SplitSeq(temp, " ") {
			allowedAudiences[j] = true
		}
	}

	return nil
}

func main() {
	err := evalEnvironment()
	if err != nil {
		log.Fatal("Unable to eval environment: ", err)
	}

	log.Printf("Issuer name: '%s'", issuerName)
	log.Printf("Allowed audiences:")
	for i := range allowedAudiences {
		log.Println(i)
	}

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

	registerHandlerWithCors(issuerVerb, "/jwthmac/issue", issuerFunc)

	err = server.ListenAndServeTLS(fileNameCert, fileNameKey)
	if err != nil {
		panic(err)
	}
}
