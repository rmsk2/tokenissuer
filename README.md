# Introduction

The idea behind this software is to issue an HMACed JWT to a calling client after a successfull mTLS authentication by that client.
This JWT can be used to add authentication to my mobile notifier project. `tokenissuer` can be deployed in a a kubernetes cluster. 
For this purpose `tokenissuer.yml` is provided which defines all non secret values. 

The secrets are expected to be stored in a separate file (let's call it for instance `secrets.yml`), which has to have the following
structure

```
apiVersion: v1
kind: Secret
metadata:
  name: token-secret
data:
  TOK_ISS_HMAC_SECRET: AAAAAAAAAAAAAAAAAAAAAAAAAA

---
apiVersion: v1
kind: Secret
metadata:
  name: token-tls
data:
  tls.crt: |
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    .
    .
    .
  tls.key: |
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    .
    .
    .
```

where `TOK_ISS_HMAC_SECRET` has to contain the HMAC key which is to be used to issue the JWT (see below). Add additional variables for additional secrets and reference them in the
`TOK_ISS_ENV_SECRETS` variable. `tls.crt` and `tls.key` should hold the TLS server certificate as well as the matching private key for the TLS server certificate of `tokenissuer` in PEM
format.

# Environment variables

Name | Sematics |
|-|-|
| `TOK_ISS_NAME` | The name to put as issuer (`iss` claim) into the JWT |
| `TOK_ISS_FILE_ROOT` | The name of a file which contains the root certificates which are allowed for client certs |
| `TOK_ISS_FILE_CERT` | The name of the file whch holds the server certificate (including possible intermediate CAs) |
| `TOK_ISS_FILE_KEY` | The name of a file which holds the private key of the server certificate |
| `TOK_ISS_ALLOWED_AUDIENCES` | A list of allowed audiences separated by blanks |
| `TOK_ISS_ENV_SECRETS`| A list separated by blanks which specifies the names of the environment variables which hold the secrets to use for the corresponding audiences. The first variable is used for the first audience given in `TOK_ISS_ALLOWED_AUDIENCES`, the second variable for the second audience and so on |

In my `tokenissuer.yml` I mount config maps and secrets as volumes in order to provide the files referenced via `TOK_ISS_FILE_ROOT`, 
`TOK_ISS_FILE_CERT` and `TOK_ISS_FILE_KEY` to the kubernetes pod.

# Additional information

This service uses TLS client authentication which happens during the establishment of a TLS connection. For this reason
using mTLS is a kind of all or nothing approach to authentication, i.e. either all TLS-traffic in a connection uses it or no traffic 
uses it. In addition `tokenissuer` must not delegate TLS termination to an ingress. If this would be the case the issuer would be accessible
within the kuberenetes cluster without authentication. For these reasons I wanted to isolate this functionality in a separate service which
can be called by any client who needs a JWT.

As the service consuming the issued JWT is different from `tokenissuer` and because `tokenisser` can not be "hidden" behind an
ingress to create the illusion that it has the same origin as the consuming service it is necessary that `tokenissuer` can be called
via CORS.

As I have found out combining CORS with TLS client authentication creates compatibility issues.  As far as I have understood the whole
situation the CORS specfication states that pre-flight CORS requests should not be using credentials, i.e. credentials like for instance 
a TLS certificate used for client authentication. If the CORS request is successfull the "real" request then has to include credentials.
Within the confines of the go standard library I have not found a possibility to let the CORS request pass without TLS client auth while
at the same time reliably enforcing that the "real" request always uses TLS client auth.

Interestingly enough as of December 2025 Firefox (in contrast to Chrome and Safari) is the only browser which interprets CORS in this strict
sense and refuses to use mTLS for pre-flight CORS requests. But it offers a config entry called `network.cors_preflight.allow_client_cert`
which if set to `true` in `about:config` makes Firefox behave like the rest of the browsers. Therefore if you want to use `tokenissuer`
with Firefox you have to turn on this feature.

# Calling the service

You have to do a `POST` request to the path `/jwthmac/issue` with a JSON structure of the following form as a body:

```
{
    "audience": "dummy"
}
```

The value given will become part of the JWT as the `aud` claim. In case of success the following JSON data will be returned

```
{
    "token": "dfkjlfgjldkfjglkdfjgljerotigjhoh45nzr895z85z45z......."
}
```

The body of the token has the following format

```
{
  "aud": "dummy",
  "iat": 1766084882,
  "sub": "Martin2",
  "iss": "daheim_token_issuer",
  "flags": 0
}
```

The `flags` value is at the moment unused but is intended to encode additional attributes of the authenticated user. The value contained
in `iss` can be cofigured through the environment variable `TOK_ISS_NAME`. The value `sub` is taken from the common name of the client
certificate.

# mTLS and older IPads

I made the experience that an IPad Pro bought in 2016 (using IPad OS 17) only allows to import a client certificate if the RSA key size is
at maximum 2048 bits and (when using `openssl pkcs12`) if the PFX file was generated with the `-legacy` flag.

# Running the token issuer during development

In its simplest form you can run the token issuer using the following command

```
TOK_ISS_ALLOWED_AUDIENCES="dummy" TOK_ISS_ENV_SECRETS="TOK_ISS_HMAC_SECRET" TOK_ISS_HMAC_SECRET=a-string-secret-at-least-256-bits-long  ./tokenissuer
```

Of course you will still need a valid TLS server certificate for the machine which you use during development. Which can of course be issued
by a private CA run by yourself. Maybe even with the help of [minica](https://github.com/rmsk2/minica).