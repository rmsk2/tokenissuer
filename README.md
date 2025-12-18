# Introduction

The idea behind this software is to issue an HMACed JWT to a calling client after a successfull mTLS authentication by that client.
In the medium term this is intended to add JWT authentication to my mobile notifier project. `tokenissuer` can be deployed in a
a kubernetes cluster. For this purpose `tokenissuer.yml` is provided which defines all non secret values. 

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

where `TOK_ISS_HMAC_SECRET` has to contain the HMAC key which is to be used to issue the JWT. `tls.crt` and `tls.key` should
hold the TLS server certificate as well as the matching private key for the TLS server certificate of `tokenissuer` in PEM format.

# Additional information

This service uses TLS client authentication which happens during the establishment of a TLS connection. For this reason
using mTLS is a kind of all or nothing approach to authentication, i.e. either all TLS-traffic uses it or no traffic uses it. In addition
`tokenissuer` must not delegate TLS termination to an ingress. For these reasons I wanted to isolate this functionality in a separate
service which can be called by any client who needs a JWT.

As the service consuming the issued JWT is different from `tokenissuer` and because `tokenisser` can not be "hidden" behind an
ingress to create the illusion that it has the same origin as the consuming service it is necessary that `tokenissuer` can be called
via CORS.

As I have found out combining CORS with TLS client authentication creates compatibility issues.  As far as I have understood the whole
situation the CORS specfication states that pre-flight CORS requests should not be using credentials. Credentials like for instance 
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
in `iss` can be cofigured through the environment variable `TOK_ISS_NAME`.