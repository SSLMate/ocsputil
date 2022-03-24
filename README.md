# `software.sslmate.com/src/ocsputil`

`software.sslmate.com/src/ocsputil` is a Go package that provides convenience functions for OCSP checking.  It's mostly a wrapper around `golang.org/x/crypto/ocsp`.

The `ocsputil.Evaluate` function evaluates the reliability of a certificate's OCSP responder, and is used by [OCSP Watch](https://sslmate.com/labs/ocsp_watch).

[View GoDocs](https://pkg.go.dev/software.sslmate.com/src/ocsputil)

## `evalocsp`

`evalocsp` is a command line tool that evaluates the reliability of a certificate's OCSP responder using `ocsputil.Evaluate`.

Install it with: `go install software.sslmate.com/src/ocsputil/cmd/evalocsp@latest`

Input (on stdin): Two PEM-encoded certificates - the certificate whose OCSP responder should be evaluated, followed by its issuer.  The first certificate may be a precertificate, but if it's signed by a dedicated precert signing CA, then the second certificate must be the issuer of the final certificate rather than the precertificate.

Output (on stdout): A JSON object with the following fields:

| Field Name       | Description |
| ---------------- | ----------- |
| `error`          | `null` if the OCSP check was successful, or the error, as a string. |
| `responder_url`  | The URL of the OCSP responder. |
| `request_bytes`  | The bytes of the OCSP request, as a base64-encoded string. |
| `response_bytes` | The bytes of the OCSP response, as a base64-encoded string. |
| `response_time`  | The length of time which the OCSP responder took to respond, formatted as a [`time.Duration` string](https://pkg.go.dev/time#Duration.String). |

If `error` is `null`, then the other fields are non-null.  If `error` is non-null, then any of the other fields may be `null` depending on the nature of the error.

## Go 1.18 Bug

Go 1.18 accidentally [banned SHA-1-signed OCSP responses](https://github.com/golang/go/issues/41682#issuecomment-1072695832), which can still be found in the WebPKI.  To work around this, use Go 1.17, or set the environment variable `GODEBUG=x509sha1=1`.  This bug will be fixed in Go 1.18.1.
