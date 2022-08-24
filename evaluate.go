// Copyright (C) 2022 Opsmate, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.
//
// Except as contained in this notice, the name(s) of the above copyright
// holders shall not be used in advertising or otherwise to promote the
// sale, use or other dealings in this Software without prior written
// authorization.

package ocsputil

import (
	"context"
	"time"
)

// Represents the result of [Evaluate].  If Err is nil, then the other fields are non-nil.
// If Err is non-nil, then any of the other fields may be nil, depending on the nature
// of the error.
type Evaluation struct {
	ResponderURL  *string
	RequestBytes  []byte
	ResponseBytes []byte
	ResponseTime  time.Duration
	Err           error
}

// Given a certificate, its issuer's subject, and its issuer's public key,
// evaluate the certificate's OCSP responder.
//
// cert can be a precertificate, but issuerSubject and issuerPubkey must be
// from the final certificate's issuer, not the precertificate's issuer.
//
// This function is a wrapper around [ParseCertificate], [CreateRequest], [Query],
// and [CheckResponse].  See the documentation for those functions for details
// about the behavior.
//
// If config is nil, a zero-value [Config] is used, which provides
// sensible defaults.
//
// Evaluate is used by [OCSP Watch].
//
// [OCSP Watch]: https://sslmate.com/labs/ocsp_watch
func Evaluate(ctx context.Context, certData []byte, issuerSubject []byte, issuerPubkey []byte, config *Config) (eval Evaluation) {
	cert, issuerCert, err := ParseCertificate(certData, issuerSubject, issuerPubkey)
	if err != nil {
		eval.Err = err
		return
	}

	serverURL, requestBytes, err := CreateRequest(cert, issuerCert)
	if err != nil {
		eval.Err = err
		return
	}
	eval.ResponderURL = &serverURL
	eval.RequestBytes = requestBytes

	responseBytes, responseTime, err := timedQuery(ctx, serverURL, requestBytes, config)
	if err != nil {
		eval.Err = err
		return
	}
	eval.ResponseBytes = responseBytes
	eval.ResponseTime = responseTime

	if _, _, err := CheckResponse(cert, issuerCert, responseBytes); err != nil {
		eval.Err = err
		return
	}

	return
}

func timedQuery(ctx context.Context, serverURL string, requestBytes []byte, config *Config) ([]byte, time.Duration, error) {
	startTime := time.Now()
	responseBytes, err := Query(ctx, serverURL, requestBytes, config)
	responseTime := time.Since(startTime)

	return responseBytes, responseTime, err
}
