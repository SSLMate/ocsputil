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
	"crypto/x509"
	"net/http"
	"time"
)

// Given a certificate and its issuer, perform an OCSP check for the certificate and
// return if and when the certificate was revoked.
//
// cert can be a precertificate, but issuerCert must be the final certificate's issuer,
// not the precertificate's issuer.
//
// This function is a wrapper around [CreateRequest], [Query], and [CheckResponse].
// See those functions' documentation for details about the behavior.
func CheckCert(ctx context.Context, cert *x509.Certificate, issuerCert *x509.Certificate, httpClient *http.Client) (revoked bool, revocationTime time.Time, err error) {
	serverURL, requestBytes, err := CreateRequest(cert, issuerCert)
	if err != nil {
		return
	}
	responseBytes, err := Query(ctx, serverURL, requestBytes, httpClient)
	if err != nil {
		return
	}
	return CheckResponse(cert, issuerCert, responseBytes)
}

// Given a certificate, its issuer's subject, and its issuer's public key, perform
// an OCSP check for the certificate and return if and when the certificate was revoked.
//
// cert can be a precertificate, but issuerSubject and issuerPubkeyBytes must be
// from the final certificate's issuer, not the precertificate's issuer.
//
// This function is a wrapper around [ParseCertificate], [CreateRequest], [Query], and
// [CheckResponse].  See those functions' documentation for details about the behavior.
func CheckRawCert(ctx context.Context, certData []byte, issuerSubject []byte, issuerPubkeyBytes []byte, httpClient *http.Client) (revoked bool, revocationTime time.Time, err error) {
	cert, issuerCert, err := ParseCertificate(certData, issuerSubject, issuerPubkeyBytes)
	if err != nil {
		return
	}
	return CheckCert(ctx, cert, issuerCert, httpClient)
}
