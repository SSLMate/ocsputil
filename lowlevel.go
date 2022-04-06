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

package ocsputil // import "software.sslmate.com/src/ocsputil"

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"golang.org/x/crypto/ocsp"
	"io"
	"net/http"
	"strings"
	"time"
)

var (
	// ErrUnknown is returned when the certificate status is not good or revoked
	ErrUnknown = errors.New("OCSP responder does not know this certificate")

	// ErrNoResponder is returned when the certificte does not contain an HTTP OCSP responder URL
	ErrNoResponder = errors.New("Certificate does not contain an HTTP OCSP responder URL")

	// ErrNoCheck is returned when the certificate is an OCSP Responder certificate with the OCSP No Check extension
	ErrNoCheck = errors.New("Certificate is an OCSP responder certificate with the OCSP No Check extension")
)

// The maximum amount of time to wait for an OCSP response, as specified by Section
// 4.10.2 of the Baseline Requirements: "The CA SHALL operate and maintain its CRL
// and OCSP capability with resources sufficient to provide a response time of ten
// seconds or less under normal operating conditions."
const QueryTimeout = 10 * time.Second

var oidOCSPNoCheck = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}

func getOCSPServer(cert *x509.Certificate) string {
	for _, server := range cert.OCSPServer {
		if strings.HasPrefix(server, "http://") {
			return server
		}
	}
	return ""
}

func isOCSPResponderCert(cert *x509.Certificate) bool {
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageOCSPSigning {
			return true
		}
	}
	return false
}

func hasOCSPNoCheck(cert *x509.Certificate) bool {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidOCSPNoCheck) {
			return true
		}
	}
	return false
}

// Given a certificate, its issuer's subject, and its issuer's public key, return
// the parsed certificate and an issuer certificate suitable for passing to
// CreateRequest and CheckResponse.  The returned issuerCert is not a fully-populated
// certificate and is only suitable for use with CreateRequest and CheckResponse.
//
// cert can be a precertificate, but issuerSubject and issuerPubkeyBytes must be
// from the final certificate's issuer, not the precertificate's issuer.
//
// Returns an error if any of the arguments can't be parsed by the crypto/x509 package.
func ParseCertificate(certData []byte, issuerSubject []byte, issuerPubkeyBytes []byte) (cert *x509.Certificate, issuerCert *x509.Certificate, err error) {
	cert, err = x509.ParseCertificate(certData)
	if err != nil {
		err = fmt.Errorf("unable to parse certificate: %w", err)
		return
	}

	issuerPubkey, err := x509.ParsePKIXPublicKey(issuerPubkeyBytes)
	if err != nil {
		err = fmt.Errorf("unable to parse issuer public key: %w", err)
		return
	}

	issuerCert = &x509.Certificate{
		RawSubjectPublicKeyInfo: issuerPubkeyBytes,
		RawSubject:              issuerSubject,
		PublicKey:               issuerPubkey,
	}
	return
}

// Given a certificate and its issuer, return the "http://" OCSP server URL and
// an OCSP request suitable for passing to Query.
//
// cert can be a precertificate, but issuerCert must be the final certificate's issuer,
// not the precertificate's issuer.
//
// Returns ErrNoResponder if the certificate lacks an "http://" OCSP responder,
// ErrNoCheck if the certificate is an OCSP Responder certificate with the OCSP
// No Check extension, or an error from golang.org/x/crypto/ocsp.CreateRequest
func CreateRequest(cert *x509.Certificate, issuerCert *x509.Certificate) (serverURL string, requestBytes []byte, err error) {
	serverURL = getOCSPServer(cert)
	if serverURL == "" {
		err = ErrNoResponder
		return
	}
	if isOCSPResponderCert(cert) && hasOCSPNoCheck(cert) {
		err = ErrNoCheck
		return
	}
	requestBytes, err = ocsp.CreateRequest(cert, issuerCert, nil)
	if err != nil {
		err = fmt.Errorf("error creating OCSP request: %w", err)
		return
	}
	return
}

// Given an OCSP server URL and an OCSP request (which can be created with CreateRequest),
// send the OCSP query using a POST request with the given HTTP client and return the
// response, which is suitable for passing to CheckResponse.  The timeout for the query is
// defined by QueryTimeout.
//
// Returns errors for the following conditions:
//  - There's a problem parsing serverURL
//  - There's an error from the HTTP client
//  - There's an error reading the response
//  - The HTTP response code is not 200
//  - The Content-Type of the response is not "application/ocsp-response"
func Query(ctx context.Context, serverURL string, requestBytes []byte, httpClient *http.Client) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	httpRequest, err := http.NewRequestWithContext(ctx, "POST", serverURL, bytes.NewBuffer(requestBytes))
	if err != nil {
		return nil, fmt.Errorf("error with OCSP responder URL: %w", err)
	}
	httpRequest.Header.Set("Content-Type", "application/ocsp-request")
	// TODO: set User-Agent header?
	httpRequest.Header["Idempotency-Key"] = nil // Forces net/http to retry on failure even though it's a POST request

	httpResponse, err := httpClient.Do(httpRequest)
	if err != nil {
		return nil, fmt.Errorf("error querying OCSP responder over HTTP: %w", err)
	}

	body, err := io.ReadAll(httpResponse.Body)
	httpResponse.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("error reading response from OCSP responder: %w", err)
	}

	if httpResponse.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP error from OCSP responder: %s", httpResponse.Status)
	}

	if contentType := httpResponse.Header.Get("Content-Type"); contentType != "application/ocsp-response" {
		return nil, fmt.Errorf("HTTP response header has invalid Content-Type value %s", contentType)
	}

	return body, nil
}

// Given a certificate, its issuer, and an OCSP response, parse the response and
// return if and when it was revoked.
//
// cert can be a precertificate, but issuerCert must be the final certificate's issuer,
// not the precertificate's issuer.
//
// Returns ErrUnknown if the response is neither good nor revoked, or an error
// from golang.org/x/crypto/ocsp.ParseResponseForCert
func CheckResponse(cert *x509.Certificate, issuerCert *x509.Certificate, responseBytes []byte) (revoked bool, revocationTime time.Time, err error) {
	response, err := ocsp.ParseResponseForCert(responseBytes, cert, issuerCert)
	if err != nil {
		err = fmt.Errorf("error parsing OCSP response: %w", err)
		return
	}

	if response.Status == ocsp.Good {
		revoked = false
	} else if response.Status == ocsp.Revoked {
		revoked = true
		revocationTime = response.RevokedAt
	} else {
		err = ErrUnknown
	}
	return
}
