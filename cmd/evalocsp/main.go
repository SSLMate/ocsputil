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

package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"os"

	"software.sslmate.com/src/ocsputil"
)

func readChain(in io.Reader) ([]*x509.Certificate, error) {
	inBytes, err := io.ReadAll(in)
	if err != nil {
		return nil, err
	}
	certs := make([]*x509.Certificate, 0, 0)
	for len(inBytes) > 0 {
		block, rest := pem.Decode(inBytes)
		if block == nil {
			return nil, errors.New("invalid PEM")
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			certs = append(certs, cert)
		}
		inBytes = rest
	}
	return certs, nil
}

func errString(err error) *string {
	if err != nil {
		str := err.Error()
		return &str
	} else {
		return nil
	}
}

func main() {
	chain, err := readChain(os.Stdin)
	if err != nil {
		log.Fatalf("Error reading certificate chain from stdin: %s", err)
	}
	if len(chain) < 2 {
		log.Fatalf("Fewer than 2 certificates provided on stdin")
	}
	var (
		certData      = chain[0].Raw
		issuerSubject = chain[1].RawSubject
		issuerPubkey  = chain[1].RawSubjectPublicKeyInfo
	)
	eval := ocsputil.Evaluate(context.Background(), certData, issuerSubject, issuerPubkey, nil)

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "\t")
	encoder.Encode(map[string]interface{}{
		"responder_url":  eval.ResponderURL,
		"request_bytes":  eval.RequestBytes,
		"response_bytes": eval.ResponseBytes,
		"response_time":  eval.ResponseTime.String(),
		"error":          errString(eval.Err),
	})
}
