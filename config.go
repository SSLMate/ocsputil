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
	"net/http"
)

// Contains configuration for the functions in this package.
// The zero value provides sensible defaults.
type Config struct {
	// The HTTP client for making OCSP requests. If nil, then [http.DefaultClient] is used.
	HTTPClient *http.Client

	// The HTTP User-Agent string for OCSP requests. If empty, then no User-Agent is sent.
	UserAgent string
}

func (config *Config) httpClient() *http.Client {
	if config != nil && config.HTTPClient != nil {
		return config.HTTPClient
	} else {
		return http.DefaultClient
	}
}

func (config *Config) userAgent() string {
	if config != nil {
		return config.UserAgent
	} else {
		return ""
	}
}
