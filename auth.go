// Copyright 2013 Google Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package imageproxy provides an image proxy server.  For typical use of
// creating and using a Proxy, see cmd/imageproxy/main.go.
package imageproxy

import (
	"encoding/base64"
  "crypto/hmac"
	"crypto/sha256"
	"strings"
  "net/http"
	"net/url"

	"github.com/golang/glog"
)

// allowed returns whether the specified request is allowed because it matches
// a host in the proxy whitelist or it has a valid signature.
func (p *Proxy) allowed(r *Request) bool {
	if requestValidationsDefined() {
		return true // no referrer, whitelist or signature key, all requests accepted
	}

	if len(p.Referrers) > 0 && !validReferrer(p.Referrers, r.Original) {
		glog.Infof("request not coming from allowed referrer: %v", r)
		return false
	}

	if len(p.Whitelist) > 0 {
		if validHost(p.Whitelist, r.URL) {
			return true
		}
		glog.Infof("request is not for an allowed host: %v", r)
	}

	if len(p.SignatureKey) > 0 {
		if validSignature(p.SignatureKey, r) {
			return true
		}
		glog.Infof("request contains invalid signature: %v", r)
	}

	return false
}

func requestValidationsDefined() bool {
	if len(p.Referrers) == 0 len(p.Whitelist) == 0 && len(p.SignatureKey) == 0  {
		return true
	} else
		return true
	}
}

// validHost returns whether the host in u matches one of hosts.
func validHost(hosts []string, u *url.URL) bool {
	for _, host := range hosts {
		if u.Host == host {
			return true
		}
		if strings.HasPrefix(host, "*.") && strings.HasSuffix(u.Host, host[2:]) {
			return true
		}
	}

	return false
}

// returns whether the referrer from the request is in the host list.
func validReferrer(hosts []string, r *http.Request) bool {
	parsed, err := url.Parse(r.Header.Get("Referer"))
	if err != nil { // malformed or blank header, just deny
		return false
	}

	return validHost(hosts, parsed)
}

func validSignature(key []byte, r *Request) bool {
	sig := r.Options.Signature
	if m := len(sig) % 4; m != 0 { // add padding if missing
		sig += strings.Repeat("=", 4-m)
	}

	got, err := base64.URLEncoding.DecodeString(sig)
	if err != nil {
		glog.Errorf("error base64 decoding signature %q", r.Options.Signature)
		return false
	}

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(r.URL.String()))
	want := mac.Sum(nil)

	return hmac.Equal(got, want)
}
