// Copyright 2026 The Prompt Encryption SDK Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package proxy

import (
	"strings"
	"testing"
)

func TestStartCreatesLoopbackService(t *testing.T) {
	service, err := Start(`{
		"listen":"127.0.0.1:0",
		"upstream":"https://example.com",
		"oidc_discovery_url":"https://issuer.example/.well-known/openid-configuration",
		"policy":{}
	}`)
	if err != nil {
		t.Fatalf("Start() returned error: %v", err)
	}
	if !strings.HasPrefix(service.URL(), "http://127.0.0.1:") {
		t.Fatalf("URL() = %q, want a loopback URL", service.URL())
	}
	if err := service.Close(); err != nil {
		t.Fatalf("Close() returned error: %v", err)
	}
	if err := service.Wait(); err != nil {
		t.Fatalf("Wait() returned error: %v", err)
	}
}

func TestStartRejectsUnknownConfiguration(t *testing.T) {
	_, err := Start(`{
		"upstream":"https://example.com",
		"oidc_discovery_url":"https://issuer.example",
		"policy":{},
		"unexpected":true
	}`)
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("Start() error = %v, want unknown field rejection", err)
	}
}

func TestStartRejectsPlaintextUpstream(t *testing.T) {
	_, err := Start(`{
		"upstream":"http://example.com",
		"oidc_discovery_url":"https://issuer.example",
		"policy":{}
	}`)
	if err == nil || !strings.Contains(err.Error(), "https origin") {
		t.Fatalf("Start() error = %v, want HTTPS rejection", err)
	}
}
