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

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	clientproxy "github.com/GoogleCloudPlatform/prompt-encryption-sdk/clientcore/proxy"
)

const defaultDiscoveryURL = "https://confidentialcomputing.googleapis.com/.well-known/openid-configuration"
const defaultIssuer = "https://confidentialcomputing.googleapis.com"
const defaultJWKSURI = "https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com"

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	listenAddress := flag.String("listen", "127.0.0.1:8080", "local address for language clients")
	upstream := flag.String("upstream", "", "attested HTTPS server origin")
	policyPath := flag.String("policy", "", "path to a language-neutral JSON policy")
	discoveryURL := flag.String("oidc-discovery-url", defaultDiscoveryURL, "trusted OIDC discovery URL")
	oidcIssuer := flag.String("oidc-issuer", defaultIssuer, "fallback trusted OIDC issuer")
	oidcJWKSURI := flag.String("oidc-jwks-uri", defaultJWKSURI, "fallback trusted JWKS URL")
	revalidationTimeout := flag.Duration("revalidation-timeout", 55*time.Minute, "maximum pooled TLS session age before re-attestation")
	insecureSkipVerify := flag.Bool("insecure-skip-tls-verify", false, "allow self-signed upstream TLS certificates")
	serverCAPath := flag.String("server-ca", "", "additional PEM CA file for upstream TLS")
	clientCertPath := flag.String("client-cert", "", "PEM client certificate for upstream mutual TLS")
	clientKeyPath := flag.String("client-key", "", "PEM client private key; defaults to --client-cert")
	flag.Parse()

	policyBytes, err := os.ReadFile(*policyPath)
	if err != nil {
		return fmt.Errorf("read --policy: %w", err)
	}
	var policy map[string]any
	decoder := json.NewDecoder(bytes.NewReader(policyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&policy); err != nil {
		return fmt.Errorf("parse --policy: %w", err)
	}
	configuration, err := json.Marshal(map[string]any{
		"listen":                   *listenAddress,
		"upstream":                 *upstream,
		"policy":                   policy,
		"oidc_discovery_url":       *discoveryURL,
		"oidc_issuer":              *oidcIssuer,
		"oidc_jwks_uri":            *oidcJWKSURI,
		"revalidation_timeout":     revalidationTimeout.String(),
		"insecure_skip_tls_verify": *insecureSkipVerify,
		"server_ca_path":           *serverCAPath,
		"client_cert_path":         *clientCertPath,
		"client_key_path":          *clientKeyPath,
	})
	if err != nil {
		return err
	}
	service, err := clientproxy.Start(string(configuration))
	if err != nil {
		return err
	}
	defer service.Close()
	if err := json.NewEncoder(os.Stdout).Encode(map[string]string{"url": service.URL()}); err != nil {
		return err
	}
	if err := service.Wait(); err != nil && !errors.Is(err, os.ErrClosed) {
		return err
	}
	return nil
}
