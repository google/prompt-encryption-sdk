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

// Package attestedclient provides an HTTP transport that attests every TLS
// connection before allowing application data onto it.
package attestedclient

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	attestationPath = "/_attest-connection"
	ekmLabel        = "EXPORTER-Prompt-Encryption-SDK"
	audience        = "https://sts.google.com"
	nonceLength     = 32
	ekmLength       = 32
)

// Policy is the language-neutral representation of AttestationPolicy.
type Policy struct {
	HardwareModel string         `json:"hw_model"`
	Workload      WorkloadPolicy `json:"workload"`
	GCEInstance   GCEPolicy      `json:"gce_instance"`
}

type WorkloadPolicy struct {
	ImageHash    string `json:"image_hash"`
	SigningKeyID string `json:"signing_key_id"`
}

type GCEPolicy struct {
	ProjectID    string `json:"project_id"`
	Zone         string `json:"zone"`
	InstanceID   string `json:"instance_id"`
	InstanceName string `json:"instance_name"`
}

// Config controls TLS and attestation validation.
type Config struct {
	UpstreamURL      *url.URL
	Policy           Policy
	OIDCDiscoveryURL string
	OIDCIssuer       string
	OIDCJWKSURI      string
	TLSConfig        *tls.Config
	HTTPClient       *http.Client
	ConnectionMaxAge time.Duration
}

// Transport pools attested TLS connections and retires each connection at its
// individual revalidation deadline.
type Transport struct {
	transport   *http.Transport
	mutex       sync.Mutex
	connections map[*trackedConnection]struct{}
	maxAge      time.Duration
}

type trackedConnection struct {
	*tls.Conn
	owner     *Transport
	createdAt time.Time
}

func (connection *trackedConnection) Close() error {
	connection.owner.mutex.Lock()
	delete(connection.owner.connections, connection)
	connection.owner.mutex.Unlock()
	return connection.Conn.Close()
}

// RoundTrip retires expired idle connections before selecting a connection.
// An expired connection already carrying a response may finish, but remains in
// the registry so the next request closes it before reuse.
func (transport *Transport) RoundTrip(request *http.Request) (*http.Response, error) {
	now := time.Now()
	hasExpiredConnection := false
	transport.mutex.Lock()
	for connection := range transport.connections {
		if now.Sub(connection.createdAt) >= transport.maxAge {
			hasExpiredConnection = true
			break
		}
	}
	transport.mutex.Unlock()
	if hasExpiredConnection {
		transport.transport.CloseIdleConnections()
	}
	return transport.transport.RoundTrip(request)
}

// CloseIdleConnections closes pooled connections without interrupting active
// application requests.
func (transport *Transport) CloseIdleConnections() {
	transport.transport.CloseIdleConnections()
}

// NewTransport returns a pooling HTTP transport. Each new TLS connection is
// attested synchronously inside DialTLSContext before net/http can use it.
func NewTransport(config Config) (*Transport, error) {
	if config.UpstreamURL == nil || config.UpstreamURL.Scheme != "https" {
		return nil, errors.New("upstream URL must use https")
	}
	if config.OIDCDiscoveryURL == "" {
		return nil, errors.New("OIDC discovery URL is required")
	}
	tlsConfig := config.TLSConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS13}
	} else {
		tlsConfig = tlsConfig.Clone()
	}
	tlsConfig.MinVersion = tls.VersionTLS13
	tlsConfig.NextProtos = []string{"http/1.1"}
	if tlsConfig.ServerName == "" {
		tlsConfig.ServerName = config.UpstreamURL.Hostname()
	}
	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 5 * time.Second}
	}
	if config.ConnectionMaxAge <= 0 {
		config.ConnectionMaxAge = 55 * time.Minute
	}

	standardTransport := &http.Transport{
		ForceAttemptHTTP2: false,
		TLSClientConfig:   tlsConfig,
	}
	transport := &Transport{
		transport:   standardTransport,
		connections: make(map[*trackedConnection]struct{}),
		maxAge:      config.ConnectionMaxAge,
	}
	standardTransport.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		dialer := &net.Dialer{Timeout: 10 * time.Second}
		raw, err := dialer.DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		connection := tls.Client(raw, tlsConfig)
		if err := connection.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, fmt.Errorf("TLS handshake: %w", err)
		}
		if err := attest(ctx, connection, config, httpClient); err != nil {
			connection.Close()
			return nil, fmt.Errorf("attestation failed: %w", err)
		}
		tracked := &trackedConnection{
			Conn:      connection,
			owner:     transport,
			createdAt: time.Now(),
		}
		transport.mutex.Lock()
		transport.connections[tracked] = struct{}{}
		transport.mutex.Unlock()
		return tracked, nil
	}
	return transport, nil
}

type attestRequest struct {
	RequiredVerifierType []string `json:"requiredVerifierType"`
	Nonce                []byte   `json:"nonce"`
}

type attestResponse struct {
	Evidence []struct {
		VerifierType string `json:"verifierType"`
		GCABundle    struct {
			AttestationToken string `json:"attestationToken"`
		} `json:"gcaBundle"`
	} `json:"evidence"`
	InstancePublicKey struct {
		KeyBytes []byte `json:"keyBytes"`
	} `json:"instancePublicKey"`
	SessionSignature []byte `json:"sessionSignature"`
}

func attest(ctx context.Context, connection *tls.Conn, config Config, httpClient *http.Client) error {
	nonce := make([]byte, nonceLength)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}
	body, err := json.Marshal(attestRequest{
		RequiredVerifierType: []string{"VERIFIER_TYPE_GCA"},
		Nonce:                nonce,
	})
	if err != nil {
		return err
	}
	requestURL := *config.UpstreamURL
	requestURL.Path = attestationPath
	requestURL.RawQuery = ""
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	if err := request.Write(connection); err != nil {
		return fmt.Errorf("write attestation request: %w", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), request)
	if err != nil {
		return fmt.Errorf("read attestation response: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return fmt.Errorf("server returned %s: %s", response.Status, message)
	}
	var evidence attestResponse
	if err := json.NewDecoder(response.Body).Decode(&evidence); err != nil {
		return fmt.Errorf("decode attestation response: %w", err)
	}
	connectionState := connection.ConnectionState()
	ekm, err := connectionState.ExportKeyingMaterial(ekmLabel, nonce, ekmLength)
	if err != nil {
		return fmt.Errorf("export TLS keying material: %w", err)
	}
	return validateEvidence(ctx, evidence, ekm, config, httpClient)
}

func validateEvidence(ctx context.Context, evidence attestResponse, ekm []byte, config Config, httpClient *http.Client) error {
	var token string
	for _, item := range evidence.Evidence {
		if item.VerifierType == "VERIFIER_TYPE_GCA" {
			token = item.GCABundle.AttestationToken
			break
		}
	}
	if token == "" {
		return errors.New("required GCA evidence is missing")
	}
	if len(evidence.InstancePublicKey.KeyBytes) == 0 {
		return errors.New("instance public key is missing")
	}
	if len(evidence.SessionSignature) == 0 {
		return errors.New("session signature is missing")
	}
	claims, err := validateToken(ctx, token, config, httpClient)
	if err != nil {
		return err
	}
	if err := enforcePolicy(claims, config.Policy); err != nil {
		return err
	}
	fingerprint := fmt.Sprintf("%x", sha256.Sum256(evidence.InstancePublicKey.KeyBytes))
	if !stringListContains(claims["eat_nonce"], fingerprint) {
		return errors.New("instance key binding failed")
	}
	block, _ := pem.Decode(evidence.InstancePublicKey.KeyBytes)
	if block == nil {
		return errors.New("instance public key is not PEM")
	}
	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse instance public key: %w", err)
	}
	publicKey, ok := parsedKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() {
		return errors.New("instance public key is not ECDSA P-256")
	}
	ekmHash := sha256.Sum256(ekm)
	tokenHash := sha256.Sum256([]byte(token))
	payload := make([]byte, 0, 68)
	payload = append(payload, 0x0a, 0x20)
	payload = append(payload, ekmHash[:]...)
	payload = append(payload, 0x12, 0x20)
	payload = append(payload, tokenHash[:]...)
	payloadHash := sha256.Sum256(payload)
	if !ecdsa.VerifyASN1(publicKey, payloadHash[:], evidence.SessionSignature) {
		return errors.New("session signature verification failed")
	}
	return nil
}

type oidcConfiguration struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

type jwkSet struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	KeyID string `json:"kid"`
	Type  string `json:"kty"`
	Alg   string `json:"alg"`
	N     string `json:"n"`
	E     string `json:"e"`
	Curve string `json:"crv"`
	X     string `json:"x"`
	Y     string `json:"y"`
}

func validateToken(ctx context.Context, token string, config Config, httpClient *http.Client) (map[string]any, error) {
	discovery := oidcConfiguration{
		Issuer:  config.OIDCIssuer,
		JWKSURI: config.OIDCJWKSURI,
	}
	var discovered oidcConfiguration
	if err := fetchJSON(ctx, httpClient, config.OIDCDiscoveryURL, &discovered); err == nil {
		discovery = discovered
	} else if discovery.Issuer == "" || discovery.JWKSURI == "" {
		return nil, fmt.Errorf("OIDC discovery: %w", err)
	}
	if discovery.Issuer == "" || discovery.JWKSURI == "" {
		return nil, errors.New("OIDC discovery response is incomplete")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("attestation token is not a JWT")
	}
	decode := base64.RawURLEncoding.DecodeString
	headerBytes, err := decode(parts[0])
	if err != nil {
		return nil, errors.New("invalid JWT header")
	}
	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, errors.New("invalid JWT header")
	}
	algorithm, _ := header["alg"].(string)
	keyID, _ := header["kid"].(string)
	tokenType, _ := header["typ"].(string)
	if tokenType != "JWT" {
		return nil, errors.New("JWT typ must be JWT")
	}
	var keys jwkSet
	if err := fetchJSON(ctx, httpClient, discovery.JWKSURI, &keys); err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}
	var signingKey *jwk
	for index := range keys.Keys {
		if keys.Keys[index].KeyID == keyID {
			signingKey = &keys.Keys[index]
			break
		}
	}
	if signingKey == nil || signingKey.Alg != algorithm {
		return nil, errors.New("JWT signing key is not trusted")
	}
	signature, err := decode(parts[2])
	if err != nil {
		return nil, errors.New("invalid JWT signature encoding")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := verifyJWK(*signingKey, digest[:], signature); err != nil {
		return nil, fmt.Errorf("OIDC token signature: %w", err)
	}
	payload, err := decode(parts[1])
	if err != nil {
		return nil, errors.New("invalid JWT payload")
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, errors.New("invalid JWT payload")
	}
	if claims["iss"] != discovery.Issuer || !stringListContains(claims["aud"], audience) {
		return nil, errors.New("OIDC token issuer or audience mismatch")
	}
	now := float64(time.Now().Unix())
	expires, ok := claims["exp"].(float64)
	if !ok || expires <= now {
		return nil, errors.New("OIDC token is expired or has no expiry")
	}
	if notBefore, ok := claims["nbf"].(float64); ok && notBefore > now {
		return nil, errors.New("OIDC token is not valid yet")
	}
	return claims, nil
}

func fetchJSON(ctx context.Context, client *http.Client, endpoint string, destination any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned %s", response.Status)
	}
	return json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(destination)
}

func verifyJWK(key jwk, digest, signature []byte) error {
	switch key.Alg {
	case "RS256":
		nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
		if err != nil {
			return err
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
		if err != nil || len(eBytes) == 0 || len(eBytes) > 8 {
			return errors.New("invalid RSA exponent")
		}
		var exponent uint64
		for _, value := range eBytes {
			exponent = exponent<<8 | uint64(value)
		}
		publicKey := &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(exponent)}
		return rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest, signature)
	case "ES256":
		xBytes, err := base64.RawURLEncoding.DecodeString(key.X)
		if err != nil {
			return err
		}
		yBytes, err := base64.RawURLEncoding.DecodeString(key.Y)
		if err != nil || key.Curve != "P-256" || len(signature) != 64 {
			return errors.New("invalid ES256 key or signature")
		}
		publicKey := &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(xBytes),
			Y:     new(big.Int).SetBytes(yBytes),
		}
		if !ecdsa.Verify(publicKey, digest, new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
			return errors.New("invalid ES256 signature")
		}
		return nil
	default:
		return fmt.Errorf("unsupported JWT algorithm %q", key.Alg)
	}
}

func enforcePolicy(claims map[string]any, policy Policy) error {
	hardwareModels := map[string]string{
		"TDX":     "GCP_INTEL_TDX",
		"SEV":     "GCP_AMD_SEV",
		"SEV_SNP": "GCP_AMD_SEV_SNP",
	}
	if policy.HardwareModel != "" {
		expected, ok := hardwareModels[policy.HardwareModel]
		if !ok {
			return fmt.Errorf("unsupported hardware model %q", policy.HardwareModel)
		}
		if claims["hwmodel"] != expected {
			return fmt.Errorf("hardware model mismatch: expected %q", expected)
		}
	}
	submods, ok := claims["submods"].(map[string]any)
	if !ok {
		return errors.New("malformed submods claim")
	}
	container, ok := submods["container"].(map[string]any)
	if !ok {
		return errors.New("malformed container claim")
	}
	gce, ok := submods["gce"].(map[string]any)
	if !ok {
		return errors.New("malformed GCE claim")
	}
	if expected := policy.Workload.ImageHash; expected != "" && container["image_digest"] != expected {
		return errors.New("workload image hash mismatch")
	}
	if expected := policy.Workload.SigningKeyID; expected != "" {
		signatures, ok := container["image_signatures"].([]any)
		if !ok {
			return errors.New("malformed image signatures claim")
		}
		found := false
		for _, rawSignature := range signatures {
			signature, ok := rawSignature.(map[string]any)
			if !ok {
				return errors.New("malformed image signatures claim")
			}
			found = found || signature["key_id"] == expected
		}
		if !found {
			return errors.New("workload image is not signed by trusted key")
		}
	}
	checks := map[string]string{
		"project_id":    policy.GCEInstance.ProjectID,
		"zone":          policy.GCEInstance.Zone,
		"instance_id":   policy.GCEInstance.InstanceID,
		"instance_name": policy.GCEInstance.InstanceName,
	}
	for field, expected := range checks {
		if expected != "" && gce[field] != expected {
			return fmt.Errorf("GCE instance %s mismatch", field)
		}
	}
	return nil
}

func stringListContains(value any, expected string) bool {
	switch typed := value.(type) {
	case string:
		return typed == expected
	case []any:
		for _, item := range typed {
			if item == expected {
				return true
			}
		}
	}
	return false
}
