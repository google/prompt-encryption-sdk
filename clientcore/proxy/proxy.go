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

// Package proxy exposes the attested client core through a loopback HTTP
// service. Its string/byte-oriented API is compatible with gomobile bind.
package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/GoogleCloudPlatform/prompt-encryption-sdk/clientcore/internal/attestedclient"
)

const defaultRevalidationTimeout = 55 * time.Minute

type configuration struct {
	ListenAddress      string                `json:"listen"`
	Upstream           string                `json:"upstream"`
	Policy             attestedclient.Policy `json:"policy"`
	OIDCDiscoveryURL   string                `json:"oidc_discovery_url"`
	OIDCIssuer         string                `json:"oidc_issuer"`
	OIDCJWKSURI        string                `json:"oidc_jwks_uri"`
	RevalidationPeriod string                `json:"revalidation_timeout"`
	InsecureSkipVerify bool                  `json:"insecure_skip_tls_verify"`
	ServerCAPath       string                `json:"server_ca_path"`
	ClientCertPath     string                `json:"client_cert_path"`
	ClientKeyPath      string                `json:"client_key_path"`
}

// Service is a running loopback proxy. It can be held by generated Kotlin,
// Swift/Objective-C, or Go bindings.
type Service struct {
	url       string
	server    *http.Server
	transport *attestedclient.Transport
	done      chan error
	closeOnce sync.Once
}

// Start validates JSON configuration and starts an embedded loopback proxy.
// Keeping the binding boundary to a string avoids language-specific config
// model generation.
func Start(configurationJSON string) (*Service, error) {
	var config configuration
	decoder := json.NewDecoder(bytes.NewBufferString(configurationJSON))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("parse configuration: %w", err)
	}
	if config.ListenAddress == "" {
		config.ListenAddress = "127.0.0.1:0"
	}
	if config.OIDCDiscoveryURL == "" {
		return nil, errors.New("oidc_discovery_url is required")
	}
	revalidationTimeout := defaultRevalidationTimeout
	if config.RevalidationPeriod != "" {
		parsed, err := time.ParseDuration(config.RevalidationPeriod)
		if err != nil || parsed <= 0 {
			return nil, errors.New("revalidation_timeout must be a positive Go duration")
		}
		revalidationTimeout = parsed
	}
	upstream, err := url.Parse(config.Upstream)
	if err != nil || upstream.Scheme != "https" || upstream.Host == "" {
		return nil, errors.New("upstream must be an https origin")
	}
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: config.InsecureSkipVerify, // Explicit caller opt-in for local/self-signed servers.
	}
	if config.ServerCAPath != "" {
		certificate, err := os.ReadFile(config.ServerCAPath)
		if err != nil {
			return nil, fmt.Errorf("read server CA: %w", err)
		}
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(certificate) {
			return nil, errors.New("server_ca_path contains no PEM certificates")
		}
		tlsConfig.RootCAs = roots
	}
	if config.ClientCertPath != "" {
		keyPath := config.ClientKeyPath
		if keyPath == "" {
			keyPath = config.ClientCertPath
		}
		certificate, err := tls.LoadX509KeyPair(config.ClientCertPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("load client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{certificate}
	}
	transport, err := attestedclient.NewTransport(attestedclient.Config{
		UpstreamURL:      upstream,
		Policy:           config.Policy,
		OIDCDiscoveryURL: config.OIDCDiscoveryURL,
		OIDCIssuer:       config.OIDCIssuer,
		OIDCJWKSURI:      config.OIDCJWKSURI,
		TLSConfig:        tlsConfig,
		ConnectionMaxAge: revalidationTimeout,
	})
	if err != nil {
		return nil, err
	}

	reverseProxy := httputil.NewSingleHostReverseProxy(upstream)
	originalDirector := reverseProxy.Director
	reverseProxy.Director = func(request *http.Request) {
		originalDirector(request)
		request.Host = upstream.Host
	}
	reverseProxy.Transport = transport
	reverseProxy.ErrorHandler = func(writer http.ResponseWriter, _ *http.Request, proxyErr error) {
		http.Error(writer, fmt.Sprintf("attested upstream request failed: %v", proxyErr), http.StatusBadGateway)
	}

	listener, err := net.Listen("tcp", config.ListenAddress)
	if err != nil {
		return nil, err
	}
	if !listener.Addr().(*net.TCPAddr).IP.IsLoopback() {
		listener.Close()
		return nil, errors.New("listen must resolve to a loopback address")
	}
	service := &Service{
		url:       "http://" + listener.Addr().String(),
		transport: transport,
		done:      make(chan error, 1),
	}
	service.server = &http.Server{Handler: reverseProxy}
	go func() {
		err := service.server.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		service.done <- err
	}()
	return service, nil
}

// URL returns the loopback origin after Start has successfully bound a port.
func (service *Service) URL() string {
	return service.url
}

// Wait blocks until the embedded HTTP service stops.
func (service *Service) Wait() error {
	return <-service.done
}

// Close stops the service and releases pooled upstream connections.
func (service *Service) Close() error {
	var closeErr error
	service.closeOnce.Do(func() {
		service.transport.CloseIdleConnections()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		closeErr = service.server.Shutdown(ctx)
	})
	return closeErr
}
