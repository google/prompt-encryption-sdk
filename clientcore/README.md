# Language-Neutral Prompt Encryption Client

The client core is a small Go executable that owns the attested TLS connection
and exposes the verified upstream as a loopback HTTP origin. Applications keep
using their language's normal HTTP client; no JNI, Swift C interop, cgo, or
Python cryptography binding is required.

```text
Kotlin / Swift / Go / Python application
                 |
                 | plain HTTP on loopback only
                 v
      prompt-encryption-client
                 |
                 | TLS 1.3 + post-handshake attestation
                 v
        existing Python server SDK
```

The core does not change the server protocol. It calls
`POST /_attest-connection`, validates the OIDC token and policy, verifies the
instance-key and live TLS EKM bindings, and only then forwards application
requests. It pools verified connections and discards idle pooled connections at
the revalidation deadline (55 minutes by default).

## Build

Go 1.23 or newer is required to build the binary.

```bash
cd clientcore
CGO_ENABLED=0 go build -o prompt-encryption-client ./cmd/prompt-encryption-client
```

Go can cross-compile the same source for common customer platforms:

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o prompt-encryption-client-linux-amd64 ./cmd/prompt-encryption-client
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -o prompt-encryption-client-darwin-arm64 ./cmd/prompt-encryption-client
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o prompt-encryption-client.exe ./cmd/prompt-encryption-client
```

## Configure and Run

Create a JSON policy. Its fields map directly to the existing protobuf policy:

```json
{
  "hw_model": "TDX",
  "workload": {
    "image_hash": "sha256:EXPECTED_CONTAINER_IMAGE_HASH",
    "signing_key_id": ""
  },
  "gce_instance": {
    "project_id": "your-project-id",
    "zone": "us-central1-a",
    "instance_id": "",
    "instance_name": ""
  }
}
```

Start one core for an upstream origin:

```bash
./prompt-encryption-client \
  --listen=127.0.0.1:8080 \
  --upstream=https://confidential-inference.example.com:8000 \
  --policy=policy.json
```

The process prints one readiness JSON object, such as
`{"url":"http://127.0.0.1:8080"}`. It rejects non-loopback listen addresses.
Standard upstream certificate verification is enabled by default. Use
`--insecure-skip-tls-verify` only for a deliberately self-signed development
server. `--server-ca` adds a private PEM trust root. Mutual-TLS deployments can
also provide `--client-cert` and `--client-key`.

## Language Examples

All examples call the same verified loopback origin.

### Kotlin (JDK HTTP client)

```kotlin
val body = """{"prompt":"Hello from Kotlin"}"""
val request = java.net.http.HttpRequest.newBuilder()
    .uri(java.net.URI.create("http://127.0.0.1:8080/v1/completions"))
    .header("Content-Type", "application/json")
    .POST(java.net.http.HttpRequest.BodyPublishers.ofString(body))
    .build()
val response = java.net.http.HttpClient.newHttpClient().send(
    request,
    java.net.http.HttpResponse.BodyHandlers.ofString(),
)
```

### Swift

```swift
var request = URLRequest(url: URL(
    string: "http://127.0.0.1:8080/v1/completions"
)!)
request.httpMethod = "POST"
request.setValue("application/json", forHTTPHeaderField: "Content-Type")
request.httpBody = #"{"prompt":"Hello from Swift"}"#.data(using: .utf8)
let (data, response) = try await URLSession.shared.data(for: request)
```

### Go

```go
response, err := http.Post(
    "http://127.0.0.1:8080/v1/completions",
    "application/json",
    strings.NewReader(`{"prompt":"Hello from Go"}`),
)
```

### Python, direct loopback use

```python
response = requests.post(
    "http://127.0.0.1:8080/v1/completions",
    json={"prompt": "Hello from Python"},
)
```

### Python, unchanged SDK interface

Set the core executable path and keep existing application code unchanged:

```bash
export PROMPT_ENCRYPTION_CLIENT_CORE=/absolute/path/to/prompt-encryption-client
```

```python
client = PromptEncryptionClient(policy)
with client.session() as http:
    response = http.post(
        "https://confidential-inference.example.com:8000/v1/completions",
        json={"prompt": "The existing interface is unchanged"},
    )
```

The Python adapter starts and stops loopback core processes with the session and
uses one process per upstream HTTPS origin. Without the environment variable,
the existing pure-Python client path remains active.

## Android and Apple Embedding

Mobile applications should embed the proxy package instead of spawning the CLI.
The public API intentionally consists of `Start(configurationJSON)`,
`Service.URL()`, and `Service.Close()`, which are compatible with Go's mobile
binding generator:

```bash
go install golang.org/x/mobile/cmd/gomobile@latest
gomobile init

cd clientcore
gomobile bind -target=android -o prompt-encryption-client.aar ./proxy
gomobile bind -target=ios -o PromptEncryptionClient.xcframework ./proxy
```

Kotlin or Swift starts the embedded service with the same JSON configuration
used by the CLI, sends normal HTTP requests to the returned loopback URL, and
closes the service with the application lifecycle. This generated binding is a
thin lifecycle shim; the TLS, OIDC, policy, EKM, and signature code remains the
same Go implementation exercised by the end-to-end contract tests.

An embedded configuration uses inline policy JSON:

```json
{
  "listen": "127.0.0.1:0",
  "upstream": "https://confidential-inference.example.com:8000",
  "oidc_discovery_url": "https://confidentialcomputing.googleapis.com/.well-known/openid-configuration",
  "oidc_issuer": "https://confidentialcomputing.googleapis.com",
  "oidc_jwks_uri": "https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com",
  "revalidation_timeout": "55m",
  "insecure_skip_tls_verify": false,
  "policy": {
    "hw_model": "TDX",
    "workload": {"image_hash": "sha256:EXPECTED_CONTAINER_IMAGE_HASH"},
    "gce_instance": {"project_id": "your-project-id", "zone": "us-central1-a"}
  }
}
```

Generating the AAR/XCFramework requires the Android or Apple toolchain on the
release builder; those platform artifacts are not built by the resource-light
local test.

## Security Boundary

Application payloads are plaintext only inside the local process boundary and
on the operating system's loopback interface. Run the application and core in
the same host, pod, or similarly isolated trust boundary. The core never binds
to a non-loopback address, and application data is never sent upstream until
the connection's attestation succeeds.
