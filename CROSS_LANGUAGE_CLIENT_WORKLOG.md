# Cross-Language Client Worklog

Last updated: 2026-07-18

## Goal

Keep the existing attested TLS protocol and Python server unchanged while making
the client usable from Kotlin, Swift, Go, Python, and other languages. The
existing Python API must remain compatible.

## Confirmed Test Seam

A real local TLS connection must:

1. call `POST /_attest-connection`;
2. validate the OIDC token and configured attestation policy;
3. validate the instance public-key binding;
4. validate the signature binding the token to TLS EKM from the live session;
5. send application data only after all validation succeeds.

The test is hermetic and does not require a TEE, GCP project, model, or external
network resource.

## Completed

- Created branch `cross-language-client-core` from `main` at `71bea4c`.
- Created an isolated `.venv` and installed the project test/server extras.
- Ran the pre-change suite to establish a baseline.
- Added a hermetic local OIDC issuer and TLS 1.3 attestation server fixture.
- Added an end-to-end test through the unchanged Python
  `PromptEncryptionClient` public interface.
- Proved the Python contract green: real OIDC signature, policy, instance-key,
  TLS EKM, session signature, and protected application request complete in
  under one second locally.
- Added the portable-client test and observed the intended red result because
  the portable client did not exist.
- Started the minimal Go client core and local reverse-proxy entry point.
- Implemented the dependency-free Go validation path for RS256/ES256 OIDC
  signatures, issuer/audience/time checks, policy checks, instance ECDSA P-256
  key binding, protobuf-compatible session payload construction, and live TLS
  EKM signature verification.
- Made the language-neutral happy-path contract green. The Go core compiles and
  both end-to-end client tests pass against the same server fixture.
- Added an opt-in Python adapter selected with
  `PROMPT_ENCRYPTION_CLIENT_CORE=/path/to/prompt-encryption-client`. The public
  constructor, session, and request calls are unchanged. The adapter lazily
  starts one core process per HTTPS origin, rewrites only the internal request
  route to loopback, restores the public response URL, and owns process cleanup.
- Proved with an end-to-end test that this Python mode does not instantiate the
  legacy Python attestation adapter.
- Focused verification after Python integration: 10 Python tests and 12
  subtests pass; `go test ./...` and `go vet ./...` pass.
- Added configurable pooled-session revalidation. A focused end-to-end test uses
  a 50 ms lifetime and observes a new TLS session and second attestation before
  the next application request.
- Added end-to-end rejection tests for workload image-policy mismatch and a
  tampered EKM/session signature. Both return a local 502 and the protected
  server observes zero application requests.
- Refactored the loopback service into a public, string-configured Go `proxy`
  package and made the CLI a thin wrapper around it. This API is suitable for
  `gomobile bind`, allowing Android Kotlin and Apple Swift applications to
  embed the same implementation when child processes are unavailable.
- Added a custom upstream CA option and restored the original upstream `Host`
  header in the reverse proxy.
- Preserved Python `requests` TLS options through the core: boolean verification,
  custom CA files, and client certificate/key pairs. Added the same flags to the
  standalone CLI.
- Added the existing Python client's trusted issuer/JWKS fallback behavior to
  the portable validator when OIDC discovery is unavailable.
- Replaced the first global pool revalidation timer after review. The transport
  now tracks each TLS connection's creation time. Expired idle connections are
  closed before selection; an expired in-flight request may finish, but that
  connection cannot carry a subsequent request. The existing revalidation
  end-to-end test remains green.

## Observations

- The portable behavior is larger than policy validation alone: EKM must be
  exported from the exact TLS connection carrying the attestation exchange and
  application request.
- A Rust/C++ library would still require separate JNI, Swift C-interop, cgo, and
  Python binding/lifecycle work. It would also need to own or integrate with
  each language's TLS connection.
- A loopback reverse proxy provides one executable and one protocol
  implementation. Kotlin, Swift, Go, and other clients can use their normal
  HTTP libraries against it.
- The local boundary carries plaintext, so the service binds only to loopback.
  Production TLS certificate verification remains enabled by default; the
  insecure option is explicit and intended for self-signed/local endpoints.
- The existing Python handshake includes the random challenge in TLS EKM but
  currently does not pass that nonce to `AttestationValidator.validate` for a
  second token-claim freshness check.
- Pre-change suite baseline: 127 passed and 7 failed. The failures are outside
  this work: five are caused by a latest-Uvicorn test setup incompatibility,
  one test references an unimported `compare`, and one existing file-descriptor
  mock interferes with pytest output capture.
- A portable binary cannot become the unconditional Python default until wheel
  publishing includes per-platform executables. Explicit selection lets the
  repository exercise the shared core now without breaking existing packages.
- Android and iOS cannot generally spawn a companion CLI. The embeddable proxy
  package addresses this without forking the security logic; producing signed
  AAR/XCFramework release artifacts still requires the relevant mobile SDKs.

## Decision

Implement the language-neutral client as a small, dependency-free Go binary
that exposes a loopback HTTP endpoint and owns the upstream attested TLS
connection. This avoids per-language cryptographic and native binding code,
produces a single static executable, and centralizes connection pooling and
revalidation.

The Python API can later manage this process behind its existing
`PromptEncryptionClient.session()` interface, preserving the user experience.

## Current Red/Green State

- Green: existing Python client against the hermetic end-to-end contract.
- Green: language-neutral Go client against the same contract.
- Green: unchanged Python API selecting the portable core.
- Green: timed revalidation of a pooled session.
- Green: policy and cryptographic-binding failures stop before application data.

## Next Steps

1. Produce signed/versioned CLI, AAR, and XCFramework artifacts in release CI.
2. Resolve the seven unrelated pre-existing server-test failures recorded
   below, preferably in a separate change.

## Verification Results

- Shared end-to-end contract: 6 passed.
- Client plus integration suites: 67 passed and 18 subtests passed.
- All unaffected Python suites: 111 passed and 25 subtests passed.
- Full Python suite: 133 passed; the same 7 baseline failures remain.
- Go: `go test ./...`, `go test -race ./...`, and `go vet ./...` pass.
- Cross-compilation: dependency-free CLI builds for Linux amd64, macOS arm64,
  and Windows amd64 with `CGO_ENABLED=0`.
- Python source/test compilation: passed with `compileall`.
- `git diff --check`: passed.
- Mobile AAR/XCFramework generation: not run because `gomobile`, Android SDK,
  and Apple build tooling are not installed in this local environment.

The 7 full-suite failures match the initial baseline:

- 5 `TlsInjectorProtocolTest` failures caused by the latest Uvicorn test config
  retaining `interface="auto"` where the installed API expects a resolved
  interface;
- 1 `AttestedTlsImplTest` subtest referencing an unimported `compare` name;
- 1 `KeysTest` whose mocked OS file descriptor collides with pytest output
  capture.
