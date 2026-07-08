# Architecture: Prompt Encryption SDK
The Prompt Encryption SDK establishes an end-to-end encrypted channel between
a client and an inference workload running inside a Trusted Execution
Environment (TEE). The security guarantee is stronger than standard TLS: the
encrypted channel is cryptographically bound to the attested identity of the
TEE endpoint, meaning neither the cloud operator nor any infrastructure-layer
observer can read prompt or response content, even with access to the host OS
or hypervisor.

This document describes the protocol, the component architecture, and the
security properties of the system.

## Background
### Why Standard TLS Is Insufficient
Standard TLS provides confidentiality and server authentication via a
certificate chain. The client knows it is talking to whoever holds the private
key associated with the certificate. What it does not know is *where* that
private key lives — whether it is inside a hardware-isolated enclave or in a
process fully visible to the cloud operator.

For regulated enterprise workloads like healthcare, finance, legal this
distinction matters. The threat model is not an external attacker intercepting
network traffic. The threat model is an infrastructure-layer observer: a
compromised hypervisor, a cloud operator with privileged access, or a malicious
co-tenant on shared infrastructure. Standard TLS provides no protection against
any of these.

TEEs address the hardware isolation side of this problem. The missing piece is
*trust establishment*: how does a client cryptographically verify that it is
talking to a specific TEE running specific software, and how is that
verification bound to the communication channel so it cannot be stripped or
forged?

### The Adversary and the Objective
We assume an adversary who controls the network (routers, L4/L7 load balancers) as well as the underlying host infrastructure (Hypervisor, Host OS). Standard TLS offers no defense against an infrastructure-layer observer.

The objective is to establish a secure channel where sensitive data (e.g., prompts) is strictly confined to the memory space of a verified TEE running a specific, known-good software stack. The adversary must not be able to eavesdrop, tamper, or perform Man-in-the-Middle (MitM) or Attestation Replay attacks. To achieve this, we use **Attested TLS**.

### Theoretical Background: Typology of Attested TLS
Attested TLS aims to provide cryptographic proof of the integrity and identity of the environment (e.g., a TEE) at the other end of a connection. The primary variations differ in *when* attestation evidence is provided relative to the TLS handshake:

1.  **Pre-Handshake Attestation:** Remote attestation occurs *before* the TLS handshake begins. The results influence the handshake, often by issuing a short-lived certificate to the server's TLS public key.

    *   *Pros:* Strong theoretical guarantee; no channel is established until attestation is verified.
    *   *Cons:*
        * Requires significant changes to existing Public Key Infrastructure (PKI) and Certificate Authority (CA) workflows, heavily hindering real-world adoption.
        * Self-signed certificate based Pre-handshake attested TLS has known vulnerabilities.
2.  **Intra-Handshake Attestation:** Attestation evidence is exchanged *during* the TLS handshake, typically embedded in custom X.509 extensions or new TLS protocol extensions (e.g., `ClientHello` / `Certificate` messages).

    *   *Pros:* Direct binding of attestation to the handshake in progress.
    *   *Cons:* Requires deep modifications to core TLS libraries and breaks compatibility with standard network infrastructure (e.g., L4 Load Balancers). Furthermore, early IETF draft proposals for intra-handshake bindings were found to have potential security flaws in Confidential Computing threat models.
3.  **Post-Handshake Attestation:** A standard TLS handshake completes first, establishing a secure channel. An application-layer attestation protocol is then run *inside* this encrypted channel, cryptographically binding the evidence to the live TLS session via Exported Keying Material (EKM).

### Design Rationale: Why Post-Handshake?
The Prompt Encryption SDK strictly utilizes **Post-Handshake Attested TLS** for the following critical reasons:

*   **Infrastructure Compatibility:** It works seamlessly with existing, hardened TLS libraries and real-world network infrastructure without requiring protocol-level modifications.
*   **Encrypted Attestation Payload:** Exchanging attestation evidence, which contains detailed platform and software measurements, inside an already established TLS tunnel protects sensitive infrastructure metadata from passive network observers.
*   **Strong Session Binding:** Using RFC 5705 EKM ensures the attestation is mathematically tied to the specific TLS session. Even though the assurance arrives "later," the cryptographic link prevents Replay and MitM attacks robustly.
*   **Standardization Momentum:** Industry consensus and recent IETF drafts (e.g., `draft-fossati-tls-exported-attestation`) strongly favor post-handshake mechanisms for Confidential Computing due to their optimal balance of security and deployability.

---

## Cryptographic Protocol Flow
The protocol operates over an established standard TLS 1.3 channel, leveraging the highly vetted TLS record layer for confidentiality, sequence numbering (replay protection), and integrity (AEAD MACs).
### High-Level Protocol Flow
```ascii
Client (urllib3/Pool)                           Server (TEE Workload)
|                                                              |
| [1] Standard TLS 1.3 Handshake (Any Cert)                    |
|<============================================================>|
|                                                              |
| [2] POST /_attest-connection                                 |
|------------------------------------------------------------->|
|                                 |                            |
|                                 +--[3a] Derives EKM_svr (RFC 5705)
|                                 +--[3b] Hardware signs Attestation Report (T_attest)
|                                 +--[3c] Generates Payload = Protobuf(SHA256(EKM_svr), SHA256(T_attest))
|                                 +--[3d] Computes Sig_session = Sign(PrivKey_instance, Payload)
|                                                              |
| [4] { T_attest, PubKey_instance, Sig_session }               |
|<-------------------------------------------------------------|
|                                                              |
+--[5] Client Verification (See Section 2.3)                   |
|                                                              |
| [6] Verified E2E Encrypted Application Data                  |
|=============================================================>|
```

### Protocol Step-by-Step
#### Step 1: Standard TLS Handshake
A standard TLS 1.3 handshake establishes an encrypted channel and a shared session secret derived from ephemeral key exchange (ECDHE). The server presents a standard PKI certificate.
#### Step 2: TLS Exported Keying Material (EKM)
Both sides independently derive a session-specific value using RFC 5705 TLS Exported Keying Material.
The label `"EXPORTER-Prompt-Encryption-SDK"` scopes this export specifically to this protocol, preventing cross-protocol attacks. The EKM is deterministically derived from the session's master secret; it cannot be forged without access to the session keys and uniquely identifies this specific TLS session.
#### Step 3: TEE Attestation Report Generation & Session Binding
The server maintains an ephemeral ECDSA P-256 key pair ($$K_{instance}$$), generated purely in TEE memory. The server interacts with the TEE hardware to obtain an Attestation Token ($$T_{attest}$$). This report contains:

*   **Platform measurements:** Hardware firmware version, CPU SVN, and platform configuration registers.
*   **Workload measurements:** A hash of the software stack running inside the TEE (bootloader, kernel, application).
*   **Hardware Identity Snapshot:** The SHA-256 fingerprint of the public key ($$PubKey_{instance}$$) is cryptographically bound into the hardware token (within the `eat_nonce` OIDC claim).

To prove possession of the key bound to the TEE, and to bind the hardware identity to the live TLS session, the server signs a specific payload using its private key $$PrivKey_{instance}$$:

$$ Payload = Protobuf(SHA256(EKM_{svr}), SHA256(T_{attest})) $$

$$ Sig_{session} = Sign_{ECDSA-P256}(PrivKey_{instance}, Payload) $$
### Client-Side Attestation Verification
The core security of the SDK rests in the client's rigorous validation of the attestation response. If any step fails, the connection is immediately terminated.

1.  **EKM Derivation:** The client independently derives $$EKM_{client}$$. Due to TLS properties, $$EKM_{client} == EKM_{svr}$$ if and only if both parties share the exact same TLS Master Secret.
2.  **Signature Chain Verification (Root of Trust):** The client fetches the JWKS from the configured OIDC Discovery URL and verifies the cryptographic signature of the JWT against the published public keys of the Root of Trust (e.g., Google Cloud Attestation).
3.  **Instance Key Binding Verification:** The client computes $$Hash_{key} = SHA256(PubKey_{instance})$$. It extracts the `eat_nonce` claim from the verified OIDC JWT and asserts that $$Hash_{key} \in claims['eat_nonce']$$.
4.  **TLS Session Binding Verification:** To prevent Attestation Replay and MitM attacks, the client binds the verified hardware identity to the live TLS socket. It reconstructs $$Payload_{client} = Protobuf(SHA256(EKM_{client}), SHA256(T_{attest}))$$ and verifies the ECDSA P-256 signature ($$Sig_{session}$$) using $$PubKey_{instance}$$

5.  **Policy Evaluation:** The client parses the claims structure to enforce user-defined policies against the `AttestationPolicy` protobuf:

    *   **Hardware Model:** Evaluates `claims['hwmodel']` (e.g., `"GCP_INTEL_TDX"`).
    *   **Workload Integrity:** Evaluates `claims['submods']['container']['image_digest']` to ensure the exact expected binary is running.
    *   **Platform Isolation:** Evaluates `claims['submods']['gce']['project_id']` and `instance_id` to prevent cross-tenant workload spoofing.
### The Chain of Trust: Establishing Cryptographic Binding
The fundamental security guarantee of this SDK relies on an unbroken chain of trust linking the physical hardware, the software workload, and the live network transport. This trust is established through the following sequence of bindings:

1.  **Hardware Roots the Trust:** The TEE hardware signs the attestation token ($$T_{attest}$$) using a private key securely fused into the silicon, establishing undeniable proof of the platform's authenticity and the integrity of the measured workload.
2.  **Token Binds to Instance Key:** The SHA-256 fingerprint of the ephemeral Instance Public Key ($$PubKey_{instance}$$) is embedded within the `eat_nonce` claim of $$T_{attest}$$ *before* the hardware signs it. This proves to the client that the specific TEE described in the report is in possession of the corresponding $$PrivKey_{instance}$$.
3.  **Instance Key Binds to TLS Session:** The server extracts the Exported Keying Material ($$EKM_{svr}$$) from the active TLS session and signs it (along with a hash of $$T_{attest}$$) using $$PrivKey_{instance}$$. Because the $$EKM$$ is deterministically derived from the TLS Master Secret, it uniquely identifies the live transport connection.

By verifying this entire chain (Hardware $$\rightarrow$$ Token $$\rightarrow$$ Instance Key $$\rightarrow$$ TLS Session), the client is mathematically assured that the TLS endpoint they are communicating with is precisely the hardware-isolated enclave described in the attestation report, preventing any possibility of MitM or Attestation Replay attacks.

---

## Component Architecture
### Client Side
*   **`PromptEncryptionClient`**: The top-level client object that owns the attestation policy and manages session lifecycle.
*   **`AttestationPolicy`**: A protobuf-defined structure describing the trusted TEE state (hw_model, workload, and gce_instance).
*   **`AttestedPoolManager` & Lazy Revalidation**: To maintain performance, the pool manager hooks into `urllib3`. Attestation is an expensive operation, so connections are reused. By default, connections are reused for up to 55 minutes, after which a new attestation handshake is transparently forced over the existing socket to ensure continuous TEE integrity and key freshness.
### Server Side
*   **`KeyManager`**: Manages the ephemeral cryptographic keys used in attestation token generation. It generates fresh signing keys, rotates them on a schedule, and maintains a brief overlap window during rotation.
*   **`TokenManager`**: Runs in a background thread to proactively rotate the attestation tokens presented to clients, preventing latency spikes at rotation boundaries.
*   **`AttestedTLS` & EKM Extraction**: Handles the post-handshake attestation exchange. Standard ASGI/WSGI servers abstract away the TLS socket. The middleware intercepts the ASGI scope and utilizes a custom C-extension (`ekm/_ekm.c`) to safely call OpenSSL's `SSL_export_keying_material` API.

---

## Threat Model Matrix & Security Considerations
### What the SDK Protects Against
| Threat | Protected? | Mechanism |
| :--- | :---: | :--- |
| Network observer reading prompt/response | ✅ Yes | TLS encryption |
| Cloud operator reading prompt/response | ✅ Yes | TEE memory isolation + attested TLS |
| Infrastructure-layer observer (hypervisor, host OS) | ✅ Yes | TEE memory isolation |
| Attestation replay attack | ✅ Yes | EKM binding ties report to specific TLS session |
| MitM presenting valid cert but not a TEE | ✅ Yes | Attestation verification fails without TEE hardware key |
| Server running unexpected software | ✅ Yes | Workload measurement in policy evaluation |
| Debug-mode TEE weakening isolation | ✅ Yes | Policy validation (if configured correctly) |

### What the SDK Does NOT Protect Against (Out of Scope)
| Threat | Protected? | Notes |
| :--- | :---: | :--- |
| Model weight confidentiality | ❌ No | Addressed by other Confidential Inference components |
| Malicious or compromised workload behavior | ❌ No | Attestation covers boot state, not runtime logic flaws/RCEs |
| Traffic analysis | ❌ No | Packet sizes and timing remain visible |
| Post-processing exfiltration | ❌ No | Depends entirely on the integrity of the workload inside the TEE |
| Denial of Service (DoS) | ❌ No | Hypervisor/Network operator can trivially drop packets |

### Operational & Security Considerations for Integrators
1.  **Pin Workload Measurements:** A permissive policy accepting any workload on a given platform provides significantly weaker guarantees. High-assurance environments must pin specific workload hashes, requiring policy updates on every server-side deployment.
2.  **Reject Debug Mode:** Never accept debug-mode TEEs in production, as debuggers can inspect TEE memory.
3.  **Validate Certificate Transparency:** The attested TLS channel proves communication with a TEE. The server certificate proves *which* endpoint you are communicating with. Both checks are vital.
4.  **Treat Policy as Code:** `AttestationPolicy` is a security-critical artifact. It must be version-controlled, strictly reviewed, and deliberately updated. Overly permissive policies silently destroy the SDK's security guarantees.
5.  **Attestation Cost Amortization:** Generating fresh TEE quotes is computationally expensive. The SDK relies on connection reuse and background token rotation to maintain low-latency inference pipelines while preserving security guarantees.

---

## Further Reading
*   [RFC 5705: Keying Material Exporters for Transport Layer Security (TLS)](https://datatracker.ietf.org/doc/html/rfc5705)
*   [Intel Trust Domain Extensions (TDX) Architecture Specification](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-trust-domain-extensions.html)
*   [AMD Secure Encrypted Virtualization-Secure Nested Paging (SEV-SNP)](https://www.amd.com/en/developer/sev.html)
*   [Google Cloud Confidential Computing](https://cloud.google.com/confidential-computing)
*   [IETF Draft: TLS Exported Authenticator (Basis for Post-Handshake Attestation)](https://datatracker.ietf.org/doc/html/rfc9261)