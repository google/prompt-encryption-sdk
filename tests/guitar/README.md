   # Guitar E2E Integration Test Pipeline

This directory contains the Guitar integration test suite for Attested Confidential Inference.

## Execution Lifecycle Flow

```
[CI Scheduler / Developer]
           │
           ▼
  1. BUILD PHASE (Guitar Build Service runs `blaze build`)
           │
           ▼
  2. PUSH & SYNC PHASE (Sandman Engine runs `PushImagesSandbox` operations)
           │  (Blocks until Go container pusher exits 0 ──► Sandbox state 'UP')
           ▼
  3. TEST RUN PHASE (Guitar Worker Node runs `blaze test`)
           │  (Runs guitar_prod_tests against Artifact Registry images)
           ▼
  4. TEARDOWN PHASE (Guitar triggers `sandman TearDown` ──► Sandbox state 'DOWN')
```

### Phase Breakdown

1. **Build Phase:**
   - Triggered by the Guitar CI scheduler or developer (`guitar run`).
   - Guitar's build service extracts all dependent targets from `confidential_inference_prod_e2e_tests` and `push_images.gcl` and invokes `blaze build` to compile Python binaries and container tarballs (`:client_image.tar` and `:workload_image.tar`).

2. **Push & Sync Phase (Sandman `operations`):**
   - Triggered by the Sandman Engine during pre-test environment setup.
   - Executes `push_images.gcl` using Sandman `operations.Start` to run the Go container pusher (`//third_party/bazel_rules/rules_docker/container/go/cmd/pusher:pusher`) in parallel for both client and workload images.
   - Sandman **synchronously blocks and waits** until both pusher commands exit with status `0` before marking the sandbox state as `UP`. This guarantees images are fully uploaded to Artifact Registry before tests start without requiring `sleep` loops or health check hacks.

3. **Test Run Phase:**
   - Triggered by the Guitar worker runner on Borg nodes once the sandbox reaches `UP` state.
   - Executes `//third_party/py/attested_confidential_inference/tests/e2e:guitar_prod_tests` against the pushed Artifact Registry image tags on a Confidential Space `c3-standard-4` VM.

4. **Teardown Phase:**
   - Triggered automatically by Guitar upon test completion (whether tests pass, fail, or time out).
   - Guitar sends a `TearDown` request to Sandman to clean up temporary resources and transition the `PushImagesSandbox` to `DOWN` state.

