# Phase 5 — Teaching, Documentation, and Demo (Lane C)

Read `00_MASTER_CONTEXT.md`. This phase is continuous, but do a final pass after
Phases 2–4.

## Goal

Make uKey the clearest open reference for how a virtual FIDO2/CTAP2 authenticator
works: readable Python, protocol docs, runnable tests, a deterministic demo, and an
honest comparison with prior art.

This is the lane that matters most for a conference talk. It does not require new
features. It requires clarity and truth.

## Deliverables

### 1. `docs/ARCHITECTURE.md`

Include:

- component diagram,
- UHID data flow,
- CTAPHID framing,
- CTAP2 command flow,
- Android Keystore/StrongBox boundary,
- transport and pairing,
- PAM/context flow (after Phase 3),
- trust boundaries and failure modes.

Use Mermaid or ASCII diagrams. Keep them editable as text.

### 2. `docs/PROTOCOL.md`

Include:

- CTAPHID packet types and fragmentation,
- `INIT`, `PING`, `CBOR`, `MSG`, `CANCEL`, `KEEPALIVE`, `ERROR`,
- CTAP2 commands:
  - `authenticatorGetInfo` (0x04),
  - `authenticatorMakeCredential` (0x01),
  - `authenticatorGetAssertion` (0x02),
  - `authenticatorGetNextAssertion` (0x08) if implemented,
- CBOR request/response examples,
- error codes,
- U2F APDU format if implemented,
- replay/framing rules for the transport.

Use real byte examples from tests where possible. Do not invent output.

### 3. `docs/BUILD_YOUR_OWN.md`

A step-by-step tutorial:

1. Prerequisites.
2. Clone and create a venv.
3. Install `cbor2`.
4. Start the mock signer.
5. Start the test daemon on port 8445.
6. Verify with `fido2-token -L` and `-I`.
7. Register a credential with `fido2-cred`.
8. Assert with `fido2-assert`.
9. Common errors and fixes.
10. How to connect the Android app.

Every command must be copy-pasteable and tested.

### 4. `docs/PRIOR_ART.md`

A fair comparison table:

- `mahirsn/passkey` — Android fingerprint as FIDO2 key on Linux; UHID, PAM,
  Bluetooth, StrongBox, Play Store; 4 stars, solo, active as of Oct 2026.
- `hparadiz/nexus-6p-biokey` — Nexus 6P, custom kernel, FIDO2 HID + fingerprint;
  one commit, hardware-specific.
- `manhavn/vrtfido` — UHID virtual FIDO2 authenticator, web CMS, PIN/fingerprint;
  0 stars, two contributors, v0.4.2.
- `0xbbuddha/Approven` — sudo/polkit approval with Android Keystore; new, not
  FIDO2/WebAuthn.
- `HMAKT99/UnTouchID` — macOS/phone approval; 340 stars, active, not Linux FIDO2.
- Any other relevant project you find.

Include date checked, stars, license, maintenance signal, and what uKey does
differently. Do not disparage other projects. Do not claim “first.”

### 5. `docs/STATUS.md`

Keep the Phase 0 table current:

- Working,
- Partial,
- Not implemented,
- Removed.

Every claim in the README must map to a row with evidence.

### 6. `docs/THREAT_MODEL.md`

Include:

- assets: private keys, biometric approval, commands, audit log,
- adversaries: local unprivileged process, network attacker, malicious app,
  stolen phone, compromised host,
- trust boundaries: Android Keystore, TLS, Unix socket, PAM,
- mitigations and residual risks,
- what is explicitly out of scope.

### 7. `docs/TESTING.md`

Document:

- unit tests,
- mock-signer integration,
- libfido2 CLI validation,
- Android tests,
- PAM tests,
- browser/SSH tests,
- package tests,
- manual hardware tests.

Include exact commands and expected results.

### 8. `docs/TALK.md`

A talk kit:

- title options,
- abstract (100–150 words),
- audience and prerequisites,
- 20–30 minute outline,
- live demo script with fallback,
- slides outline,
- Q&A,
- “what not to claim” list,
- prior-art slide,
- security-gaps slide.

Suggested framing:

> “I built a virtual FIDO2 authenticator from scratch. Here’s the protocol stack,
> the demo, the mistakes, and how it compares to existing projects.”

Do not use “first,” “unique,” or “production-ready.”

### 9. `scripts/demo.sh`

A deterministic, non-destructive demo:

- uses port 8445 and `--device-name "uKey Test"`,
- starts the mock signer,
- waits for `/dev/hidraw7`,
- runs `fido2-token -L`, `-I`,
- runs `fido2-cred -M` / `-V`,
- runs `fido2-assert -G` / `-V`,
- prints PASS/FAIL,
- traps cleanup and kills only its own PIDs,
- exits 0 on success, non-zero on failure.

It must not touch port 8443 or `/dev/hidraw6`.

### 10. `scripts/demo_phone.sh`

A checklist/helper for the phone demo:

- install the APK,
- `adb reverse tcp:8443 tcp:8443` (or the configured port),
- start the app,
- pair,
- trigger a WebAuthn/sudo request,
- show the biometric prompt,
- record a backup video.

Include a “if the phone fails, play the backup video” note.

### 11. README rewrite

Keep it short:

- one-paragraph description,
- status badge/table,
- what works / what doesn’t,
- install,
- quick demo,
- prior art,
- security and threat model link,
- license.

Remove or move aspirational claims. The README must not be longer than the code’s
actual capability.

## Acceptance criteria

1. A new contributor can clone the repo and complete the mock-signer demo in under
   15 minutes using only the docs.
2. `scripts/demo.sh` exits 0 and does not disturb the production service.
3. `docs/STATUS.md` matches the code and README.
4. `docs/PRIOR_ART.md` is accurate and fair.
5. `docs/TALK.md` has an abstract, outline, demo plan, and “do not claim” list.
6. Every command in `docs/BUILD_YOUR_OWN.md` has been run and works.
7. No unsupported claim remains in README/docs.
8. The talk kit can be used to submit to a CFP without further editing except
   event-specific details.

## Out of scope

- New protocol features.
- Packaging changes.
- Android UI redesign.
- Marketing pages that overclaim.

This phase can be done incrementally. The final pass should happen after Phases 2–4
so the docs describe what actually exists.
