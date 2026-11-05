# Phase 6 — Optional Hardening and Advanced Features

Read `00_MASTER_CONTEXT.md`. Do not start this phase until Phases 0–3 pass.

This phase is optional. Pick one item at a time. Do not turn it into a feature
sprawl. Each item must ship with tests, docs, and a security note.

## 6.1 Resident credentials and `getNextAssertion`

Goal: browser passkey parity.

Tasks:

- Implement `rk=true` in `authenticatorMakeCredential`.
- Persist discoverable credentials with:
  - credential ID,
  - RP ID,
  - user ID,
  - user name/display name,
  - private-key alias,
  - sign counter,
  - created/updated timestamps.
- Implement `authenticatorGetAssertion` without an allow list.
- Implement `authenticatorGetNextAssertion` (0x08) with correct request ownership
  and timeout.
- Enforce a maximum credential count and return the proper CTAP error when full.
- Add credential management:
  - list,
  - delete,
  - delete-all for an RP,
  - enumerate RPs.
- Tests:
  - make resident credential,
  - assert without allow list,
  - multiple credentials + `getNextAssertion`,
  - delete and re-enumerate,
  - persistence across restart.

Acceptance:

- A browser can register and use a discoverable passkey.
- `getNextAssertion` returns the expected credentials in order.
- Credential storage is `0600` and does not contain private keys.

## 6.2 CTAP2 PIN/UV

Goal: support `clientPin` and PIN-based UV where required.

Tasks:

- Implement PIN protocol 1 and/or 2:
  - `getPINRetries`,
  - `getKeyAgreement`,
  - `setPIN`,
  - `changePIN`,
  - `getPINToken`.
- Store PIN verifier and retry counter securely.
- Enforce retry limits and power-cycle behavior.
- Integrate with the Android biometric prompt where appropriate.
- Tests for wrong PIN, retry exhaustion, PIN change, token use.
- Document that phone biometric is still the primary UV path.

Acceptance:

- `fido2-token -S` / PIN operations work as expected.
- PIN retries decrement and reset correctly.
- No PIN is logged or stored in plaintext.

## 6.3 StrongBox attestation and key binding

Goal: make the hardware-backed claim real.

Tasks:

- Generate a StrongBox/TEE attestation certificate chain if the device supports
  it.
- Return packed attestation with a real attestation object.
- Document the difference between self-attestation and hardware attestation.
- Review `setInvalidatedByBiometricEnrollment(false)`:
  - either remove it (keys invalidate when biometrics change),
  - or document the trade-off and add a setting.
- Add a test/verification command that reports the security level (`StrongBox`,
  `TEE`, `Software`).
- Do not claim a vendor-certified chain unless one exists.

Acceptance:

- `fido2-token -I` still works.
- Attestation object verifies with a test tool.
- The security level is reported accurately.
- Key invalidation behavior is documented.

## 6.4 Bluetooth transport

Goal: parity with `passkey` for cable-free use.

Tasks:

- Choose BLE GATT or RFCOMM. Document why.
- Pairing and authentication must reuse the Phase 1 pairing/TLS model where
  possible.
- Do not add an unauthenticated Bluetooth channel.
- Handle reconnect, suspend/resume, and adapter state.
- Tests on at least two Android devices if possible.
- Document battery impact.

Acceptance:

- Paired phone connects over Bluetooth.
- Unpaired device cannot authenticate.
- `fido2-cred` / `fido2-assert` work over Bluetooth.
- USB/Wi-Fi paths still work.

## 6.5 Multi-device support

Goal: more than one phone can approve.

Tasks:

- Register multiple devices.
- Ask all connected devices in parallel; first approval wins.
- Cancel pending requests on other devices.
- Prevent replay across devices.
- Add `ukeyctl devices` status and priority.
- Tests for two simulated signers.

Acceptance:

- First approval succeeds; late approvals are ignored.
- Denial from one device does not cancel another unless configured.
- No duplicate signatures.

## 6.6 BLE proximity auto-lock

Goal: make auto-lock smoother than “TCP disconnected.”

Tasks:

- Use BLE RSSI or connection state as a proximity signal.
- Add hysteresis and a grace period.
- Do not lock on transient RSSI drops.
- Keep the Phase 0 config option: auto-lock remains opt-in.
- Add a manual `ukeyctl lock` / `ukeyctl unlock` command.
- Tests with simulated RSSI values.

Acceptance:

- Walking away locks after the configured grace.
- Returning and biometric auth unlocks.
- Auto-lock off means no lock, ever.

## 6.7 Policy engine

Goal: per-service authentication policy.

Tasks:

- Config for:
  - services requiring UV,
  - services requiring user presence,
  - rate limits,
  - lockout thresholds,
  - allowed RPs,
  - command redaction patterns.
- Enforce in the daemon/PAM path.
- Audit policy decisions.
- Tests for allow/deny.

Acceptance:

- Policy is enforced consistently.
- Defaults preserve password fallback.
- Misconfiguration fails safe, not open.

## 6.8 Fuzzing and security review

Goal: find parser bugs before attackers do.

Tasks:

- Add fuzz targets for:
  - CTAPHID framing,
  - CTAP2 CBOR,
  - U2F APDU,
  - transport framing.
- Use `atheris`, `hypothesis`, or `cargo fuzz` as appropriate.
- Run in CI with a time limit.
- Add a `SECURITY.md` with disclosure policy.
- Commission an external review if possible.
- Fix findings and document residual risk.

Acceptance:

- Fuzz targets run without crashes for the CI time budget.
- Known crashes are fixed or documented.
- `SECURITY.md` exists.

## Rules for this phase

- One item per branch/PR.
- Do not start a new item until the previous one passes.
- Every item updates `docs/STATUS.md` and `docs/THREAT_MODEL.md`.
- No feature is “done” without a test and a manual verification note.
- If a feature cannot be made secure, do not ship it. Document why.
