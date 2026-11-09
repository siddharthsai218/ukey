# uKey Implementation Status

Verified against Fedora 43 with libfido2 1.15.0 and 39 passing unit tests.

This document tracks the implementation status of core subsystems, protocol engines, and integration workflows across the uKey project.

---

## Shipped & Verified Today

These components are fully implemented, covered by automated test suites, and verified against standard Linux FIDO2 tools (`libfido2`).

| Subsystem | Feature | Implementation & Verification |
|---|---|---|
| **Kernel Interface** | UHID virtual device | Creates a `/dev/hidraw` node via `/dev/uhid` recognized by the kernel as a genuine USB HID security key (`0x1209`). Verified with `fido2-token -L`. |
| **Protocol Framing** | CTAPHID layer | Full framing support for `INIT`, `PING`, `CBOR`, `CANCEL`, and `KEEPALIVE` across 64-byte USB HID reports with channel ID multiplexing and fragmentation. Verified in `tests/test_phase1.py`. |
| **Authenticator Core** | CTAP2 `getInfo` | Implements authenticator discovery reporting `FIDO_2_0`, `ES256` (alg -7), and standard capability flags. Verified with `fido2-token -I`. |
| **Authenticator Core** | CTAP2 `makeCredential` | Generates authenticator credentials with packed self-attestation and clientDataHash binding. Verified with `fido2-cred -M` and test suite. |
| **Authenticator Core** | CTAP2 `getAssertion` | Processes cryptographic challenge assertions, converting raw P-256 `r ‖ s` signatures to DER format at the protocol boundary. Verified with `fido2-assert -G`. |
| **Test Infrastructure** | Deterministic Mock Signer | P-256 test double for headless testing and automated continuous integration. Exercised in `tests/`. |
| **Device Pairing** | Single-Use PIN & Token | 6-digit one-time pairing PIN issuing a 256-bit device token. Includes 5-attempt brute-force lockout and instant token revocation. Verified in `tests/test_pairing.py`. |
| **Android Client** | Hardware KeyStore Signer | Native Kotlin client utilizing `AndroidKeyStore` with StrongBox preference and TEE fallback (rejecting software keys). Each assertion triggers a `BiometricPrompt`. |
| **Local Storage** | Credential Metadata | Stores credential mappings in `~/.config/ukey/credentials.json` with restricted `0600` POSIX permissions. Private keys never leave the phone enclave. |
| **Local Controls** | `ukeyctl` & Web Dashboard | CLI management tool (`status`, `doctor`, `config`, `menu`) and local loopback console at `127.0.0.1:8444` for pairing, revocation, and master pause control. |
| **Session Control** | Auto-lock Engine | Debounced proximity detection with grace period and reconnect cancellation. Verified in `tests/test_auto_lock.py`. |
| **Continuous Integration** | Automated Test Suite | 39 automated unit tests running against Python 3.10–3.12, with shell and systemd service validation. |

---

## In Active Development

These features and workflows are currently under active development and testing.

| Feature | Focus Area | Status |
|---|---|---|
| **Browser WebAuthn** | Host Integration | End-to-end browser passkey registration and assertion flow across Chromium and Firefox. |
| **OpenSSH `ecdsa-sk`** | Host Integration | Standard hardware-backed SSH key generation (`ssh-keygen -t ecdsa-sk`) and authentication. |
| **CTAP1 / U2F Layer** | Protocol Depth | Backward compatibility layer for legacy PAM login modules (`pam_u2f`). |
| **Resident Credentials** | Protocol Depth | Discoverable credentials (`rk=true`) and multi-account selection via `getNextAssertion`. |
| **Mutual Transport Auth** | Security Hardening | Cryptographic mutual handshake for the local bridge channel. |
| **Multi-Distro Packaging** | Deployment | Automated package builds for Debian, Ubuntu, Arch Linux, and openSUSE. |

---

## How to Verify

Run the full automated test suite:

```bash
cd ukey
.venv/bin/python -m unittest discover -s tests -v
```

Verify that the Linux kernel exposes the virtual security key:

```bash
fido2-token -L
fido2-token -I /dev/hidraw6   # Replace with the node returned by -L
```
