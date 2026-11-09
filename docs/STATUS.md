# uKey status

Last verified: 2026-11-04 on Fedora 43 with libfido2 1.15.0.

This file is the source of truth for what the repository implements. The
website (`docs/index.html`) and README summarize it; if they disagree, fix them.

| Feature | Status | Evidence | Notes |
|---|---|---|---|
| UHID virtual device | Working | `fido2-token -L` shows a hidraw node | The kernel sees a USB-style HID device created by the daemon. |
| CTAPHID framing | Working | `tests/test_phase1.py`; `fido2-token -I` | INIT, PING, CBOR, CANCEL, KEEPALIVE; 64-byte reports, fragmentation, channel IDs. |
| CTAP2 GetInfo | Working | Python tests; `fido2-token -I` | Reports `FIDO_2_0`, ES256, `caps: 0x0c (nowink, cbor, nomsg)`. |
| CTAP2 MakeCredential | Working | Python tests; `fido2-cred -M` / `-V` | Packed self-attestation; non-resident credentials only. |
| CTAP2 GetAssertion | Working | Python tests; `fido2-assert -G` / `-V` | ES256; raw `r || s` converted to DER at the CTAP2 boundary. |
| Mock signer | Working | `daemon/mock_signer.py`; test suite | Deterministic P-256 signer. Ephemeral keys; test double only. |
| Phone pairing | Working | `tests/test_pairing.py`; `ukeyctl pair` / `devices` | Single-use 6-digit PIN; 256-bit device token stored as a SHA-256 hash; 5-attempt/60 s lockout; revoke. Handshake is plaintext; localhost clients may bypass it. |
| Android signer | Partial | Kotlin source; Kotlin unit tests | StrongBox preferred, TEE fallback, software keys rejected; per-use biometric prompt. Not independently audited. |
| Credential metadata persistence | Working | `~/.config/ukey/credentials.json` | Credential ID, RP ID, and public key; unencrypted. Private keys stay with the signer. |
| Browser WebAuthn | Not verified | No browser end-to-end test in the repo | Do not claim daily passkey use. |
| SSH `ecdsa-sk` | Not verified | No end-to-end test in the repo | The protocol may work; the project does not claim it. |
| U2F / CTAP1 / `pam_u2f` | Not implemented | `CTAPHID_MSG` returns `6d 00`; `caps` reports `nomsg` | The PAM scripts are not a working credential path. |
| Resident credentials | Not implemented | `rk=true` is rejected | No `getNextAssertion`. |
| Host fingerprint | Detection only | `fprintd-list` in `daemon/ukey_daemon.py` | Logging/detection only; it is not an authentication factor. |
| Face scanner | Not implemented | No camera code | Remove any claim that it exists. |
| Audit ledger / receipts | Not implemented | No receipt or audit log in current code | The phone does not maintain a tamper-proof ledger. |
| Wireless transport | Partial, opt-in | `--wireless` or `wireless: true` | TCP only; unauthenticated and unencrypted. Loopback/`adb reverse` is the safe default. |
| Auto-lock | Implemented, opt-in | `tests/test_auto_lock.py` | Grace period, reconnect cancellation, debounce, shutdown guard. Off by default; not a security boundary. |
| Configuration | Implemented | `daemon/ukey_config.py`; `tests/test_config.py` | Defaults to loopback and auto-lock off. Config file mode `0600`. |
| `ukeyctl` | Implemented | `scripts/ukeyctl` | status, config get/set, doctor, logs, version. |
| Fedora installer | Partial | `install.sh` | Fedora-only; installs safe defaults. Manual setup is the portable path. |
| CI | Added | `.github/workflows/test.yml` | Python 3.10–3.12 tests, shell checks, systemd syntax check. |
| Context approval / `sudo` display | Design only | `docs/CONTEXT_DISPLAY.md` | Mockup and schema; no protocol field, PAM module, or working flow. |
| Transport authentication/encryption | Missing | Code review | The signer socket is unauthenticated and unencrypted. |

## How to verify the working claims

```bash
. .venv/bin/activate
python -m unittest discover -s tests -v
fido2-token -L
fido2-token -I /dev/hidraw6   # use the node printed above
```

For the end-to-end libfido2 flow, see the "Validation" section of the README.
It uses the mock signer, not a physical phone. The Android signer is built and
unit-tested, but a full phone-to-libfido2 run is hardware-dependent and is not
part of CI.

## Known broken or unfinished

- `CTAPHID_MSG` (U2F/CTAP1) returns `6d 00`; PAM/`sudo` does not work.
- Resident credentials (`rk=true`) are rejected.
- The signer protocol has no TLS, authentication, or peer verification.
- Browser WebAuthn and SSH `ecdsa-sk` are untested end-to-end.
- The Android signer has not been independently audited.
- The context-approval flow is a design document, not an implementation.
- The installer is Fedora-only.
