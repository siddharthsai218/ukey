# uKey — Master Context for AI Agents

You are a senior software/security engineer working on **uKey**, a Linux + Android
project that turns an Android phone into a FIDO2/CTAP2 security key for Linux.

Repository: `/home/siddharth/Desktop/ukey`
License: GPL-3.0
Primary languages: Python 3.10+ (daemon), Kotlin/Android (app), Bash (install and
operations scripts)
Target platforms: Linux (Fedora, Debian/Ubuntu, Arch) and Android 8+

Read this file before every phase. Re-verify the state instead of trusting this
document if the repo has changed.

---

## 1. Product goal

A user should be able to use their phone as a real FIDO2/CTAP2 authenticator for:

- browser WebAuthn (Chrome/Firefox),
- Linux `sudo` / polkit / login through PAM,
- OpenSSH `ecdsa-sk` keys,
- libfido2 tools (`fido2-token`, `fido2-cred`, `fido2-assert`).

The four build lanes are:

- **A — Secure wireless key:** authenticated, encrypted LAN/USB transport with
  QR/manual pairing, reconnect, and optional auto-lock.
- **B — Context-aware sudo key:** the phone displays the exact command, user, TTY,
  and host being authorized, then approve/deny with biometrics.
- **C — Teaching/reference implementation:** readable Python code, protocol docs,
  tests, demo scripts, and an honest prior-art comparison.
- **D — Cross-distro plug-and-play:** one-command install on Fedora, Debian/Ubuntu,
  and Arch, with udev, systemd user service, packages, and clean uninstall.

The project is a **security prototype**, not a production password manager. It must
fail closed for authentication, but it must not lock or freeze the desktop unless
the user explicitly enabled auto-lock.

---

## 2. Current architecture

- `daemon/ukey_daemon.py` — virtual FIDO2 authenticator over `/dev/uhid`.
  Implements UHID, CTAPHID framing, and CTAP2 `authenticatorGetInfo`,
  `authenticatorMakeCredential`, `authenticatorGetAssertion`.
- `daemon/mock_signer.py` — software P-256 signer used for tests/demos.
- `android/app/src/main/java/org/ukey/` — Android app:
  - `UKeyService.kt` — foreground TCP bridge and reconnect.
  - `crypto/KeystoreManager.kt` — P-256 AndroidKeyStore key, StrongBox preferred,
    TEE fallback, strong-biometric gating.
  - `MainActivity.kt` — `BiometricPrompt` and UI.
  - `BridgeState.kt` — in-memory transaction log and auth state.
- `tests/test_phase1.py` — 8 CTAPHID/CTAP2 tests.
- `install.sh` — currently Fedora-only installer (`rpm`/`dnf`).
- `systemd/ukey.service` — currently starts with `--wireless --auto-lock`.
- `scripts/setup_pam_sudo.sh` — configures `pam_u2f`; assumes U2F support.
- `scripts/senior_demo.sh` — interactive demo.
- `docs/` — README, product guide, pamphlet, evaluation guide.

---

## 3. Verified current state (2026-11-04)

These were verified before this prompt pack was written. Re-run them before
relying on them.

- Python tests pass: 8/8.
  ```bash
  cd /home/siddharth/Desktop/ukey
  python -m unittest discover -s tests -v
  ```
- A test daemon on port 8445 with `--device-name "uKey Test"` creates
  `/dev/hidraw7`.
- `fido2-token -L` lists the device.
- `fido2-token -I /dev/hidraw7` reports `FIDO_2_0`, `es256`, and an AAGUID.
- `fido2-cred -M` / `-V` and `fido2-assert -G` / `-V` pass against the test
  daemon with `daemon/mock_signer.py`.
- Android APK exists at
  `android/app/build/outputs/apk/debug/app-debug.apk`.
- The production service `ukey.service` is running as a systemd user unit on port
  8443 and `/dev/hidraw6`, started with `--wireless --auto-lock`.

---

## 4. Known gaps and bugs

These are real. Do not pretend they are fixed.

### Protocol / authentication

- **No U2F/CTAP1.** `CTAPHID_MSG` in `daemon/ukey_daemon.py` returns `6D 00`.
  `pamu2fcfg` / `pam_u2f` likely fail. The README’s `sudo` claim is not supported.
- **No resident credentials.** `authenticatorMakeCredential` rejects `rk=true`
  with `CTAP2_ERR_UNSUPPORTED_OPTION`.
- **No `authenticatorGetNextAssertion`.** Multiple assertions are not supported.
- **No CTAP2 PIN/UV protocol.** The Android biometric prompt is used, but there is
  no `clientPin` implementation.
- **No attestation chain.** Self-attestation only; no vendor-certified chain.
- **No transport security.** The signer TCP socket is unauthenticated and
  unencrypted. `--wireless` binds `0.0.0.0`.
- **No replay protection** on the signer bridge.

### Auto-lock / disconnect behavior

- `systemd/ukey.service` hardcodes `--wireless --auto-lock`.
- `UKeyDaemon._on_signer_disconnect()` calls `loginctl lock-session` whenever the
  phone disconnects if auto-lock is enabled.
- There is no CLI/config option to disable auto-lock without editing the unit.
- Disconnect during an in-flight `fido2-*` request can hang or produce a poor
  error. It must fail closed with a normal CTAP error within a bounded timeout.
- The desktop must not lock or freeze on phone disconnect unless auto-lock is
  explicitly enabled.

### Packaging / operations

- `install.sh` is Fedora-only (`rpm`, `dnf`).
- `systemd/ukey.service` hardcodes `%h/Desktop/ukey`, so it is not portable.
- No `.deb`, `.rpm`, or Arch package.
- No CI.
- No `ukeyctl` status/config/uninstall command.
- udev setup assumes a local checkout.

### Claims / documentation

- README claims “tri-modal biometrics,” a “tamper-proof audit ledger,” “zero
  cloud,” and working PAM `sudo`. Most of that is not implemented.
- Host fingerprint support is detection/logging only.
- Face scanner is a docs mockup.
- Audit ledger is in-memory on Android.
- “USB” is `adb reverse`; Wi-Fi is unauthenticated.
- `setInvalidatedByBiometricEnrollment(false)` weakens key binding and needs a
  security review.
- `docs/PAMPHLET.md` and `docs/SENIOR_EVALUATION_GUIDE.md` contain claims that
  exceed the implementation.

---

## 5. Non-negotiable safety rules

1. **Do not kill the production service.**
   Never run `pkill -f ukey_daemon`, `systemctl --user stop ukey`, or kill the
   production service PID (find it with
   `systemctl --user show -p MainPID ukey`). Use a separate test daemon on port
   8445 with `--device-name "uKey Test"`. Kill only the PIDs you started.
2. **Do not overwrite `/dev/hidraw6`.**
   The production device is `/dev/hidraw6`. Test devices appear as
   `/dev/hidraw7` or later.
3. **Do not test PAM on your only login path.**
   Keep a root shell open. Back up PAM files. Prefer a VM/container or a test
   user. `sudo` misconfiguration can lock you out.
4. **Do not make destructive filesystem changes without asking.**
   No `rm -rf` on home/config directories. No deleting credentials.
5. **Do not commit generated artifacts or secrets.**
   No `.venv/`, `android/app/build/`, `*.apk`, `*.pem`, `*.key`,
   `credentials.json`, logs, or tokens.
6. **Do not add telemetry, cloud relays, analytics, or hidden network calls.**
7. **Do not fake demos, screenshots, logs, or test output.**
8. **Do not claim “first,” “unique,” “tamper-proof,” “tri-modal,” or “production
   ready” unless the exact claim is implemented and tested.**
9. **Keep GPL-3.0 compatibility.** If you adapt code from another project,
   attribute it and preserve the license.
10. **Small commits, one phase per branch.** Do not mix unrelated changes.

---

## 6. Test environment

### Python unit tests

```bash
cd /home/siddharth/Desktop/ukey
python -m unittest discover -s tests -v
```

Expected: 8 tests pass at baseline (more after new phases).

### Test daemon on a separate port

Terminal A:

```bash
cd /home/siddharth/Desktop/ukey
.venv/bin/python daemon/ukey_daemon.py \
  --port 8445 \
  --device-name "uKey Test" \
  --verbose
```

Terminal B:

```bash
cd /home/siddharth/Desktop/ukey
.venv/bin/python daemon/mock_signer.py --port 8445 --verbose
```

Then:

```bash
fido2-token -L
# Expect: /dev/hidraw7 ... ( uKey Test)
fido2-token -I /dev/hidraw7
```

### libfido2 make/assert check

Use a temporary directory and the device path from the test daemon. The exact
commands are in `README.md` under “Validation.” At minimum, verify:

```bash
fido2-token -L
fido2-token -I /dev/hidraw7
```

and a make/assert flow with `fido2-cred` / `fido2-assert` exits 0.

### Auto-lock tests

Use a fake `loginctl` in `PATH` so tests never lock the real session:

```bash
mkdir -p /tmp/ukey-test-bin
cat > /tmp/ukey-test-bin/loginctl <<'EOF'
#!/usr/bin/env bash
echo "$*" >> /tmp/ukey-loginctl-calls
exit 0
EOF
chmod +x /tmp/ukey-test-bin/loginctl
PATH=/tmp/ukey-test-bin:$PATH ...
```

Assert the call file is empty when auto-lock is disabled, and has exactly one
`lock-session` line when auto-lock is enabled and the grace period expires.

### Android

```bash
cd /home/siddharth/Desktop/ukey/android
./gradlew test
```

If Gradle is unavailable or the Android SDK is not configured, state that
explicitly; do not claim Android tests passed.

---

## 7. Reporting format

Every phase report must include:

```
## Summary
## Files changed
## Tests run
## Manual verification
## Risks / limitations
## Follow-ups
```

Include actual command output for acceptance checks. If a check failed, say so.
Do not mark a phase complete if any acceptance criterion is unmet.

---

## 8. Scope discipline

- Implement one phase at a time.
- Do not start Phase N+1 until Phase N’s acceptance checks pass.
- If a requirement conflicts with the current architecture, document the conflict
  and propose the smallest change. Do not rewrite the whole daemon.
- If a feature cannot be completed safely, stop and report the blocker.
- Prefer working, tested, documented behavior over feature count.
