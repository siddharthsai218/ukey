# AGENTS.md

Operating notes for AI agents and contributors working in this repository.

## What this is

uKey is a prototype virtual FIDO2 authenticator. A Python daemon creates a
virtual HID device over `/dev/uhid`; an Android app holds the P-256 key in
AndroidKeyStore and signs CTAP2 requests. The current scope is CTAP2
`getInfo` / `makeCredential` / `getAssertion` over USB (via `adb reverse`) or
TCP.

Read `README.md`, `docs/STATUS.md`, and `docs/THREAT_MODEL.md` before changing
behavior. `docs/STATUS.md` is the source of truth for what works.

## Repository layout

```
daemon/
  ukey_daemon.py     UHID + CTAPHID + CTAP2 engine, TCP signer bridge
  ukey_config.py     JSON config: validation, safe defaults, atomic 0600 save
  mock_signer.py     deterministic software signer for tests and demos
android/             Kotlin app; AndroidKeyStore key + biometric prompt
scripts/ukeyctl      status / config get|set / doctor / logs
systemd/             portable user-service template
tests/               test_phase1.py, test_config.py, test_auto_lock.py
docs/                index.html (public site), STATUS, THREAT_MODEL, design notes
docs/ai-prompts/     phase-by-phase implementation prompts (not linked publicly)
install.sh           Fedora-only user installer using safe defaults
setup_udev.sh        installs the /etc/udev/rules.d/70-ukey.rules permission rule
```

## Test commands

Use the project virtual environment. The system Python usually lacks `cbor2`.

```bash
cd /home/siddharth/Desktop/ukey
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m py_compile daemon/ukey_daemon.py daemon/ukey_config.py scripts/ukeyctl
bash -n install.sh setup_udev.sh
```

Hardware checks need `/dev/uhid` and access to a hidraw node; they are manual,
not part of CI. See the "Validation" section of `README.md`.

CI is `.github/workflows/test.yml` (Python 3.10–3.12, shell syntax, systemd unit
syntax). It does not require real hardware.

## Non-negotiable safety rules

1. **Do not disturb the production service.** It runs as a systemd user unit on
   port **8443** and owns **`/dev/hidraw6`**. Never run `pkill -f ukey_daemon`,
   `systemctl --user stop ukey`, or kill its PID. Use a separate test daemon on
   port **8445** with `--device-name "uKey Test"`, which appears as
   `/dev/hidraw7`. Kill only PIDs you started.
2. **Do not overwrite `/dev/hidraw6`.** Treat it as read-only from the test
   harness.
3. **Do not test PAM on your only login path.** Keep a root shell open and back
   up PAM files. Prefer a VM, container, or throwaway user.
4. **Do not make destructive filesystem changes without asking.** No `rm -rf` on
   home or config directories, and do not delete credentials.
5. **Do not commit generated artifacts or secrets.** No `.venv/`, Android build
   output, `*.apk`, `*.pem`, `*.key`, `credentials.json`, logs, or tokens.
6. **No telemetry, cloud relays, analytics, or hidden network calls.**
7. **Do not fake demos, screenshots, logs, or test output.**
8. **Do not claim "first," "unique," "tamper-proof," "tri-modal," "zero cloud,"
   or "production ready"** unless the exact claim is implemented and tested.
   Mark partial, untested, and design-only work explicitly.
9. **Keep GPL-3.0 compatibility.** Attribute adapted code and preserve licenses.
10. **Small commits.** One phase or one coherent change per commit; do not mix
    documentation rewrites with unrelated behavior changes.

## Configuration and defaults

The daemon reads `~/.config/ukey/config.json` (override with `UKEY_CONFIG`).
Defaults are intentionally safe:

```json
{
  "wireless": false,
  "auto_lock": false,
  "auto_lock_grace_seconds": 5,
  "listen_host": "127.0.0.1",
  "port": 8443,
  "device_name": "uKey FIDO2 Authenticator"
}
```

CLI flags override the file. `--wireless` binds `0.0.0.0`; it adds no transport
security. Auto-lock is opt-in and is not a security boundary. Use
`scripts/ukeyctl` instead of editing JSON by hand when possible.

## Honesty rules for docs and demos

- Describe only behavior that is implemented and, where possible, tested.
- Keep the status table in `docs/STATUS.md` aligned with the website and README.
- The phone context-approval flow is design-only (`docs/CONTEXT_DISPLAY.md`).
- U2F/CTAP1, resident credentials, transport encryption, and PAM `sudo` do not
  work today. `CTAPHID_MSG` returns `6d 00`; `caps` reports `nomsg`.
- Browser WebAuthn and SSH `ecdsa-sk` have no end-to-end tests in this repo.

## Where to start

`docs/ai-prompts/00_MASTER_CONTEXT.md` is the entry point for planned work.
It links the phase prompts for stabilization, protocol work, Android, PAM,
packaging, and hardening. Treat those prompts as plans, not as evidence that a
feature exists.
