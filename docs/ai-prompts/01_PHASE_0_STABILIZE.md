# Phase 0 — Stabilize, Tell the Truth, Fix Auto-Lock

Read `00_MASTER_CONTEXT.md` first. This phase is a prerequisite for every other
phase.

## Goal

Make the current project safe to run, honest about what it does, and configurable
so that phone disconnect does **not** lock or freeze the desktop unless the user
explicitly asks for auto-lock.

This phase does not add U2F, PAM, transport encryption, or packaging. It makes the
existing behavior correct and prepares the repo for those phases.

## Why this phase exists

The current systemd unit starts the daemon with `--wireless --auto-lock`. That
means:

- the daemon listens on `0.0.0.0` by default,
- when the phone disconnects, `loginctl lock-session` runs,
- users who do not want an “IoT-style” always-on phone key have no simple way to
  disable it.

The fix is not to remove the feature. The fix is to make it **opt-in**, configurable,
and well-tested.

## Tasks

### 1. Truth audit

Create `docs/STATUS.md` with a table:

| Feature | Status | Evidence | Notes |
|---|---|---|---|
| UHID virtual device | Working | `fido2-token -L` | ... |
| CTAP2 getInfo/make/getAssertion | Working | tests + `fido2-cred` | ... |
| U2F/CTAP1 / `pam_u2f` | Not implemented | `CTAPHID_MSG` returns `6D 00` | ... |
| Resident credentials | Not implemented | `rk` rejected | ... |
| Android StrongBox signer | Partial | code + APK | device-dependent |
| Host fingerprint | Detection only | logs | not authentication |
| Face scanner | Not implemented | docs mockup | remove claim |
| Audit ledger | In-memory only | `BridgeState.kt` | not tamper-proof |
| Wireless transport | Partial | TCP, unauthenticated | Phase 1 |
| Auto-lock | Partial | `loginctl` | default off after this phase |
| PAM sudo | Not implemented | script assumes U2F | Phase 2 |
| Cross-distro install | Not implemented | Fedora-only | Phase 4 |

Then audit and correct:

- `README.md`
- `docs/PAMPHLET.md`
- `docs/SENIOR_EVALUATION_GUIDE.md`
- `docs/index.html` and `docs/pamphlet.html` if they repeat the same claims
- `scripts/senior_demo.sh` output text

Rules:

- Remove or mark as “Roadmap” anything not implemented.
- Keep the honest “Security and scope” content at the bottom of the README.
- Do not delete useful documentation; move aspirational material to
  `docs/ROADMAP.md` if needed.
- Add a `docs/THREAT_MODEL.md` with assets, adversaries, trust boundaries, and
  known gaps. It can be short but must be accurate.

### 2. Add configuration

Add a config module, e.g. `daemon/ukey_config.py`, with defaults:

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

Requirements:

- Default config path: `~/.config/ukey/config.json`.
- Override with `UKEY_CONFIG` environment variable.
- Create the file with mode `0600` on first run if needed.
- CLI flags override config:
  - `--auto-lock` enables auto-lock.
  - `--no-auto-lock` disables it and wins over config.
  - `--auto-lock-grace SECONDS` sets the grace period.
  - `--wireless` enables LAN binding.
  - `--no-wireless` disables it.
  - `--listen-host` and `--port` still work.
- Validate values. Reject negative grace periods and invalid ports.
- Log the effective configuration at startup without secrets.

### 3. Fix auto-lock behavior

Current code: `UKeyDaemon._on_signer_disconnect()` calls
`loginctl lock-session` if `--auto-lock` is set.

New behavior:

1. Auto-lock is **off by default**.
2. If disabled, a phone disconnect must:
   - fail in-flight authentication closed with a CTAP error,
   - leave the desktop session unlocked and usable,
   - log that auto-lock is disabled (debug/info, not a warning storm).
3. If enabled, lock only when all of these are true:
   - a phone/signer was successfully connected at least once,
   - it disconnected,
   - it stayed disconnected for `auto_lock_grace_seconds`,
   - the daemon is not shutting down/restarting.
4. If the phone reconnects within the grace period, cancel the pending lock.
5. Debounce duplicate disconnect events so `loginctl` is called at most once per
   disconnect episode.
6. Do not lock if the session is already locked.
7. Use a single timer/thread or event; do not spawn an unbounded number of
   threads.
8. Log the decision and the reason.

Implement this without breaking the existing signer reconnect behavior.

### 4. Fix disconnect/reconnect during requests

When the phone disconnects while `makeCredential` or `getAssertion` is in flight:

- The request must fail within a bounded timeout (target: 10 seconds or less).
- Return a proper CTAP2 error (`CTAP2_ERR_OTHER` or
  `CTAP2_ERR_KEEPALIVE_CANCEL` as appropriate), not hang forever.
- The UHID device behavior must be deliberate:
  - Either keep the virtual device present and return “no signer” errors until
    reconnect, or remove/recreate it cleanly.
  - Document the choice.
- Reconnecting the phone must resume operation without restarting the daemon.

Add tests for:

- disconnect during `getInfo` (should be immediate),
- disconnect during `makeCredential`/`getAssertion` (bounded failure),
- reconnect and successful `fido2-assert` afterward.

### 5. Add `ukeyctl` (minimal)

Create `scripts/ukeyctl` (Python or Bash) with:

```text
ukeyctl status
ukeyctl config get
ukeyctl config set KEY VALUE
ukeyctl doctor
ukeyctl logs
ukeyctl --version
```

Minimum behavior:

- `status` prints whether the service is active, the port, device name, effective
  wireless/auto-lock settings, and the hidraw node if present.
- `config get` prints the effective config.
- `config set auto_lock false` writes the config file atomically with mode 0600.
- `doctor` checks `/dev/uhid`, Python, `cbor2`, `fido2-tools`, `pamu2fcfg`,
  `loginctl`, and write access to the config directory. It must not install
  anything.
- `logs` prints the last 50 journal lines for the user unit (or a clear message if
  journalctl is unavailable).

Do not make `ukeyctl` require root for read-only commands.

### 6. Fix systemd unit and installer defaults

Change `systemd/ukey.service` so it does **not** hardcode `--wireless --auto-lock`.
It should use the config file and default to safe behavior.

Example:

```ini
[Service]
Type=simple
WorkingDirectory=%h/.local/share/ukey
ExecStart=%h/.local/share/ukey/.venv/bin/python %h/.local/share/ukey/daemon/ukey_daemon.py
Restart=on-failure
RestartSec=3
```

Adjust paths so the unit is portable. Do not assume `~/Desktop/ukey`.

Update `install.sh` so a fresh install:

- does not enable wireless,
- does not enable auto-lock,
- starts the service in USB/localhost mode,
- prints how to opt in:
  ```bash
  ukeyctl config set wireless true
  ukeyctl config set auto_lock true
  systemctl --user restart ukey
  ```

If the installer currently writes a unit with `--wireless --auto-lock`, fix it.

### 7. Add CI

Add `.github/workflows/test.yml`:

- Python 3.10, 3.11, 3.12.
- Install `cbor2`.
- Run `python -m unittest discover -s tests -v`.
- Run `shellcheck` on `install.sh`, `scripts/*.sh` if available.
- Run `systemd-analyze verify systemd/ukey.service` if available.
- Do not require `/dev/uhid` in CI. Unit tests must not need a real kernel device.
- Add a separate job for a mocked/fake UHID if the tests support it; otherwise
  document that hardware tests are manual.

### 8. Add `AGENTS.md`

Add a short root-level `AGENTS.md` with:

- repo layout,
- test commands,
- safety rules from `00_MASTER_CONTEXT.md`,
- “do not touch production service” warning,
- link to `docs/ai-prompts/`.

## Files likely to change

- `daemon/ukey_daemon.py`
- new `daemon/ukey_config.py`
- `systemd/ukey.service`
- `install.sh`
- `scripts/ukeyctl`
- `README.md`
- `docs/STATUS.md`
- `docs/THREAT_MODEL.md`
- `docs/ROADMAP.md` (if needed)
- `tests/` (new tests)
- `.github/workflows/test.yml`
- `AGENTS.md`

## Acceptance criteria

Run these and include output:

1. `python -m unittest discover -s tests -v` — all tests pass.
2. Start a test daemon on port 8445 with a fake `loginctl` in `PATH` and
   auto-lock disabled. Connect/disconnect the mock signer. Assert
   `/tmp/ukey-loginctl-calls` is empty.
3. Repeat with `--auto-lock --auto-lock-grace 0`. Assert exactly one
   `lock-session` call.
4. Repeat with `--auto-lock --auto-lock-grace 5`, disconnect, reconnect within 2
   seconds. Assert no `lock-session` call.
5. Disconnect during an in-flight `fido2-assert`. Assert it exits non-zero within
   10 seconds and does not hang.
6. Reconnect and complete a `fido2-assert` successfully without restarting the
   daemon.
7. `ukeyctl config get` shows `auto_lock: false` and `wireless: false` by default.
8. `systemctl --user cat ukey` (after reinstall) shows no `--wireless` or
   `--auto-lock`.
9. `docs/STATUS.md` matches the code; no README claim says a feature works when it
   does not.
10. The production service on 8443 is still running and `/dev/hidraw6` is still
    present.

## Out of scope

- U2F/CTAP1 or PAM.
- TLS/transport encryption.
- Packaging for other distros.
- New Android features.
- Resident credentials.
- Bluetooth.

Do not start Phase 1 until all acceptance checks pass.
