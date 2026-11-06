---
last_mapped_commit: 20aa48b012b01497d738980fff0dad10a7d85b96
last_mapped_at: 2026-11-06
---
# Testing Structure & Practices

**Analysis Date:** 2026-11-06

## Test Framework & Execution

- **Framework**: Standard Python `unittest`.
- **Virtual Environment Requirement**:
  Tests must run in the repository virtualenv (`.venv/bin/python`) because standard system Python usually lacks `cbor2`:
  ```bash
  cd /home/siddharth/Desktop/ukey
  .venv/bin/python -m unittest discover -s tests -v
  ```
- **Syntax & Compilation Validation**:
  ```bash
  .venv/bin/python -m py_compile daemon/ukey_daemon.py daemon/ukey_config.py daemon/ukey_pairing.py daemon/ukey_web.py scripts/ukeyctl
  bash -n install.sh setup_udev.sh scripts/setup_pam_sudo.sh
  ```

## Test Suite Breakdown

### 1. `tests/test_phase1.py`
- Tests CTAPHID packet framing, sequence numbers, fragmentation, and reassembly.
- Tests `authenticatorMakeCredential` parameter parsing and CBOR encoding.
- Tests `authenticatorGetAssertion` parsing and response formatting.
- Tests Relying Party ID validation, user ID validation, and unsupported algorithm rejection.

### 2. `tests/test_config.py`
- Tests JSON configuration schema validation, defaults, and type casting.
- Tests CLI override precedence over configuration files.
- Tests atomic file persistence and permission enforcement (`0600`).

### 3. `tests/test_auto_lock.py`
- Tests session auto-lock behavior when the mobile signer disconnects.
- Tests grace period timing logic and screen locking triggers via `loginctl lock-session`.

### 4. `tests/test_pairing.py`
- Tests 6-digit PIN generation, 15-minute expiration, and one-time use invalidation.
- Tests 256-bit device token issuance and SHA-256 token verification.
- Tests rogue device rejection when an invalid PIN or token is supplied.

### 5. `tests/test_signer_bridge.py`
- Uses `daemon/mock_signer.py` to test TCP bridge request/response cycles.
- Tests timeout handling, keepalive packet delivery, and connection drop recovery.

## Hardware Validation (Manual / Post-Install)

Hardware checks require access to `/dev/uhid` and cannot be fully automated in standard CI:
1. **HID Node Verification**:
   ```bash
   ls -l /dev/uhid
   fido2-token -L
   ```
2. **Credential Registration Test**:
   ```bash
   pamu2fcfg -o pam://test -i pam://test
   ```
3. **OpenSSH Key Generation**:
   ```bash
   ssh-keygen -t ecdsa-sk -f ~/.ssh/id_test
   ```

## Continuous Integration (CI)

- Configured in `.github/workflows/test.yml`.
- Runs on GitHub Actions across Python 3.10, 3.11, and 3.12.
- Executes test discovery, Python syntax checks, bash linting (`bash -n`), and systemd unit verification.
