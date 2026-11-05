# Phase 2 — U2F/CTAP1 or a Real PAM Module

Read `00_MASTER_CONTEXT.md` and complete Phases 0–1 first.

## Goal

Make Linux authentication real. After this phase, a user should be able to use uKey
for `sudo`, polkit, and login through PAM, and the project’s `sudo` claim must be
backed by a working command.

Pick **one** implementation path:

- **Preferred:** implement U2F/CTAP1 in the daemon so the standard `pam_u2f` and
  `pamu2fcfg` tools work.
- **Alternative:** write a small custom PAM module that calls libfido2
  `get_assert` against uKey’s virtual device (similar to `mahirsn/passkey`).

Do not do both in one phase. Document the decision and why.

## Why this matters

`pam_u2f` speaks U2F/CTAP1 over `CTAPHID_MSG` (0x03). The current daemon returns
`6D 00` (“instruction not supported”) for `CTAPHID_MSG`, so registration and
authentication fail. Until this is fixed, the README must not claim working PAM
`sudo`.

## Option A — U2F/CTAP1 implementation

### Protocol

Implement in `daemon/ukey_daemon.py` (or a new `daemon/u2f.py`):

- `CTAPHID_MSG` (0x03) request/response.
- APDU parsing:
  - short and extended length encoding,
  - `Lc`, `Le`,
  - ISO 7816 status words `SW1SW2`.
- U2F commands:
  - `U2F_VERSION` (INS 0x03) → `U2F_V2` + `9000`.
  - `U2F_REGISTER` (INS 0x01):
    - request: challenge parameter (32 bytes), application parameter (32 bytes),
    - response: reserved byte `0x05`, public key (65-byte uncompressed P-256),
      key handle length, key handle, attestation certificate (DER), signature.
  - `U2F_AUTHENTICATE` (INS 0x02):
    - request: challenge parameter (32), application parameter (32), key handle
      length, key handle, control byte.
    - control byte:
      - `0x07` check-only,
      - `0x03` enforce user presence,
      - `0x08` don’t enforce user presence.
    - response: user-presence byte, counter (4-byte big-endian), signature.
- Error statuses:
  - `0x6D00` INS not supported,
  - `0x6E00` CLA not supported,
  - `0x6700` wrong length,
  - `0x6A80` bad key handle,
  - `0x6985` user presence required / test of user presence failed,
  - `0x6A81` wrong data,
  - `0x6982` security status not satisfied.

### Credentials

- Key handle can be a random 32-byte ID mapped to a stored credential, or a
  wrapped/encrypted private key. Choose one and document it.
- Store credential metadata in `~/.config/ukey/credentials.json` with mode `0600`.
- The private key must remain in Android Keystore/StrongBox. Do not export it.
- The U2F signature must be produced by the Android signer, not by a host-side
  key, in the real flow. The mock signer may be used for tests.
- Maintain a per-credential signature counter and persist it.
- Bind the credential to the application parameter (RP ID hash).
- Ensure key handles survive daemon restarts.

### Attestation

- Use a self-signed attestation certificate generated at first run, or a fixed
  test certificate for the mock signer.
- Document that this is self-attestation, not a vendor-certified chain.
- `pamu2fcfg` may not require a trusted chain; verify behavior.

### PAM integration

- Update `scripts/setup_pam_sudo.sh` to:
  - detect `pam_u2f` availability,
  - back up the target PAM file with a timestamp,
  - use the correct mechanism per distro (`pam-auth-update` on Debian/Ubuntu,
    `authselect` on Fedora where applicable, direct file edit otherwise),
  - be idempotent,
  - provide an uninstall path,
  - never leave `sudo` unusable.
- Add `ukeyctl pam install`, `ukeyctl pam uninstall`, `ukeyctl pam status`.
- Default PAM mode must preserve password fallback. Do not make phone-only auth the
  default on the first install.

### Tests

- `pamu2fcfg` produces a valid credential line against the test daemon.
- `pam_u2f` approves a test PAM service.
- Wrong key handle fails.
- Check-only request does not increment the counter or require touch.
- Enforce request requires user presence/biometric approval.
- Counter increments and persists across daemon restart.
- A credential registered for one app ID fails for another.
- `fido2-token -I` and the CTAP2 make/assert flow still work.

## Option B — Custom PAM module

If U2F is too large, implement a custom PAM module instead. Requirements:

- `pam_sm_authenticate` in C or Rust.
- Registration CLI: `ukeyctl register` (or `ukey register`).
- Authfile format compatible with the project’s own module; document it.
- Ask all connected devices in parallel; first approval wins.
- Verify the assertion signature on the host with libfido2 or a small verifier.
- Timeout and password fallback.
- `mode=on-empty` and `mode=parallel` if you want parity with `passkey`.
- Keep a root shell open during all PAM tests.

## Browser and OpenSSH verification

Do not claim these until tested:

- Chrome/Chromium and Firefox WebAuthn registration and login.
- `ssh-keygen -t ecdsa-sk` and an actual SSH authentication.
- If a path does not work, either fix it or remove the claim from the README.

Record the exact commands and output in `docs/TESTING.md`.

## Acceptance criteria

1. `pamu2fcfg` succeeds and prints a credential line.
2. `pam_u2f` (or the custom PAM module) approves `sudo` for a test user.
3. Denying or timing out the phone fails authentication.
4. Password fallback still works if the phone is unavailable.
5. `sudo` is not broken for the normal password path.
6. Counter and credential persistence survive a daemon restart.
7. `fido2-token -I`, `fido2-cred`, and `fido2-assert` still pass.
8. Browser and SSH results are documented with commands.
9. README no longer claims PAM unless it is actually working.

## Out of scope

- Context-aware command display (Phase 3).
- Packaging (Phase 4).
- Resident credentials and `getNextAssertion` (Phase 6).
- PIN/UV (Phase 6).

Do not start Phase 3 until Phase 2 acceptance checks pass.
