<div align="center">

<picture>
  <source media="(prefers-color-scheme: light)" srcset="assets/ukey-logo-black.png">
  <img src="assets/ukey-logo.png" alt="uKey" width="320">
</picture>

### Your Android phone, as a virtual FIDO2 security key for Linux

A working prototype: a Python daemon creates a USB-style HID authenticator through `/dev/uhid`, while an Android app keeps the P-256 key in AndroidKeyStore and approves signatures with a biometric prompt.

<br />

<p align="center">
  <a href="https://docs.kernel.org/hid/uhid.html"><img src="https://img.shields.io/badge/Kernel-/dev/uhid-22C55E.svg?style=flat-square&logo=linux&logoColor=white" alt="Linux Kernel /dev/uhid"></a>
  <a href="https://developer.android.com/privacy-and-security/keystore"><img src="https://img.shields.io/badge/Android-AndroidKeyStore-10B981.svg?style=flat-square&logo=android&logoColor=white" alt="AndroidKeyStore"></a>
  <a href="https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html"><img src="https://img.shields.io/badge/Protocol-FIDO2%20%2F%20CTAP2-06B6D4.svg?style=flat-square" alt="FIDO2 / CTAP2"></a>
  <a href="https://github.com/ukey-sh/ukey/actions"><img src="https://img.shields.io/badge/Tests-39%20passed-brightgreen.svg?style=flat-square" alt="Tests"></a>
  <a href="https://www.gnu.org/licenses/gpl-3.0"><img src="https://img.shields.io/badge/License-GPLv3-blue.svg?style=flat-square" alt="License: GPLv3"></a>
</p>

**[Website](https://ukey.sh)** · **[Status](docs/STATUS.md)** · **[Threat model](docs/THREAT_MODEL.md)** · **[Quickstart](#quickstart)** · **[Architecture](#architecture)**

</div>

---

> **Prototype status.** CTAP2 `getInfo`, `makeCredential`, and `getAssertion` are implemented and exercised with libfido2 and the repository tests. PAM/`sudo`, browser WebAuthn, SSH `ecdsa-sk`, U2F/CTAP1, resident credentials, and encrypted transport are **not working or not verified end-to-end**. [`docs/STATUS.md`](docs/STATUS.md) is the source of truth; the website and this README summarize it.

---

## What works today

| Area | State | Evidence |
|---|---|---|
| UHID virtual device | **Working** | `fido2-token -L` / `-I` show a `FIDO_2_0` token on a `/dev/hidraw` node |
| CTAPHID framing | **Working** | `tests/test_phase1.py`; INIT, PING, CBOR, CANCEL, KEEPALIVE, fragmentation |
| CTAP2 `getInfo` | **Working** | Python tests; `fido2-token -I` |
| CTAP2 `makeCredential` | **Working** | Python tests; `fido2-cred -M` / `-V`; non-resident, packed self-attestation |
| CTAP2 `getAssertion` | **Working** | Python tests; `fido2-assert -G` / `-V`; ES256 |
| Phone pairing | **Working** | `tests/test_pairing.py`; one-time 6-digit PIN, 256-bit device token, lockout, revoke |
| Android signer | **Partial** | Kotlin source and unit tests; StrongBox preferred, TEE fallback; not independently audited |
| Credential metadata | **Working** | `~/.config/ukey/credentials.json`; credential ID, RP ID, public key; unencrypted |
| Local controls | **Working** | `ukeyctl` menu/status/config/doctor; dashboard on `127.0.0.1:8444` |
| Auto-lock | **Opt-in** | `tests/test_auto_lock.py`; convenience feature, not a security boundary |
| Fedora installer | **Partial** | `install.sh`; verified on Fedora 43, other distros are best-effort |

## What is not claimed

- **PAM / `sudo` is not a working credential path.** U2F/CTAP1 is not implemented; `CTAPHID_MSG` returns `6d 00` and `caps` reports `nomsg`. The PAM setup script exists but has no working U2F path behind it.
- **Browser WebAuthn and SSH `ecdsa-sk` have no end-to-end tests in this repository.** The protocol may work, but the project does not claim daily passkey or SSH use.
- **Resident/discoverable credentials are rejected** (`rk=true`); there is no `getNextAssertion`.
- **Transport is not secured.** The signer socket is plain TCP. Pairing tokens exist, but localhost clients can skip the handshake, so loopback is not a hard boundary against a hostile local process. `--wireless` exposes that socket on the LAN.
- **There is no face scanner, audit ledger, receipt chain, or tamper-proof history.**
- **The Android signer has not been independently audited.** A full phone-to-libfido2 run needs real hardware and is not part of CI.

---

## Quickstart

The verified path is a Fedora machine with `/dev/uhid`, Python 3.10–3.12, and libfido2 installed.

```bash
git clone https://github.com/ukey-sh/ukey.git
cd ukey
./install.sh
```

`install.sh` asks for `sudo` to install the udev rule. It creates a Python virtual environment and a systemd **user** service, then starts it with safe defaults: signer bridge on `127.0.0.1:8443`, wireless off, auto-lock off.

Verify that the kernel sees the token:

```bash
fido2-token -L
fido2-token -I /dev/hidraw6   # use the node printed by -L
```

Expected: a hidraw node and `FIDO_2_0` / `ES256` details. The node number is assigned by the kernel and may differ. No success output is fabricated here.

### Other distributions

The installer has package branches for Fedora, Debian/Ubuntu, Arch, and openSUSE, but **only Fedora 43 has been verified**. On other distributions, use the manual setup path: install `libfido2` and `python3-venv`, run `./setup_udev.sh`, create the virtual environment, and start the daemon yourself. Treat the distro branches as convenience, not a support claim.

---

## Pair an Android phone

Build and install the app from `android/` with Gradle, then connect it over USB:

```bash
adb reverse tcp:8443 tcp:8443
./scripts/ukeyctl pair
```

Enter the one-time 6-digit PIN shown by `ukeyctl pair` in the app. Pairing returns a 256-bit device token that the phone stores for later connections. The PIN is single-use, rotates when a new PIN is requested, and is invalidated after five failed attempts. `./scripts/ukeyctl devices` lists paired phones and can revoke a token.

The Android signer is the partial part of the project: StrongBox is preferred, TEE is the fallback, software-backed keys are rejected, and every assertion is gated by a `BiometricPrompt`. It is built and unit-tested, but not audited.

### Local controls

```bash
./scripts/ukeyctl status
./scripts/ukeyctl doctor
./scripts/ukeyctl menu          # interactive terminal control center
./scripts/ukeyctl web           # http://127.0.0.1:8444
```

The dashboard and CLI bind to loopback. They can toggle biometric interception, show a pairing PIN, list/revoke devices, and read recent logs.

---

## Architecture

```
Linux host
  libfido2 / fido2-*  ──►  /dev/hidrawN  ◄──  Linux kernel /dev/uhid
                                                    ▲
                                                    │ HID reports
                                      uKey Python daemon
                                        ├─ CTAPHID framing
                                        ├─ CTAP2 engine
                                        ├─ credential metadata
                                        ├─ pairing manager
                                        ├─ signer bridge (TCP :8443)
                                        └─ local dashboard (:8444)
                                                    ▲
                                                    │ TCP: adb reverse or LAN
                                                    ▼
                                      Android app (partial signer)
                                        ├─ pairing / token auth
                                        ├─ BiometricPrompt
                                        └─ AndroidKeyStore P-256 key
                                             ├─ StrongBox preferred
                                             └─ TEE fallback
```

The daemon owns no private keys. It asks the signer to sign; the phone gates that operation behind the biometric prompt and keeps the key in AndroidKeyStore.

---

## Tests

```bash
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m py_compile daemon/*.py scripts/ukeyctl
bash -n install.sh setup_udev.sh scripts/setup_pam_sudo.sh
```

39 tests currently pass. Coverage includes CTAPHID framing, CBOR canonicalization, CTAP2 make/assert, configuration validation, auto-lock behavior, pairing/token auth, and the signer bridge. CI runs Python 3.10–3.12 plus shell and systemd syntax checks.

Hardware checks — a real `/dev/uhid`, a hidraw node, and a phone-to-libfido2 assertion — are manual. They are not part of CI and should not be described as passing unless they actually ran.

---

## Security boundaries

Safe defaults matter more than feature lists:

- `wireless: false` and `listen_host: 127.0.0.1`; keep the signer on `adb reverse` unless you accept a plaintext LAN socket.
- `auto_lock: false` by default. Auto-lock is convenience, not an authentication control.
- Credential metadata in `credentials.json` is unencrypted. It is readable by the local user and root; the private key is not in that file.
- Local clients that skip the pairing handshake are accepted as a **Localhost Mock**. The bridge is not a hard security boundary against a hostile local process.
- The Android app, biometric flow, and protocol edge are self-reviewed, not independently audited. There is no attestation chain or vendor certificate.
- Pairing authenticates the phone, but the channel is not encrypted. Transport hardening is roadmap work.

Read [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the full list.

---

## License

GPL-3.0. See [`LICENSE`](LICENSE).

Developed by **BYN Siddharth Sai** and contributors.
