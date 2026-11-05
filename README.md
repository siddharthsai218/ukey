# uKey: a virtual FIDO2 authenticator for Linux

[![Linux Kernel /dev/uhid](https://img.shields.io/badge/Kernel-/dev/uhid-blue.svg)](https://docs.kernel.org/hid/uhid.html)
[![FIDO2 / CTAP2](https://img.shields.io/badge/Protocol-FIDO2%20%2F%20CTAP2-green.svg)](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html)
[![Android StrongBox](https://img.shields.io/badge/Hardware-Android%20StrongBox%20%2F%20TEE-orange.svg)](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setIsStrongBoxBacked(boolean))
[![Status: Prototype](https://img.shields.io/badge/Status-Prototype-orange.svg)](#status)
[![License: GPLv3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)

**uKey makes Linux believe an Android phone is a USB FIDO2 security key.** The host sees a real `/dev/hidraw` HID device. A Python daemon implements UHID, CTAPHID, and CTAP2. The private key lives in AndroidKeyStore — StrongBox preferred, TEE fallback — and every assertion requires a per-use biometric prompt on the phone.

This is a prototype and a reference implementation, not a product. The interesting part is the implementation: a virtual device, a readable protocol engine, and a remote signer. The website in [`docs/index.html`](docs/index.html) tells that story, including the gaps.

## Status

| Area | State | Evidence / limit |
|---|---|---|
| Virtual FIDO2 device | Working | UHID creates a HID device; libfido2 enumerates a hidraw node. Verified with `fido2-token -L` / `-I`. |
| CTAPHID + CTAP2 | Working | `INIT`, `PING`, `CBOR`, `CANCEL`, `KEEPALIVE`; `getInfo`, `makeCredential`, `getAssertion`. 8/8 protocol tests, 24 total. |
| Mock signer | Working | Deterministic P-256 signer for tests and demos. Ephemeral keys, not a security boundary. |
| Android signer | Partial, not audited | StrongBox preferred, TEE fallback, software-backed keys rejected; per-use biometric prompt; Kotlin unit tests. No phone-to-libfido2 run in CI. |
| Credential storage | Metadata only | Credential ID, RP ID, and public key persist in `~/.config/ukey/credentials.json`, unencrypted. Private keys stay in AndroidKeyStore. |
| Browser WebAuthn | Not claimed | No browser end-to-end test is included. |
| SSH `ecdsa-sk` | Not claimed | No end-to-end test is included. |
| PAM / `sudo` | Not yet | `CTAPHID_MSG` is not implemented; `fido2-token -I` reports `nomsg`. The credential path is unfinished. |
| Resident credentials | Unsupported | `rk=true` is rejected; no `getNextAssertion`. |
| Transport security | Missing | The signer socket is unauthenticated and unencrypted. Keep it on loopback via `adb reverse`. |
| Auto-lock | Implemented, opt-in | Grace period, reconnect cancellation, debounce, and shutdown guard. Off by default; not a security boundary. |
| Configuration | Implemented | Shared JSON config at `~/.config/ukey/config.json`, written `0600`, with loopback and auto-lock-off defaults. CLI flags override for one run. |
| Installer | Fedora-only | Installs a safe loopback service with auto-lock off. Manual setup is the portable path. |
| Context approval | Design | The phone mockup and context schema exist; no protocol field or PAM hook is wired up. |

If you need a daily-driver security key or a passkey manager, use a YubiKey, a platform passkey, or a more complete project such as [`mahirsn/passkey`](https://github.com/mahirsn/passkey). uKey is not trying to win that comparison.

## The experiment: see what you sign

FIDO2 signs a digest, not a command. The second act of this project is an experiment: capture the `sudo` command context, show it on the phone, and bind the approval signature to that exact context.

The obvious local case is weak — if you are at the laptop, you can already see the terminal. The case worth exploring is when the terminal is not the trust channel: remote sessions, unattended scripts, shared machines, or a host you do not fully trust. That work is not implemented yet. See [`docs/CONTEXT_DISPLAY.md`](docs/CONTEXT_DISPLAY.md) for the design notes.

## Safety

Do not use uKey for production credentials or anything you cannot afford to lose. The prototype has no CTAP2 PIN protocol, no resident credentials, no attestation certificate chain, no encrypted credential store, and no protection against a hostile local process attaching to the signer socket. Credential metadata is stored unencrypted in `~/.config/ukey/credentials.json`. The Android app improves the key boundary, but the wire protocol is still unauthenticated and unencrypted.

---

## Architecture Overview

```
 [ Linux Kernel: /dev/uhid ]  <--- Emulates USB HID (VID: 0x1209, PID: 0x0001)
            │
            ▼
 [ CTAPHID / CTAP2 Engine ]   <--- Handles 64-byte CBOR reports, keepalives, MakeCredential
            │
            ▼
   [ Local TCP Bridge ]       <--- 127.0.0.1:8443 (Reverse-tunneled USB or Wi-Fi)
            │
            ▼
[ Android StrongBox / TEE ]   <--- NIST P-256 Private Key generated inside silicon
            │
            ▼
   [ BiometricPrompt ]        <--- Per-use hardware biometric authorization on phone
```

## Project layout

```
ukey/
├── daemon/
│   ├── ukey_daemon.py     # UHID, CTAPHID, CTAP2 engine
│   ├── ukey_config.py     # config loading, validation, safe defaults
│   └── mock_signer.py     # software P-256 signer
├── android/               # Phase 2 hardware-backed signer
│   ├── app/src/main/java/org/ukey/
│   │   ├── MainActivity.kt
│   │   ├── UKeyService.kt
│   │   ├── BridgeState.kt
│   │   ├── Protocol.kt
│   │   ├── crypto/        # KeystoreManager, DerUtils, EcUtil, Hex
│   │   └── net/           # DaemonClient, JSON framing
│   ├── app/src/test/java/org/ukey/crypto/DerUtilsTest.kt
│   ├── build.gradle.kts
│   └── settings.gradle.kts
├── tests/
│   ├── test_phase1.py     # in-process CTAPHID/CTAP2/ECDSA tests
│   ├── test_config.py     # config validation and CLI precedence
│   └── test_auto_lock.py  # opt-in auto-lock behavior
├── scripts/
│   └── ukeyctl           # status/config/doctor/logs helper
├── systemd/ukey.service  # portable user-service template
├── setup_udev.sh          # installs /etc/udev/rules.d/70-ukey.rules
├── requirements.txt       # cbor2
└── README.md
```

## Requirements

- Linux with UHID enabled (`CONFIG_UHID=y` or `=m`); `/dev/uhid` must exist
- Python 3.10+
- `cbor2`
- For the validation commands: `fido2-tools` (libfido2), `openssl`

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

## Install (Fedora)

```bash
./install.sh
```

The installer configures `/dev/uhid` permissions, creates the project virtual
environment when needed, installs `fido2-tools` if missing, and enables a
`systemd --user` service. It writes a safe default configuration: the signer
bridge stays on loopback and auto-lock is off.

It does not enable `--wireless` or `--auto-lock`. Opt in later with
`./scripts/ukeyctl config set …` and restart the service. On other
distributions, follow the manual steps below.

## Device permissions

Run once:

```bash
sudo ./setup_udev.sh
```

This installs `/etc/udev/rules.d/70-ukey.rules`, reloads udev, and triggers the
`misc` and `hidraw` subsystems. The rules use `TAG+="uaccess"` so the
currently logged-in user gets an ACL instead of the device being world-writable.

The requested `ATTRS{name}` hidraw rule is present. On current kernels the
virtual HID parent does not expose a `name` sysfs attribute, so the script also
installs a modalias fallback:

```
KERNEL=="hidraw*", ATTRS{modalias}=="hid:b0003g0001v00001209p00000001", TAG+="uaccess", MODE="0660"
```

Check access with:

```bash
getfacl /dev/uhid /dev/hidraw*
```

If the daemon is already running when the rules are installed, restart it.

## Running

Terminal 1:

```bash
./daemon/ukey_daemon.py --verbose
```

Terminal 2 — choose one signer:

```bash
# Development: ephemeral software keys
./daemon/mock_signer.py --verbose

# Or: the Phase 2 Android app (see below)
```

The daemon creates the HID device immediately; the signer can connect before or
after. The daemon log prints the hidraw node it finds, for example:

```
hidraw node: /dev/hidraw6
```

Node numbers vary by machine. Use the one printed by the daemon in the
validation commands below.

Do not run the mock signer and the Android app at the same time; the daemon
accepts one signer connection.

## Configuration

The daemon and `ukeyctl` share a small JSON configuration file:

```
~/.config/ukey/config.json
```

The file is created with mode `0600` on first run. Set `UKEY_CONFIG` to use a
different path.

Safe defaults:

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

Use `ukeyctl` to inspect or change it without editing JSON by hand:

```bash
./scripts/ukeyctl status
./scripts/ukeyctl config get
./scripts/ukeyctl config set wireless true
./scripts/ukeyctl config set auto_lock true
./scripts/ukeyctl config set auto_lock_grace_seconds 10
./scripts/ukeyctl doctor
./scripts/ukeyctl logs
```

CLI flags override the file for one run:

```bash
# Keep everything on loopback even if the config enables wireless
./daemon/ukey_daemon.py --no-wireless

# Auto-lock is opt-in; this enables it for this run
./daemon/ukey_daemon.py --auto-lock --auto-lock-grace 5

# Explicit bind address still wins
./daemon/ukey_daemon.py --listen-host 192.0.2.10
```

If the daemon is installed as a user service, change the config and restart it:

```bash
./scripts/ukeyctl config set wireless true
systemctl --user restart ukey
```

The checked-in `systemd/ukey.service` starts the daemon with no
`--wireless`/`--auto-lock` flags, so the config file is authoritative. The
installer substitutes the actual project directory into the unit before
installing it.

### Auto-lock behavior

`auto_lock` is off by default. When enabled, the daemon locks the session only
after a signer has connected at least once, then disconnected, and stayed
disconnected for `auto_lock_grace_seconds`. Reconnecting within the grace
period cancels the pending lock. Duplicate disconnect events are debounced, and
shutdown never locks the session.

This is a convenience feature, not a security boundary. A crashed daemon cannot
lock the session, and a hostile local process can already control the session.

## Android signer (Phase 2)

### Build and test

Requirements: JDK 17+ and Android SDK platform 36. Set `sdk.dir` in
`android/local.properties` (or `ANDROID_HOME`), then:

```bash
cd android
./gradlew assembleDebug
./gradlew test
```

The debug APK is written to
`android/app/build/outputs/apk/debug/app-debug.apk`. The unit tests exercise
strict DER-to-raw ECDSA conversion and credential-ID encoding.

### Install and connect over USB

From the repository root:

```bash
adb install -r android/app/build/outputs/apk/debug/app-debug.apk
adb reverse tcp:8443 tcp:8443
```

Open **uKey**, leave the host as `127.0.0.1` and the port as `8443`, then tap
**Start / Reconnect**. `adb reverse` makes that loopback address on the phone
reach the Linux daemon.

### Connect over local Wi-Fi

The daemon binds to loopback by default. To expose the bridge on the LAN:

```bash
./daemon/ukey_daemon.py --listen-host 0.0.0.0 --verbose
```

Enter the Linux host's LAN IP in the app, keep port `8443`, and make sure the
host firewall permits TCP 8443 from the phone. Only do this on a trusted
network: the signer protocol has no transport encryption or peer
authentication. USB with `adb reverse` is the safer default.

`--wireless` is a shortcut for binding `0.0.0.0` and printing the host's LAN
address; it does not add transport security. The equivalent persistent setting
is `ukeyctl config set wireless true`, followed by a service restart.

### What the app enforces

- The device must have a PIN/pattern/password and an enrolled strong biometric.
  The app shows a warning and fails closed otherwise.
- Each credential is an EC/P-256 key in AndroidKeyStore. Creation is attempted
  in StrongBox and falls back to the TEE only when StrongBox is unavailable.
  Keys that are not inside secure hardware are deleted and rejected.
- `make_credential` creates the key and returns normalized 32-byte X/Y
  coordinates plus a 32-byte credential ID. Registration does not prompt
  because no signature is produced.
- `get_assertion` and the daemon's packed-self-attestation `attest` action
  require a per-use `BiometricPrompt` (title **uKey Authenticator**, subtitle
  **Authorize: `<rp_id>`**) before the key signs the host-provided digest.
- The credential ID is stateless:
  `SHA-256(rp_id)[0..15] || UUID[0..15]`, and the alias is
  `ukey_cred_<UUID>`. The RP prefix is verified before every signature so a
  credential cannot be replayed for a different RP.
- Signatures are decoded from AndroidKeyStore's ASN.1 DER into fixed 64-byte
  `r || s` (128 hex characters). Malformed, negative, over-wide, or trailing
  DER is rejected.
- A biometric cancel or prompt dismissal returns exactly
  `{"id":N,"error":"user_cancelled"}`.

### Service and lifecycle behavior

`UKeyService` is a `connectedDevice` foreground service with a persistent
**uKey Bridge** notification, exponential reconnect (1 s to 30 s with jitter),
and a 25-second authorization timeout, below the daemon's 30-second signer
timeout. The activity keeps the screen on and can show over the lock screen.
If the app is in the background, the service posts a high-priority notification
instead of attempting a forbidden background activity start. On Android builds
with aggressive battery management, exclude uKey from battery optimization so
the foreground bridge is not frozen during idle periods.

### Wire compatibility

The app auto-detects the daemon's framing from the first message and mirrors it
for responses:

- 4-byte big-endian length + UTF-8 JSON
- newline-delimited UTF-8 JSON

It implements the required `make_credential` and `get_assertion` actions and
also `attest`, which the Phase 1 daemon uses by default for packed
self-attestation. The daemon persists credential metadata (credential ID, RP
ID, and public key) to `~/.config/ukey/credentials.json` and reloads it on
startup. The private key remains with the signer: Android Keystore keys survive,
while restarting the mock signer discards its ephemeral key.

## Validation

### Enumerate and inspect

```bash
fido2-token -L
fido2-token -I /dev/hidraw6   # use the uKey node printed above
```

Expected `fido2-token -I` fields include:

```
proto: 0x02
major: 0x01
minor: 0x00
build: 0x00
caps: 0x0c (nowink, cbor, nomsg)
version strings: FIDO_2_0
transport strings: usb
algorithms: es256 (public-key)
aaguid: fa83a1a960d94daabc6c092271928a11
options: nork, up, uv
fwversion: 0x0
maxmsgsiz: 1024
maxcredcntlst: 8
maxcredlen: 255
maxcredblob: 0
maxlargeblob: 0
```

`nowink` means no wink command; `nomsg` means CTAP1/U2F messages are not
implemented. That is why the PAM/`sudo` path is unfinished. The product string
in `fido2-token -L` comes from the virtual HID device name, for example
`( uKey FIDO2 Authenticator)`.

### MakeCredential

```bash
cd /tmp
printf 'credential-challenge\n' | openssl dgst -sha256 -binary | base64 > cred_in
echo example.com >> cred_in
echo testuser >> cred_in
head -c 32 /dev/urandom | base64 >> cred_in

fido2-cred -M -i cred_in -o cred_out /dev/hidraw6
```

`cred_out` contains the client data hash, RP ID, format, authData, credential
ID, and attestation signature. `fido2-cred -V` verifies the packed
self-attestation and prints the credential public key:

```bash
fido2-cred -V -i cred_out -o cred_verify_out
tail -n +2 cred_verify_out > cred_pub.pem
```

### GetAssertion

```bash
printf 'assertion-challenge\n' | openssl dgst -sha256 -binary | base64 > assert_in
sed -n '2p' cred_out >> assert_in   # RP ID
sed -n '5p' cred_out >> assert_in   # credential ID

fido2-assert -G -i assert_in -o assert_out /dev/hidraw6
fido2-assert -V -i assert_out cred_pub.pem
```

The last command verifies the assertion signature against the credential
public key.

### KEEPALIVE

Restart the mock signer with an artificial delay:

```bash
./daemon/mock_signer.py --delay-ms 1000 --verbose
```

Run a MakeCredential or GetAssertion. The daemon emits `0xBB` packets every
100 ms while waiting; libfido2 accepts them and the command still succeeds. In
testing, a 1-second signer delay produced 12 keepalives for a GetAssertion and
24 for a MakeCredential (two signer round trips).

## Protocol notes

### CTAP2 framing

The real CTAP2 wire format is used:

- Request: one command byte, then an optional CBOR parameter map
- Response: one status byte, then an optional CBOR result

libfido2 and browsers require this. A `getInfo` request is the single byte
`0x04`; a successful response starts with `0x00`.

### Signatures

The signer protocol deliberately returns compact 64-byte `r || s` signatures.
CTAP2/WebAuthn carry ES256 signatures as ASN.1 DER, so the daemon converts at
the CTAP2 boundary. This is why `fido2-cred -V` and `fido2-assert -V` can verify
signatures produced by either the mock signer or the Android app.

### Attestation modes

`--attestation self` (default) returns a standards-compliant **packed
self-attestation**: `fmt: "packed"`, `attStmt: {"alg": -7, "sig": <DER>}`.
This is what makes `fido2-cred -M` work with libfido2 1.12: that tool calls
`base64_encode(NULL, 0)` for a `none` attestation and exits with
`fido2-cred: output error` before printing anything.

`--attestation none` returns the strict CTAP2 none attestation
(`fmt: "none"`, `attStmt: {}`). It is available for clients that implement the
specification correctly:

```bash
./daemon/ukey_daemon.py --attestation none
```

## Tests

Python:

```bash
. .venv/bin/activate
python -m unittest discover -s tests -v
```

The 24 tests exercise CTAPHID INIT/PING fragmentation, GetInfo,
MakeCredential, GetAssertion, exclude lists, both attestation modes,
independent ECDSA verification, config validation and precedence, and the
auto-lock episode/grace/cancellation logic. The auto-lock tests use a fake
`loginctl` and never touch the real session.

Phase 2:

```bash
cd android
./gradlew test
```

`DerUtilsTest` verifies DER-to-raw conversion (including 33-byte integers with
leading zeros, short integers, and malformed input), EC coordinate
normalization, and the stateless credential-ID layout.

## Docker validation

`/dev/uhid` is often root-only until the udev rule is installed. During
development this project was tested in a privileged container that shared the
host's `/dev`:

```bash
docker run --rm -it --privileged -v /dev:/dev -v "$PWD":/ukey -w /ukey \
  debian:bookworm-slim bash

apt-get update
apt-get install -y python3 python3-cbor2 fido2-tools
python3 daemon/ukey_daemon.py --verbose
# in another shell:
python3 daemon/mock_signer.py --verbose
```

With the udev rule installed, the daemon can run directly on the host without
root.

## Security and scope

The mock signer is a test double, not a security boundary. Its private keys are
ephemeral and live only in process memory. Phase 1 has no CTAP2 PIN protocol, no
resident credentials, no attestation certificate chain, no encrypted credential
store, and no protection against a hostile local process attaching to the signer
socket. Credential metadata is stored unencrypted in
`~/.config/ukey/credentials.json`; private keys are not written there.

The Android app improves the key boundary: private keys are non-exportable
AndroidKeyStore keys, StrongBox is preferred, software-backed keys are rejected,
and each assertion requires a strong-biometric prompt that displays the RP ID.
The wire protocol itself is still unauthenticated and unencrypted, so keep it on
loopback via `adb reverse` unless the network is trusted. The daemon returns
packed self-attestation, not a vendor-certified attestation chain. Credential
metadata is persisted unencrypted; private keys stay in the signer. Do not use
the current protocol for production credentials.
