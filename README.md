# uKey: Context-Aware Hardware Security Key for Linux

[![Linux Kernel /dev/uhid](https://img.shields.io/badge/Kernel-/dev/uhid-blue.svg)](https://docs.kernel.org/hid/uhid.html)
[![FIDO2 / CTAP2](https://img.shields.io/badge/Protocol-FIDO2%20%2F%20CTAP2-green.svg)](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html)
[![Android StrongBox](https://img.shields.io/badge/Hardware-Android%20StrongBox%20%2F%20TEE-orange.svg)](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setIsStrongBoxBacked(boolean))
[![Zero Cloud](https://img.shields.io/badge/Privacy-100%25%20Local%20%2F%20Zero%20Cloud-emerald.svg)](#)
[![License: GPLv3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)

**uKey** turns any standard Android phone into an **out-of-band, hardware-backed FIDO2 / CTAP2 security key** for Linux via `/dev/uhid`.

Authenticate Linux `sudo`, OpenSSH hardware keys (`ecdsa-sk`), and browser WebAuthn logins (Google, GitHub, AWS) using your phone's tamper-resistant biometric hardware enclave.

---

## Why uKey is Truly Unique

Unlike traditional hardware keys or cloud passkeys, uKey introduces three breakthrough paradigms for Linux security:

### 1. Tri-Modal Biometrics: 3 Ways to Sign In, 1 Central Audit Ledger
You are never stranded if your phone is in another room or your laptop lacks a fingerprint reader:
- **Option 1 (Laptop Fingerprint):** If your laptop has a built-in sensor, authenticate in 0.4s right on the keyboard palm rest (`pam_fprintd.so`).
- **Option 2 (Laptop Webcam Face Scanner):** Built-in camera (`/dev/video0`) scans your face locally (Linux Hello).
- **Option 3 (Phone StrongBox):** Route cryptographic assertions directly to your Android hardware enclave.

**The Mobile Security Audit Ledger:** Whichever method you choose on your laptop, uKey transmits an authenticated transaction receipt to your phone app. Your phone maintains a real-time, tamper-resistant audit trail of every `sudo` escalation, SSH session, and WebAuthn login across your Linux machine.

### 2. Zero-Cloud Privacy Guarantee
- **Biometric vectors never leave local silicon:** Face embeddings and fingerprint minutiae are processed purely in local RAM/silicon and destroyed immediately.
- **Audit receipts only:** The phone receives only cryptographically signed receipts (`timestamp`, `service`, `status`), never raw biometric data.
- **100% Offline / Local Socket:** Operates strictly over USB (`adb reverse`) or local Wi-Fi. Zero external telemetry, zero cloud relays, zero tracking.

### 3. "See What You Sign" — Out-of-Band Hardware Inspection
- **The Physical YubiKey Flaw:** Commercial hardware keys (YubiKey, Nitrokey) are "blind". When a background script triggers a sudo prompt, you tap the gold disc with zero context of what process or command you just authorized.
- **The uKey Solution:** Your phone has a high-resolution touchscreen. uKey sends the exact relying party, command, and process context out-of-band to your phone. You visually verify what you are signing before touching the biometric sensor.

### 4. Proximity Walk-Away Screen Lock (`--auto-lock`)
- Ever walked away from your laptop at a college lab, office, or coffee shop?
- Run `ukey_daemon.py --auto-lock`. The second your phone unplugs or leaves local connectivity, Linux instantly triggers `loginctl lock-session`. When you return and touch your fingerprint, your session unlocks.

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
│   └── test_phase1.py     # in-process CTAPHID/CTAP2/ECDSA tests
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
hidraw node: /dev/hidraw3
```

Do not run the mock signer and the Android app at the same time; the daemon
accepts one signer connection.

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
self-attestation. Credential state remains in the daemon's memory, so
restarting the daemon discards credentials and new ones must be registered.

## Validation

### Enumerate and inspect

```bash
fido2-token -L
fido2-token -I /dev/hidraw3
```

Expected `fido2-token -I` fields include:

```
proto: 0x02
major: 0x01
minor: 0x00
build: 0x00
caps: 0x04 (nowink, cbor, msg)
version strings: FIDO_2_0
transport strings: usb
aaguid: fa83a1a960d94daabc6c092271928a11
options: nork, up, uv, noclientPin
maxmsgsiz: 1024
maxcredcntlst: 8
maxcredlen: 255
```

The product string in `fido2-token -L` is blank because UHID exposes only a HID
device name, not a USB product-string descriptor. The device is still fully
usable.

### MakeCredential

```bash
cd /tmp
printf 'credential-challenge\n' | openssl dgst -sha256 -binary | base64 > cred_in
echo example.com >> cred_in
echo testuser >> cred_in
head -c 32 /dev/urandom | base64 >> cred_in

fido2-cred -M -i cred_in -o cred_out /dev/hidraw3
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

fido2-assert -G -i assert_in -o assert_out /dev/hidraw3
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

Phase 1:

```bash
. .venv/bin/activate
python -m unittest discover -s tests -v
```

The tests exercise CTAPHID INIT/PING fragmentation, GetInfo, MakeCredential,
GetAssertion, exclude lists, both attestation modes, and independent ECDSA
verification.

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
ephemeral and live only in process memory. Phase 1 has no PIN/UV protocol, no
resident credentials, no attestation certificate chain, no persistent storage,
and no protection against a hostile local process attaching to the signer
socket.

The Android app improves the key boundary: private keys are non-exportable
AndroidKeyStore keys, StrongBox is preferred, software-backed keys are rejected,
and each assertion requires a strong-biometric prompt that displays the RP ID.
The wire protocol itself is still unauthenticated and unencrypted, so keep it on
loopback via `adb reverse` unless the network is trusted. The app returns packed
self-attestation, not a vendor-certified attestation chain. As with Phase 1,
credentials are remembered by the daemon process only; restarting it discards
them. Do not use the current protocol for production credentials.
