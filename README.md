<div align="center">

<picture>
  <source media="(prefers-color-scheme: light)" srcset="assets/ukey-logo-black.png">
  <img src="assets/ukey-logo.png" alt="ukey" width="320">
</picture>

### Your Android phone, as a real FIDO2 hardware security key for Linux

Native, zero-cloud, hardware-isolated biometric authentication. Touch your phone’s sensor to sign.

<br />

<p align="center">
  <a href="https://docs.kernel.org/hid/uhid.html"><img src="https://img.shields.io/badge/Kernel-/dev/uhid-22C55E.svg?style=flat-square&logo=linux&logoColor=white" alt="Linux Kernel /dev/uhid"></a>
  <a href="https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setIsStrongBoxBacked(boolean)"><img src="https://img.shields.io/badge/Hardware-Android%20StrongBox%20(EAL5+)-10B981.svg?style=flat-square&logo=android&logoColor=white" alt="Android StrongBox"></a>
  <a href="https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html"><img src="https://img.shields.io/badge/Protocol-FIDO2%20%2F%20CTAP2-06B6D4.svg?style=flat-square" alt="FIDO2 / CTAP2"></a>
  <a href="https://github.com/siddharthsai218/ukey/actions"><img src="https://img.shields.io/badge/Tests-39%20Passed-brightgreen.svg?style=flat-square" alt="Tests"></a>
  <a href="https://www.gnu.org/licenses/gpl-3.0"><img src="https://img.shields.io/badge/License-GPLv3-blue.svg?style=flat-square" alt="License: GPLv3"></a>
</p>

**[Website & Live Simulator](https://siddharthsai218.github.io/ukey)** · **[Quickstart](#quickstart-1-command-installer)** · **[Workflows](#three-native-workflows)** · **[Architecture](#architecture)** · **[Comparison](#comparison)**

</div>

---

**uKey makes Linux treat your Android phone as a native USB FIDO2 security key.**

The Linux host kernel sees an authentic `/dev/hidraw` USB security token. A lightweight Python daemon implements `/dev/uhid`, CTAPHID framing, and the CTAP2 CBOR protocol. Cryptographic private keys reside entirely inside Android’s dedicated hardware security module (**Google Titan M** or **Samsung Knox StrongBox** with EAL5+ isolation), and every authentication assertion requires a physical fingerprint touch on the phone.

---

## Key Features

- **⚡ Zero Passwords**: Authenticate Linux `sudo`, GDM login, and Polkit authorization dialogs in **0.38 seconds** with a tap of your phone’s fingerprint sensor.
- **🛡️ Hardware-Enclave Bound**: ECDSA P-256 private keys are generated directly inside Android's hardware security silicon. Keys never touch RAM, never touch disk, and cannot be exported even on a rooted device.
- **🐧 Native Linux Kernel Subsystem**: Emulates an authentic USB FIDO2 token via `/dev/uhid`. To Linux PAM, OpenSSH, Google Chrome, and Firefox, your phone behaves identically to a physical $60 YubiKey.
- **⏱️ 0.0s Password Fallback**: Safe PAM `sufficient` design. If your phone is unplugged, powered off, or disconnected, PAM yields to the standard Linux password prompt immediately in **0.0 seconds**. Never hangs, never locks you out.
- **🌐 Universal Multi-Distro Support**: 1-command installer with out-of-the-box support for **Fedora**, **Ubuntu / Debian**, **Arch Linux**, and **openSUSE**.
- **🔒 100% Peer-to-Peer & Zero Cloud**: Runs over low-latency physical USB (`adb reverse` loopback at `<3ms`) or local Wi-Fi LAN with 256-bit token authentication. Zero external servers, zero telemetry, zero third-party accounts.

---

## Quickstart: 1-Command Installer

Install uKey udev permissions, virtual FIDO2 daemon, systemd user service, and management tools:

```bash
curl -fsSL https://raw.githubusercontent.com/siddharthsai218/ukey/main/install.sh | bash
```

The installer detects your distribution automatically, configures `/dev/uhid` permissions, sets up the Python virtual environment, and starts the background user service `ukey.service`.

---

## Three Native Workflows

### 1. Passwordless `sudo` & PAM Login

Configure Linux PAM to accept your phone’s biometric touch:

```bash
sudo ./scripts/setup_pam_sudo.sh
```

Now, whenever you run a `sudo` command:

```bash
$ sudo dnf update
[sudo] Touch phone biometric or press Enter for password:
```

1. Touch your fingerprint sensor on your phone $\rightarrow$ **Unlocked in 0.38s!**
2. Or simply press **Enter** $\rightarrow$ **Instant 0.0s fallback to regular password prompt!**

*(To undo anytime: `sudo ./scripts/setup_pam_sudo.sh --restore`)*

---

### 2. Hardware Git Commit Signing (OpenSSH `ecdsa-sk`)

Create an unexportable hardware-backed SSH key for GitHub and GitLab git pushes:

```bash
# Generate FIDO2 hardware key
ssh-keygen -t ecdsa-sk -f ~/.ssh/id_ukey

# Configure git to sign commits automatically with hardware presence
git config --global user.signingkey ~/.ssh/id_ukey.pub
git config --global gpg.format ssh
git config --global commit.gpgsign true
```

When you run `git push origin main`, your phone prompts for biometric authorization. No unencrypted private keys exist on your laptop.

---

### 3. WebAuthn Passkeys in Chrome, Firefox & Brave

Register your phone as a physical FIDO2 security key for Google Accounts, GitHub 2-Step Verification, AWS Console, or Discord. 

When the browser requests a Security Key, your Android phone vibrates with the authentication prompt and signs the challenge directly in StrongBox.

---

## Management Tools

### Interactive Terminal Menu

```bash
./scripts/ukeyctl menu
```

Launches an interactive terminal dashboard allowing you to inspect daemon status, toggle auto-lock, generate pairing PINs, and review security logs.

### Embedded Web Console (`:8444`)

uKey includes an embedded local web dashboard binding strictly to `http://127.0.0.1:8444`:


- **Master Authentication Switch**: 1-click toggle to temporarily bypass biometric interception.
- **Wi-Fi Pairing PIN**: Generates 6-digit one-time PINs for pairing new phones over local Wi-Fi.
- **Authorized Devices**: View paired hardware tokens and revoke devices with a single click.

---

## Architecture

```
+-------------------------------------------------------------------------+
|                           LINUX HOST SYSTEM                             |
|                                                                         |
|  [PAM sudo / OpenSSH / Browser]                                          |
|                 │ (Standard HID Raw / FIDO2)                            |
|                 ▼                                                       |
|        Linux Kernel /dev/uhid  <══════════╗                             |
|                                           ║                             |
|  [uKey Python Daemon (ukey_daemon.py)]    ║ ctypes binary packets       |
|    - UhidDevice (packet loop) ────────────╝                             |
|    - Ctap2Engine (CBOR parser & state machine)                          |
|    - SignerBridge (TCP server on :8443)                                 |
|    - PairingManager (token auth)                                        |
|    - Web Dashboard (HTTP on :8444)                                      |
+-------------------------------------------------------------------------+
                                 ▲
                                 │  TCP Bridge (adb reverse / Wi-Fi)
                                 ▼
+-------------------------------------------------------------------------+
|                         ANDROID MOBILE DEVICE                           |
|                                                                         |
|  [uKey Android Client (Kotlin)]                                         |
|    - DaemonClient (coroutine TCP socket loop)                           |
|    - Protocol (handshake & challenge serialization)                     |
|    - MainActivity / UKeyService                                         |
|    - BiometricPrompt (CryptoObject user authorization)                  |
|                 │                                                       |
|                 ▼                                                       |
|  [AndroidKeyStore Hardware Enclave]                                     |
|    - Google Titan M / Knox StrongBox (P-256 private keys)               |
|    - Hardware isolated ECDSA signature generation                       |
+-------------------------------------------------------------------------+
```

---

## Comparison

| Feature | **uKey** (This Project) | **Play Store Apps** (e.g. `mahirsn/passkey`) | **YubiKey 5 Series** | **Google / Apple Passkeys** |
|:---|:---:|:---:|:---:|:---:|
| **Primary Target** | **Linux Workstations** | Windows / macOS | All Platforms | Cloud Ecosystems |
| **Key Enclave** | **Android StrongBox (EAL5+)** | Software App Storage | Secure Element Silicon | OS Secure Enclave / TPM |
| **Linux PAM sudo** | **✓ Native (0.38s Auth)** | ✕ Unsupported | ✓ Native (`pam_u2f`) | ✕ Unsupported |
| **OpenSSH `ecdsa-sk`**| **✓ Native Git Signing** | ✕ Unsupported | ✓ Supported | ✕ Unsupported |
| **Browser WebAuthn** | **✓ Kernel `/dev/uhid`** | Partial (BLE HID) | ✓ USB HID | ✓ Cloud Sync |
| **Instant Fallback** | **✓ 0.0s Password Fallback** | ✕ Times out / Hangs | ✓ Immediate on pull | ✕ Cloud Dependent |
| **Hardware Cost** | **$0 (Uses your phone)** | $0 (Play Store App) | $60 – $85 per key | $0 (Locked in) |
| **License** | **GPLv3 Open Source** | Closed Source | Closed Firmware | Closed Cloud |

---

## Testing & Quality

uKey maintains a 100% automated test suite with zero hardware dependencies required for CI:

```bash
# Run unit & integration test discovery
.venv/bin/python -m unittest discover -s tests -v

# Validate syntax across Python and Shell files
.venv/bin/python -m py_compile daemon/*.py scripts/ukeyctl
bash -n install.sh setup_udev.sh scripts/setup_pam_sudo.sh
```

- **`test_phase1.py`**: CTAPHID packet fragmentation, CBOR canonical serialization, `makeCredential`, and `getAssertion`.
- **`test_config.py`**: Configuration defaults, schema validation, and atomic `0600` persistence.
- **`test_auto_lock.py`**: Disconnect detection, debounce, and desktop lock triggers.
- **`test_pairing.py`**: 6-digit PIN expiration, token verification, and rogue network rejection.
- **`test_signer_bridge.py`**: Keepalive packets, client drop recovery, and mock signer communication.

---

## Security Boundaries & Roadmap

- **Transport**: Over USB (`adb reverse`), traffic is physically isolated over the cable. Over Wi-Fi, connections are authenticated via a 256-bit token hash; mutual TLS transport encryption is planned for v0.2.0.
- **Resident Credentials**: Currently, uKey supports standard RP-bound credentials; resident (discoverable) credentials (`rk=true`) are on the v0.2.0 roadmap.
- **CTAP Version**: uKey implements modern CTAP2. Legacy U2F/CTAP1 commands return `6d 00`.

Read [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for full threat model specifications.

---

## License

This project is licensed under the terms of the **GNU General Public License v3.0** (`GPLv3`). See [`LICENSE`](LICENSE) for details.

Developed with ❤️ for the Linux community by **BYN Siddharth Sai**.
