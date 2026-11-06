---
last_mapped_commit: 20aa48b012b01497d738980fff0dad10a7d85b96
last_mapped_at: 2026-11-06
---
# Technology Stack

**Analysis Date:** 2026-11-06

## Languages & Runtimes

- **Python 3.10 – 3.12**: Core Linux daemon, CLI utilities, and test suites.
  - Runtime: CPython in a local virtual environment (`.venv/bin/python`).
  - Standard library reliance: `ctypes` (kernel binary structs), `socket`, `select`, `threading`, `hashlib`, `secrets`, `http.server`.
- **Kotlin 1.9+ / Java 17**: Native Android authentication application.
  - Runtime: Android Runtime (ART) on Android 8.0+ (API 26), targeted for Android 14 (API 34).
  - Coroutines: `kotlinx-coroutines-core:1.7.3`, `kotlinx-coroutines-android:1.7.3`.
- **Bash**: Deployment, udev setup, PAM configuration, and installer scripts.
  - Cross-distribution compatibility: Fedora (`dnf`), Ubuntu/Debian (`apt`), Arch Linux (`pacman`), openSUSE (`zypper`).

## Core Dependencies & Libraries

### Python Dependencies
Defined in `requirements.txt`:
- `cbor2 >= 5.5.0`: Concise Binary Object Representation (CBOR) decoding and canonical encoding for CTAP2 payloads.
- `cryptography >= 41.0.0`: Elliptic curve and cryptographic utility support for test suites and deterministic mock signer.

### Android Dependencies
Defined in `android/app/build.gradle.kts`:
- `androidx.core:core-ktx:1.12.0`: Android Kotlin extensions.
- `androidx.appcompat:appcompat:1.6.1`: Material component compatibility.
- `androidx.biometric:biometric:1.2.0-alpha05`: AndroidX BiometricPrompt API with `CryptoObject` binding for strong biometric gating (`BIOMETRIC_STRONG`).
- `com.google.android.material:material:1.11.0`: Material 3 design components.

## Operating System & Hardware Interfaces

- **Linux Kernel `/dev/uhid`**: Character device used to create and register user-space virtual USB HID devices (`UHID_CREATE2`, `UHID_INPUT2`, `UHID_OUTPUT`).
- **USB HID Subsystem**: Emulates a FIDO2 composite security token with Vendor ID `0x1209` (Generic Free/Open Hardware) and Product ID `0x0001`.
- **Linux PAM (Pluggable Authentication Modules)**: `pam_u2f.so` module interfacing with `/dev/uhid` for `sudo` elevation and desktop logins.
- **AndroidKeyStore**: Hardware security module interface supporting `secp256r1` (NIST P-256) key generation and ECDSA signing inside Google Titan M or Samsung Knox StrongBox (EAL5+).

## Build & Service Infrastructure

- **Systemd User Units**: `systemd/ukey.service` provides unprivileged, persistent user-space background execution.
- **Udev Rules**: `/etc/udev/rules.d/70-ukey.rules` provides logind seat management (`TAG+="uaccess"`) for `/dev/uhid` and `/dev/hidraw*`.
- **Gradle**: Kotlin DSL (`build.gradle.kts`) for Android APK compilation.
- **Python venv**: Dedicated isolated virtualenv preventing system-level dependency conflicts.
