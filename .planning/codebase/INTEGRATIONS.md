---
last_mapped_commit: 20aa48b012b01497d738980fff0dad10a7d85b96
last_mapped_at: 2026-11-06
---
# External & System Integrations

**Analysis Date:** 2026-11-06

## 1. Linux Kernel & Subsystem Integrations

- **`/dev/uhid` (User HID)**:
  - File: `daemon/ukey_daemon.py`
  - Integration: Creates a virtual USB HID node in userspace without requiring a dedicated out-of-tree kernel module.
  - Events Handled: `UHID_CREATE2` (initializes HID report descriptor), `UHID_INPUT2` (sends 64-byte CTAPHID interrupt packets), `UHID_OUTPUT` (receives CTAPHID command packets from applications), `UHID_GET_REPORT`, `UHID_SET_REPORT`.
- **`/dev/hidraw*`**:
  - Automatically mapped by the kernel when uKey attaches to `/dev/uhid`.
  - Used by standard Linux FIDO2 tools (`fido2-token`, `fido2-cred`, `pamu2fcfg`).
- **`systemd-logind` & `udev`**:
  - File: `setup_udev.sh` installs `/etc/udev/rules.d/70-ukey.rules`.
  - Integrates with systemd's seat manager via `TAG+="uaccess"`, granting dynamic read/write ACLs to the active console user.

## 2. Linux Authentication Subsystems

- **PAM (`pam_u2f.so`)**:
  - File: `scripts/setup_pam_sudo.sh`
  - Integration: Configured in `/etc/pam.d/sudo` with `auth sufficient pam_u2f.so authfile=~/.config/Yubico/u2f_keys`.
  - Behavior: Intercepts `sudo` commands, prompts the virtual FIDO2 token, and validates the hardware biometric assertion. If uKey is offline or uninstalled, PAM falls back to `pam_unix` password prompt in 0.0s.
- **OpenSSH (`ecdsa-sk`)**:
  - Integration: Interacts natively with OpenSSH 8.2+ via `ssh-keygen -t ecdsa-sk -f ~/.ssh/id_ukey`.
  - Behavior: Employs standard CTAP2 FIDO2 keys for SSH authentication and Git commit signing without exposing unencrypted private keys on disk.
- **Web Browsers (WebAuthn / CTAP2)**:
  - Integration: Supported natively in Chromium, Google Chrome, Firefox, and Brave via standard HID raw access.

## 3. Android Hardware Security Integrations

- **AndroidKeyStore (StrongBox & TEE)**:
  - File: `android/app/src/main/java/org/ukey/crypto/KeystoreManager.kt`
  - Integration: Requests `builder.setIsStrongBoxBacked(true)` targeting dedicated hardware security modules (Google Titan M, Samsung Knox).
  - Fallback: Gracefully falls back to TrustZone TEE if StrongBox is reported unavailable by the OEM, while validating `keyInfo.isInsideSecureHardware`.
- **AndroidX BiometricPrompt**:
  - File: `android/app/src/main/java/org/ukey/MainActivity.kt`
  - Integration: Binds the cryptographic `Signature` to `BiometricPrompt.CryptoObject` with `BIOMETRIC_STRONG` requirements, preventing signature creation without authentic physical fingerprint authentication.

## 4. Network & Daemon Bridge Integrations

- **TCP Signer Bridge (Port 8443)**:
  - File: `daemon/ukey_daemon.py`, `android/app/src/main/java/org/ukey/net/DaemonClient.kt`
  - Modes:
    - Wired USB: Tunnelled securely over ADB loopback via `adb reverse tcp:8443 tcp:8443` (latency `<3ms`).
    - Wi-Fi LAN: Listens on `0.0.0.0:8443` authenticated by 256-bit device tokens (latency `<5ms`).
- **Local Management Web Console (Port 8444)**:
  - File: `daemon/ukey_web.py`
  - Integration: Embedded HTTP service binding strictly to `127.0.0.1:8444`, exposing JSON APIs (`/api/status`, `/api/toggle`, `/api/pin/new`, `/api/devices/revoke`) for the desktop control dashboard.
