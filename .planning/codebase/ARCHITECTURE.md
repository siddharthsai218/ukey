---
last_mapped_commit: 20aa48b012b01497d738980fff0dad10a7d85b96
last_mapped_at: 2026-11-06
---
# System Architecture

**Analysis Date:** 2026-11-06

## High-Level Topology

uKey implements a split-architecture virtual FIDO2/CTAP2 hardware token. The cryptography and biometric user presence checks are physically decoupled from the host operating system and executed inside a dedicated smartphone hardware enclave.

```
+-------------------------------------------------------------------------+
|                           LINUX HOST SYSTEM                             |
|                                                                         |
|  [PAM sudo / OpenSSH / Chrome]                                          |
|                 | (Standard HID Raw / FIDO2)                            |
|                 v                                                       |
|        Linux Kernel /dev/uhid  <==========+                             |
|                                           |                             |
|  [uKey Python Daemon (ukey_daemon.py)]    | ctypes binary packets       |
|    - UhidDevice (packet loop) ------------+                             |
|    - Ctap2Engine (CBOR parser & state machine)                          |
|    - SignerBridge (TCP server on :8443)                                 |
|    - PairingManager (token auth)                                        |
|    - Web Dashboard (HTTP on :8444)                                      |
+-------------------------------------------------------------------------+
                                 ^
                                 |  TCP Bridge (adb reverse / Wi-Fi)
                                 v
+-------------------------------------------------------------------------+
|                         ANDROID MOBILE DEVICE                           |
|                                                                         |
|  [uKey Android Client (Kotlin)]                                         |
|    - DaemonClient (coroutine TCP socket loop)                           |
|    - Protocol (handshake & challenge serialization)                     |
|    - MainActivity / UKeyService                                         |
|    - BiometricPrompt (CryptoObject user authorization)                  |
|                 |                                                       |
|                 v                                                       |
|  [AndroidKeyStore Hardware Enclave]                                     |
|    - Google Titan M / Knox StrongBox (P-256 private keys)               |
|    - Hardware isolated ECDSA signature generation                       |
+-------------------------------------------------------------------------+
```

## Architectural Layers

### 1. Linux Host Kernel Interface (`daemon/ukey_daemon.py`)
- **`UhidDevice`**: Manages low-level Linux character device operations on `/dev/uhid`.
  - Defines binary C structures (`_UhidCreate2Req`, `_UhidInput2Req`, `_UhidOutputReq`) via Python `ctypes`.
  - Implements the USB HID Report Descriptor specified by the FIDO Alliance (64-byte Input/Output reports).
- **`Ctap2Engine`**: Processes CTAPHID framing and CTAP2 CBOR command packets.
  - Channels & Packets: Handles CID (Channel ID) allocation, packet fragmentation, sequence numbers, keepalives, and timeouts.
  - Command Dispatcher: Handles `authenticatorMakeCredential` (0x01), `authenticatorGetAssertion` (0x02), `authenticatorGetInfo` (0x04), and `authenticatorReset` (0x07).
  - Credentials Store: Maintains local mapping of credential IDs and relying party hashes (`credentials.json`), with stateless verification fallbacks.

### 2. Network & Transport Bridge (`daemon/ukey_daemon.py`, `daemon/ukey_pairing.py`)
- **`SignerBridge`**: Thread-safe communication hub connecting the CTAP2 engine to the Android client over a TCP connection.
  - Handshake: Enforces authentication on connection. Phones must present either a valid 256-bit device token or a freshly generated 6-digit PIN.
  - Wire Format: Asynchronous newline-delimited JSON messages (`action`, `id`, `rp_id`, `client_hash`, `digest`).
  - Keepalive: Proactively sends CTAPHID keepalive status packets to the Linux kernel while waiting for biometric authorization to prevent USB timeouts.
- **`PairingManager`**: Manages persistent authorized device tokens and temporary pairing PINs with atomic file writes (`os.replace` + `chmod 0600`).

### 3. Mobile Hardware Enclave Client (`android/app/src/main/java/org/ukey/`)
- **`KeystoreManager`**: Generates and manages non-exportable P-256 (`secp256r1`) key pairs inside `AndroidKeyStore`.
  - Hardware Protection: Requests StrongBox backing (`builder.setIsStrongBoxBacked(true)`), validating `keyInfo.isInsideSecureHardware`.
  - Per-Use Biometric Constraint: Configures `setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)` so private keys cannot sign unless authorized by biometric hardware.
- **`DaemonClient`**: Persistent coroutine TCP client that handles exponential backoff, socket reconnects, handshake authentication, and message dispatch.
- **`MainActivity`**: Hosts the `BiometricPrompt` UI, binding the active signature challenge into `BiometricPrompt.CryptoObject`.

## Key Architectural Patterns

1. **Decoupled Cryptographic Core**: The Linux workstation never generates, stores, or sees private keys. All cryptographic private keys are hardware-bound inside the phone's secure element.
2. **Stateless Credential Derivation**: Credential IDs embed a 16-byte prefix of `SHA256(rp_id)`. Even if host credentials storage is deleted or reset, the daemon can verify that a credential belongs to the requesting Relying Party.
3. **Safe PAM Fallback (`sufficient`)**: Sudo PAM integration is strictly non-blocking. If the daemon or phone is offline, PAM immediately yields to `pam_unix` password prompt in `0.0s`, eliminating the risk of permanent lockout.
