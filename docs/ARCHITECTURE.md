# uKey Architecture

This document details the end-to-end systems architecture of **uKey**, explaining how a Linux workstation communicates with an Android phone's secure hardware enclave to emulate a physical USB FIDO2 security key.

---

## High-Level System Overview

```
┌─────────────────────────────────────────────────────────────┐
│                        LINUX HOST                           │
│                                                             │
│  [ Standard FIDO2 Tools ]                                   │
│  fido2-token · fido2-cred · fido2-assert · libfido2         │
│                           │                                 │
│                           ▼ (standard POSIX read/write)     │
│                 /dev/hidrawX node                           │
│                           │                                 │
│  [ Linux Kernel ]         ▼                                 │
│  /dev/uhid (User-space HID Subsystem)                       │
│                           │                                 │
│                           ▼ (64-byte HID report packets)    │
│  [ uKey Python Daemon ]                                     │
│  ├─ CTAPHID Framing (CID, INIT, PING, CBOR, KEEPALIVE)      │
│  ├─ CTAP2 Engine (getInfo, makeCredential, getAssertion)    │
│  ├─ Credential Metadata (~/.config/ukey/credentials.json)   │
│  └─ Localhost Signer Bridge (127.0.0.1:8443)                │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            │ Local USB Loopback (adb reverse tcp:8443 tcp:8443)
                            │ Zero cloud relays · No LAN exposure
                            │
┌───────────────────────────▼─────────────────────────────────┐
│                       ANDROID PHONE                         │
│                                                             │
│  [ uKey Android Client ]                                    │
│  ├─ Local socket connection (:8443)                         │
│  ├─ Per-assertion BiometricPrompt (Fingerprint)             │
│  └─ AndroidKeyStore Cryptographic Engine                    │
│                           │                                 │
│  [ Hardware Secure Enclave ]                                │
│  Google Titan M / Samsung Knox / ARM TrustZone              │
│  ├─ StrongBox Keymaster (P-256 ECDSA / secp256r1)           │
│  └─ Device-bound private keys (Never leave silicon)         │
└─────────────────────────────────────────────────────────────┘
```

---

## The Five Architectural Layers

### Layer 1: Client Subsystem
* **Components:** `libfido2`, standard CLI utilities (`fido2-token`, `fido2-cred`, `fido2-assert`), and OpenSSH.
* **Function:** Standard Linux tools treat uKey as an off-the-shelf physical FIDO2 authenticator. No proprietary client drivers, browser extensions, or patches to system libraries are required.

### Layer 2: Linux Kernel User-Space HID (`/dev/uhid`)
* **Function:** Enables user-space processes to create synthetic HID devices inside the Linux kernel.
* **Mechanism:**
  1. The daemon opens `/dev/uhid` and writes a `UHID_CREATE2` packet containing standard FIDO Alliance HID report descriptors.
  2. The Linux kernel instantiates a virtual USB device and exposes a `/dev/hidrawX` node.
  3. Udev rules (`70-ukey.rules`) configure node permissions for unprivileged user access.

### Layer 3: Python Daemon Core
* **CTAPHID Framing Engine:** Handles USB HID 64-byte report packets, channel ID (CID) allocation, packet fragmentation, and protocol states (`INIT`, `PING`, `CBOR`, `CANCEL`, `KEEPALIVE`).
* **CTAP2 Authenticator Engine:** Decodes CBOR payloads for standard operations:
  * `getInfo` (0x04): Reports authenticator capabilities (`FIDO_2_0`, `ES256`, `0x0c` flags).
  * `makeCredential` (0x01): Generates packed self-attestation objects with clientDataHash binding.
  * `getAssertion` (0x02): Validates RP IDs and coordinates challenge-response signing.
* **Metadata Persistence:** Stores credential IDs, RP IDs, and public keys in `~/.config/ukey/credentials.json` with restricted `0600` POSIX permissions. Private keys never touch this store.

### Layer 4: Localhost Loopback Bridge
* **Socket Interface:** Daemon exposes an internal TCP server on `127.0.0.1:8443`.
* **Transport:** Routed over physical USB cable via `adb reverse tcp:8443 tcp:8443`.
* **Security Properties:** Zero cloud infrastructure, no telemetry, and no wide-area network routing. Communications remain strictly bound to local loopback.
* **Pairing & Authentication:** Single-use 6-digit PIN issues a 256-bit cryptographic device token with brute-force lockout mechanisms.

### Layer 5: Android Hardware Keystore & Biometrics
* **Hardware Isolation:** P-256 (`secp256r1`) private keys are generated inside `AndroidKeyStore` with StrongBox preference and TEE fallback. Software-backed keys are rejected.
* **Device-Bound Keys:** Key material is physically trapped inside the secure hardware processor (Google Titan M / Samsung Knox) and cannot be exported or extracted by the OS or user-space applications.
* **Active Biometric Presence:** Every assertion requires explicit physical user authorization through Android's native `BiometricPrompt` before a signature is issued.

---

## End-to-End Authentication Sequence

```
Host (libfido2)         Daemon (/dev/uhid)          Android Client           Hardware Enclave
      │                         │                         │                         │
      │ 1. fido2-assert         │                         │                         │
      ├────────────────────────►│                         │                         │
      │                         │ 2. Forward challenge    │                         │
      │                         ├────────────────────────►│                         │
      │                         │    over adb reverse     │                         │
      │                         │                         │ 3. Display prompt       │
      │                         │                         │    "Touch fingerprint"  │
      │                         │                         │                         │
      │                         │                         │ 4. User touches sensor  │
      │                         │                         │────────────────────────►│
      │                         │                         │                         │ 5. Hardware signs
      │                         │                         │    6. Return signature  │    P-256 hash
      │                         │ 7. Return raw signature │◄────────────────────────┤
      │                         │◄────────────────────────┤                         │
      │                         │                         │                         │
      │ 8. DER signature packet │                         │                         │
      │◄────────────────────────┤                         │                         │
      ▼                         ▼                         ▼                         ▼
```

---

## Key Technical References

* **Linux Kernel UHID Documentation:** [https://docs.kernel.org/hid/uhid.html](https://docs.kernel.org/hid/uhid.html)
* **FIDO2 / CTAP2 Specification:** [https://fidoalliance.org/specs/fido-v2.0-ps-20190130/](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html)
* **Android KeyStore Architecture:** [https://developer.android.com/privacy-and-security/keystore](https://developer.android.com/privacy-and-security/keystore)
