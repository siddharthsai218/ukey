# Security Architecture

uKey is designed to bring hardware-grade FIDO2 authentication to Linux workstations using the secure hardware enclave already present in modern Android devices.

---

## Architectural Principles

### 1. Hardware Key Isolation
* **Non-Exportable Private Keys:** Cryptographic keys (P-256 / ES256) are generated inside Android's hardware keystore (`AndroidKeyStore`). Key material is isolated in physical silicon (Google Titan M, Samsung Knox, ARM TrustZone) and cannot be extracted by the host, the operating system, or user-space applications.
* **Hardware Enforcement:** The client enforces StrongBox or Trusted Execution Environment (TEE) backing; software-backed keys are explicitly rejected.

### 2. Physical Biometric Presence Verification
* **Per-Assertion Biometric Authorization:** Every authentication request triggers Android’s native `BiometricPrompt` on the phone.
* **Zero Silent Signatures:** Unlike disk-stored SSH keys (`~/.ssh/id_ed25519`) or automated scripts, no assertion can be signed without physical human biometric presence.

### 3. Local Loopback Transport
* **Zero Cloud Dependence:** uKey operates entirely offline. No telemetry, no relays, and no third-party cloud infrastructure.
* **Safe-by-Default Binding:** The daemon binds to loopback (`127.0.0.1:8443` and `127.0.0.1:8444`). Communications between the Linux host and the phone are routed over local USB loopback via `adb reverse`.
* **Zero-PIN Token Authentication:** Pairing uses a single-use 6-digit PIN that issues a cryptographic device token, allowing instant one-click revocation from the local console.

### 4. Linux Kernel Integration
* **Standard User-Space Subsystems:** Emulates USB HID security keys through the standard Linux `/dev/uhid` interface without requiring custom kernel modules or privileged out-of-tree drivers.
* **Metadata Integrity:** Local configuration and credential mappings are stored with restricted POSIX permissions (`0600`) in `~/.config/ukey/`.
