---
last_mapped_commit: 20aa48b012b01497d738980fff0dad10a7d85b96
last_mapped_at: 2026-11-06
---
# Repository Structure

**Analysis Date:** 2026-11-06

## Directory Layout

```
ukey/
├── daemon/                    # Linux host daemon and background services
│   ├── ukey_daemon.py         # UHID device driver, CTAPHID engine, CTAP2 CBOR dispatcher, TCP bridge
│   ├── ukey_config.py         # JSON configuration loading, validation, and atomic 0600 file persistence
│   ├── ukey_pairing.py        # 6-digit PIN pairing, 256-bit device token hashing & management
│   ├── ukey_web.py            # Local HTTP settings console running on 127.0.0.1:8444
│   └── mock_signer.py         # Deterministic software signer for automated test suites
├── android/                   # Native Android mobile client application (Kotlin / Gradle)
│   ├── app/
│   │   ├── src/main/java/org/ukey/
│   │   │   ├── crypto/        # Cryptographic enclave management & utilities
│   │   │   │   ├── KeystoreManager.kt # AndroidKeyStore StrongBox/TEE key generation and signing
│   │   │   │   ├── DerUtils.kt        # ASN.1 DER to raw P-256 signature conversion
│   │   │   │   ├── EcUtil.kt          # Elliptic curve coordinate math and stateless cred IDs
│   │   │   │   └── Hex.kt             # Hexadecimal encoding/decoding utilities
│   │   │   ├── net/           # Networking and daemon connection
│   │   │   │   └── DaemonClient.kt    # TCP client with backoff and handshake authentication
│   │   │   ├── MainActivity.kt        # UI, status indicators, and BiometricPrompt presentation
│   │   │   ├── UKeyService.kt         # Foreground Android service maintaining persistent bridge
│   │   │   ├── Protocol.kt            # JSON wire protocol serialization & parsing
│   │   │   └── BridgeState.kt         # Shared application state and coroutine task coordination
│   │   └── build.gradle.kts   # Android build configuration & dependencies
│   └── build.gradle.kts       # Root Gradle configuration
├── scripts/                   # User-facing administration and configuration scripts
│   ├── ukeyctl                # CLI tool (status, config, pair, devices, web, doctor, logs, menu)
│   ├── setup_pam_sudo.sh      # Universal PAM sudo configuration script with backup & restore
│   └── senior_demo.sh         # Automated evaluation script for testing and demonstration
├── tests/                     # Automated Python test suite (unittest)
│   ├── test_phase1.py         # CTAP2 CBOR framing, makeCredential, and getAssertion tests
│   ├── test_config.py         # Configuration validation, schema enforcement, atomic write tests
│   ├── test_auto_lock.py      # Session auto-lock timeout and grace period tests
│   ├── test_pairing.py        # 6-digit PIN pairing, token verification, and rejection tests
│   └── test_signer_bridge.py  # Mock signer TCP bridge handshake and keepalive tests
├── docs/                      # Documentation and web showcase
│   ├── index.html             # Product landing website with interactive hardware rig
│   ├── STATUS.md              # Canonical source of truth for implemented vs planned features
│   ├── THREAT_MODEL.md        # Security boundaries, adversary models, and mitigations
│   ├── CONTEXT_DISPLAY.md     # Design documentation for context-aware phone approval flows
│   └── ai-prompts/            # Phase-by-phase implementation specifications
├── systemd/                   # Systemd service definitions
│   └── ukey.service           # Portable user-space systemd unit file
├── install.sh                 # Universal installer script for Fedora, Ubuntu, Arch, openSUSE
├── setup_udev.sh              # Kernel udev rules installer for /dev/uhid permissions
├── requirements.txt           # Python package requirements (cbor2, cryptography)
├── LICENSE                    # GPLv3 open source license
└── AGENTS.md                  # Operational notes and safety constraints for AI agents
```

## Key Configuration & State Locations

- **Workstation Configuration**: `~/.config/ukey/config.json` (modes: `wireless`, `auto_lock`, `listen_host`, `port`).
- **Paired Devices & PINs**: `~/.config/ukey/pairing.json` (permissions `0600`).
- **Credentials Cache**: `~/.config/ukey/credentials.json` (host credential mappings).
- **PAM U2F Keys**: `~/.config/Yubico/u2f_keys` (standard `pamu2fcfg` format).
- **Systemd User Unit**: `~/.config/systemd/user/ukey.service`.
- **System Udev Rule**: `/etc/udev/rules.d/70-ukey.rules`.
- **Kernel Character Device**: `/dev/uhid`.
