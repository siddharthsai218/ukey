# Threat model

This document describes what uKey is trying to protect, who it is protecting it
from, and where the current prototype stops. It is deliberately short. If the
code and this document disagree, the code is wrong or this document is stale;
open an issue instead of assuming the stronger claim.

## Assets

| Asset | Where it lives | Why it matters |
|---|---|---|
| FIDO2 private key | Android Keystore (StrongBox preferred, TEE fallback) | Whoever can use it can sign assertions for the registered RP. |
| Biometric approval | Android `BiometricPrompt` | It is the user-presence and user-verification signal for each assertion. |
| Credential metadata | `~/.config/ukey/credentials.json` and daemon memory | Credential ID, RP ID, and public key. Not secret, but integrity-sensitive. |
| Host session | Linux desktop / login session | A malicious signer reply or unlock path could grant access. |
| User intent | The phone screen and the host terminal | The user must be able to tell what they are approving. |

The private key is generated inside AndroidKeyStore and is not exported. The
daemon only ever sees public keys and signatures. The mock signer is a test
double and its keys are ephemeral.

## Adversaries

| Adversary | Capability | Current outcome |
|---|---|---|
| Remote network attacker | Can reach the signer TCP port when `--wireless` is enabled | **Not stopped.** The transport has no TLS, authentication, or peer verification. Keep the bridge on loopback via `adb reverse`. |
| Local unprivileged process | Can connect to `127.0.0.1:8443` and speak the JSON protocol | **Not stopped.** There is no local peer authentication. A hostile process on the host can impersonate the phone or the daemon. |
| Malicious website | Asks the browser for a WebAuthn credential | Partially mitigated by WebAuthn origin binding and the RP ID shown on the phone. Browser end-to-end behavior is not tested in this repo. |
| Network attacker on the phone link | Can observe or modify Wi-Fi traffic | **Not stopped.** No transport encryption. USB with `adb reverse` avoids the network. |
| Attacker with the unlocked phone | Can attempt to trigger an assertion | Mitigated by the per-use strong-biometric prompt, assuming the Android Keystore and biometric stack are not compromised. |
| Attacker with the locked phone | Has the device but not the biometric | Private key is non-exportable and gated by biometric authentication. This is the main security benefit over a software key on the host. |
| Compromised Linux host | Controls the daemon, the hidraw client, and the session | **Out of scope.** A host root compromise defeats any authenticator attached to that host. |
| Malicious or compromised Android app | Runs inside the phone | Partially mitigated by AndroidKeyStore non-exportability. A compromised app process can ask the keystore to sign while the user is prompted. Not independently audited. |
| Supply-chain attacker | Modifies dependencies or build outputs | **Not addressed.** No reproducible builds, signing policy, or dependency pinning beyond `requirements.txt`. |
| Denial of service | Disconnects the phone, floods the bridge, or kills the daemon | Authentication fails closed. Auto-lock is opt-in and is a convenience feature, not a security boundary. |

## Trust boundaries

1. **Android Keystore ↔ app process.** The key material stays inside the
   keystore. The app receives signatures, not keys. StrongBox is preferred; the
   code rejects software-backed keys.
2. **Phone app ↔ daemon over TCP.** This boundary is currently unauthenticated
   and unencrypted. It is the weakest link in a wireless deployment.
3. **Daemon ↔ kernel via `/dev/uhid`.** The kernel creates a virtual HID device.
   Any local process with access to the matching `/dev/hidraw` node can talk to
   it, subject to udev permissions.
4. **Kernel ↔ FIDO2 client (browser, libfido2, PAM).** Standard Linux hidraw
   access control applies. The daemon does not know which client is asking.
5. **Host terminal ↔ phone screen.** For ordinary WebAuthn the phone sees the RP
   ID and account name, not the terminal contents. For the proposed `sudo` flow
   the host helper would have to read the command from `/proc` and send it to the
   phone; that flow is design-only (see `docs/CONTEXT_DISPLAY.md`).

## Security properties the implementation does provide

- The FIDO2 private key is generated in AndroidKeyStore and is not exported to
  the daemon.
- Each assertion requests a strong-biometric prompt in the Android app.
- The daemon verifies that the signer returned a raw 64-byte ECDSA signature and
  converts it to DER at the CTAP2 boundary. `fido2-assert -V` verifies it.
- The daemon persists only credential metadata (credential ID, RP ID, public
  key). Private keys never reach the daemon.
- On signer disconnect, an in-flight request is expected to fail closed with a
  CTAP error rather than hang. This is covered by the Phase 0 acceptance checks;
  re-run them before relying on it.
- Auto-lock is off by default. When enabled, it requires a prior connection, a
  grace period, a still-disconnected signer, and a session that is not already
  locked.
- No telemetry, analytics, or cloud relay is implemented.

## Known gaps

| Gap | Consequence | Status |
|---|---|---|
| No transport authentication or encryption | A network or local attacker can impersonate the phone or daemon. | Open |
| No replay protection on the bridge | A recorded signer response could be replayed in the current session model. | Open |
| No CTAP2 PIN/UV protocol | The host cannot verify user verification through CTAP; biometric gating is app-local. | Open |
| No resident credentials or `getNextAssertion` | Usernameless and multi-account flows are unavailable. | Open |
| No attestation chain | Relying parties cannot verify a vendor attestation certificate. | Open |
| Credential metadata is unencrypted | RP IDs and credential IDs are readable by the local user and root. | Open |
| No local peer authentication | Any local process that can reach the port can act as the signer. | Open |
| Android app not independently audited | Keystore, biometric, and protocol handling are only self-reviewed. | Open |
| Browser and SSH `ecdsa-sk` flows untested | The repo cannot claim they work. | Open |
| U2F/CTAP1 and PAM not implemented | `sudo` via `pam_u2f` does not work. | Open |
| Auto-lock is not a security control | A crashed daemon cannot lock the session; a hostile local user can already control it. | By design |

## Non-goals

- Protecting a host that is already root-compromised.
- Protecting against a compromised Android OS or a malicious biometric sensor.
- Coercion resistance. If someone can force the user's finger onto the sensor,
  the biometric prompt succeeds.
- Hiding credential metadata from the local user or root.
- Providing a hardware certification or vendor attestation chain.
- Replacing a dedicated hardware key for high-value accounts.

## Reporting

This is a prototype. Do not use it for accounts you cannot afford to lose. If
you find a flaw, open an issue at
<https://github.com/siddharthsai218/ukey/issues> with reproduction steps and the
affected commit. Please do not include real credentials or private keys.
