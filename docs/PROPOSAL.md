# Conference Proposal: uKey

## Title
**Why Buy a $60 Dongle? Turning Your Android Phone into a FIDO2 Security Key for Linux**

---

## Field 1: Proposal Description

Every developer is told to use a hardware security key. But a dedicated dongle costs money, takes up a USB port, and is easy to lose. Your phone already has a secure chip, a fingerprint sensor, and a battery. Why not use it as the key?

uKey is an open-source project that makes an Android phone look like a real FIDO2 security key to Linux. No dongle, no cloud, no root daemon. The phone holds a private key in hardware (StrongBox or TEE), and every signature requires your fingerprint.

In this talk, I'll show what works today, how it works under the hood, and what is still hard.

What you can do with it today:
• Linux sees your phone as a real security key: libfido2 lists it as a /dev/hidraw device.
• You can register a credential and sign a challenge with standard FIDO2 tools.
• The private key never leaves the phone's secure hardware.
• Your fingerprint is required for every signature.
• Everything runs locally: no cloud, no telemetry, no third-party service.

How it works, in plain language:
• A small Linux daemon creates a virtual USB HID device through /dev/uhid, so the kernel thinks a real security key is plugged in.
• The daemon speaks CTAPHID and CTAP2, the same protocols a YubiKey uses.
• The phone does the actual signing inside Android Keystore, behind a biometric prompt.
• The two talk over a local connection — USB via adb reverse by default.

What's next:
• Browser WebAuthn: using the phone as a security key for websites.
• PAM and OpenSSH: sudo/login and Git commit signing.
• Passkeys: discoverable credentials for usernameless login.
• Transport hardening: authenticated, encrypted links beyond loopback.

Demo:
A live fido2-token / fido2-cred / fido2-assert flow against the phone, with a recorded backup.

Why this matters:
Hardware-backed authentication should not require buying another device. The phone in your pocket is already a security token — this project explores how far we can take that idea with open-source software.

---

## Field 2: Key Takeaways

• What a virtual FIDO2 token is, and how Linux sees a phone as a real security key without a custom kernel driver.
• How FIDO2 works in plain language: registration, assertion, and why it resists phishing.
• How Android's secure hardware protects the private key and enforces biometric approval for every signature.
• Where the project works today, and what it will take to support browsers, PAM, and SSH.
• How to build on the code: architecture, tests, and a realistic roadmap.
