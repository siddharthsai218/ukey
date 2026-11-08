# Conference Proposal: uKey (Final Submission Ready)

## Title
**Why Buy a $60 Dongle? Turning Your Android Phone into a FIDO2 Security Key for Linux**

*(Alternative)*:  
**Your Phone Is Already a Security Key: Building a Virtual FIDO2 Authenticator for Linux**

---

## Field 1: Proposal Description

Hardware security keys are the best defense against phishing, but most developers don't carry one. They cost money, take up a USB port, and get lost. Your phone, meanwhile, already has a secure chip, a fingerprint sensor, and a battery. uKey asks: why not use the phone as the key?

uKey is an open-source project that makes an Android phone appear as a real FIDO2 security key to Linux. No dongle, no cloud, no root daemon. The private key stays in the phone's secure hardware, and every signature requires a fingerprint.

In this talk, I'll show what works today, explain how it works in plain language, and lay out the roadmap for using it with websites, Git, and system login.

What it does today:
• Linux detects the phone as a real security key — libfido2 sees a /dev/hidraw device, just like a physical token.
• You can create a FIDO2 credential and sign an authentication challenge with standard tools.
• The private key is generated and used inside Android Keystore (StrongBox or TEE) and never leaves the phone.
• Every signature requires a biometric prompt.
• The phone and laptop communicate locally over USB (adb reverse); no cloud, no telemetry.

How it works, in plain language:
• A small Linux daemon creates a virtual USB HID device through /dev/uhid, so the kernel treats it like a physical security key.
• The daemon speaks CTAPHID and CTAP2, the same protocols a YubiKey uses.
• The phone signs inside Android's secure hardware, behind a fingerprint check.
• The two sides talk over a local socket.

The core authenticator works today. The integration roadmap is about turning it into something you can use every day:
• Websites: use the phone as a security key for WebAuthn/2FA.
• Git and SSH: sign commits and authenticate with OpenSSH ecdsa-sk.
• System login: PAM/sudo integration.
• Passkeys: discoverable credentials for usernameless login.
• Transport hardening: authenticated, encrypted links beyond loopback.

Demo:
A live fido2-token / fido2-cred / fido2-assert flow with the phone over adb reverse, plus a recorded backup.

Why it matters:
Hardware-backed authentication shouldn't require another purchase. The phone in your pocket is already a security token. This talk shows how far open-source software can take that idea — and what's left to build.

---

## Field 2: Key Takeaways

• How Linux sees a phone as a real FIDO2 security key, without a custom kernel driver.
• How FIDO2 works in plain language: registration, assertion, and why it resists phishing.
• How Android's secure hardware protects the private key and enforces biometric approval.
• What works today, and what it will take to support websites, Git, SSH, and PAM.
• A realistic roadmap for a local-only, open-source alternative to commercial hardware keys.
