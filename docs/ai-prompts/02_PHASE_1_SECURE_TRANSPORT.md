# Phase 1 — Secure Transport and Pairing (Lane A)

Read `00_MASTER_CONTEXT.md` and complete Phase 0 first.

## Goal

Turn the phone↔Linux bridge from an unauthenticated TCP socket into an
authenticated, encrypted, replay-resistant transport that is safe enough to use on
a LAN — and keep wireless **opt-in**.

This phase is the foundation for Lane A: “a secure wireless key.” It does not add
context-aware sudo or packaging.

## Current problem

- The daemon listens on `127.0.0.1:8443` by default, but `--wireless` makes it listen
  on `0.0.0.0`.
- There is no authentication: any process that can reach the port can pretend to be
  the phone.
- There is no encryption: command context, RP IDs, and signatures cross the network
  in plaintext.
- There is no replay protection.
- The Android app trusts whatever host it connects to.

## Design requirements

Write `docs/TRANSPORT.md` before implementing. It must define:

- pairing flow,
- certificate/key storage,
- TLS version and cipher policy,
- client authentication,
- message framing,
- request IDs, nonces, timestamps, and replay window,
- max message size and timeouts,
- error codes,
- revocation/rotation,
- what happens on disconnect/reconnect,
- threat model and residual risks.

### Pairing

Implement a simple, testable pairing flow:

1. On the host, `ukeyctl pair` generates:
   - a one-time 32-byte random pairing token,
   - a URI/QR payload containing host, port, token, and server certificate
     fingerprint.
2. The user enters/scans the token in the Android app.
3. The phone proves knowledge of the token over a TLS channel.
4. The host stores the phone’s client public key/fingerprint in
   `~/.config/ukey/paired.json` with mode `0600`.
5. The token is single-use and expires after 5 minutes.
6. `ukeyctl devices` lists paired devices.
7. `ukeyctl revoke <id>` removes a device.

A QR code is nice but optional for this phase. A manual pairing code is enough if
it is documented and tested. Do not add a heavy QR dependency unless it is already
available.

### TLS

- Use TLS 1.3 (allow TLS 1.2 only if the Android version requires it; document).
- Generate a self-signed server certificate on first run in
  `~/.config/ukey/tls/` with `0600` permissions.
- The Android app pins the server certificate fingerprint from pairing.
- The server requires a client certificate. Unknown clients are rejected.
- No plaintext fallback. If TLS fails, fail closed.
- Do not log tokens, private keys, or full certificate bodies.

### Framing and replay protection

- Keep the existing JSON length-prefixed framing if possible, but add:
  - a 16-byte request ID,
  - a 32-byte nonce,
  - a timestamp,
  - a monotonically increasing counter per connection.
- Reject duplicate request IDs within a 5-minute window.
- Reject timestamps outside ±60 seconds (allow clock skew; document).
- Reject frames larger than 1 MiB.
- Bound request processing with a timeout (target: 10 seconds; biometric prompts
  may need 60 seconds, but make it configurable and documented).
- Ensure a replayed frame cannot produce a second signature.

### Binding and defaults

- Default: `listen_host = "127.0.0.1"`, `wireless = false`.
- `--wireless` sets the host to `0.0.0.0` only when explicitly passed or configured.
- Print a clear warning when binding to a non-loopback address:
  - “Wireless mode is enabled. Pairing and TLS are required. Do not expose this
    port to the public internet.”
- Add `--listen-host` validation. Refuse `0.0.0.0` unless `--wireless` is set.
- Document firewall guidance.

### Android changes

- Use TLS for the daemon connection.
- Pin the server certificate fingerprint from pairing.
- Store the client key in Android Keystore if feasible; otherwise use an
  app-private file with `MODE_PRIVATE` and document the trade-off.
- Add pairing UI:
  - manual host/port/token entry first,
  - QR scan optional.
- Add paired-device/revoke UI if time permits.
- Reconnect with exponential backoff and heartbeat.
- On TLS/pairing failure, show a clear error; do not silently fall back to
  plaintext.

### CLI

Add or extend `ukeyctl`:

```text
ukeyctl pair
ukeyctl devices
ukeyctl revoke <id>
ukeyctl status
ukeyctl doctor
```

`ukeyctl pair` should print the pairing URI/code and the server fingerprint.

## Tests

### Unit tests

- Frame encode/decode.
- Replay cache accepts a fresh request and rejects a duplicate.
- Timestamp outside the window is rejected.
- Oversized frame is rejected.
- Invalid config is rejected.
- Pairing token expiry and single-use behavior.

### Integration tests

Use two test daemons on ports 8445 and 8446. Do not touch 8443.

1. Start daemon with `--wireless` on 8445. Confirm it binds `0.0.0.0`.
2. Connect with `openssl s_client` without a client cert. Confirm handshake fails
   or the request is rejected.
3. Pair a test client. Confirm `fido2-token -L` sees the device via the daemon’s
   UHID node.
4. Complete `fido2-cred` / `fido2-assert` over TLS.
5. Replay a captured frame. Confirm it is rejected and no second signature is
   produced.
6. Revoke the client. Confirm subsequent connections fail.
7. Start daemon without `--wireless`. Confirm it does not listen on `0.0.0.0`.

### Auto-lock regression

Re-run the Phase 0 auto-lock tests. Secure transport must not change the default:
auto-lock stays off unless enabled.

## Acceptance criteria

1. `fido2-cred` / `fido2-assert` pass over TLS with a paired client.
2. An unpaired client cannot complete a request.
3. A replayed frame is rejected.
4. A wrong server certificate is rejected by the Android client (manual or test).
5. `--wireless` is required to bind beyond loopback; the default is loopback.
6. `ukeyctl pair`, `devices`, `revoke`, `status` work.
7. Phase 0 auto-lock tests still pass.
8. `docs/TRANSPORT.md` matches the implementation.
9. No production service disruption on 8443 / `/dev/hidraw6`.

## Out of scope

- Context-aware sudo (Phase 3).
- PAM/U2F (Phase 2).
- Packaging (Phase 4).
- Bluetooth.
- Resident credentials.
- A full mobile app store release.

Do not start Phase 2 until Phase 1 acceptance checks pass.
