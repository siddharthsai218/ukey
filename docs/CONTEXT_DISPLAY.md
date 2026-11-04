# Context Display on the Phone

This document defines what the phone shows for each approval request, where that
context comes from, and what cannot be shown honestly.

## Principle

The phone can only display context that the request actually carries. There are
two different sources:

| Flow | Context source | What the phone can show |
|---|---|---|
| Browser WebAuthn | CTAP2 request from Chrome/Firefox | RP ID, account name (registration), action |
| `sudo` / PAM | Host helper reading `/proc` and PAM | command, user, TTY, cwd, host, service |

The phone UI is one approval screen with a `kind` field. The payload differs.

## What CTAP2 actually provides

### `authenticatorMakeCredential`

The daemon receives:

- `rp.id` — e.g. `google.com`
- `rp.name` — e.g. `Google`
- `user.id` — opaque bytes
- `user.name` — e.g. `sid@gmail.com`
- `user.displayName` — e.g. `Siddharth`
- `clientDataHash` — SHA-256 of the browser's `clientDataJSON`
- `options` — `rk`, `uv`
- `excludeList`

### `authenticatorGetAssertion`

The daemon receives:

- `rpId` — e.g. `google.com`
- `clientDataHash`
- `allowList` — credential IDs
- `options` — `up`, `uv`

It does **not** receive the user name. To show an account on login, store
`user.name` and `user.displayName` with the credential at registration time.

### What is never available

- The full page URL or origin. CTAP2 sends only `clientDataHash`, not
  `clientDataJSON`.
- The page content, the login button, or the browser tab.
- A human-readable command for `pam_u2f`. U2F has only a challenge and an
  application parameter (RP ID hash).

Chrome already shows the origin in its own WebAuthn dialog. The phone must not
claim to show it.

## Unified request envelope

The daemon sends JSON to the phone over the signer bridge. Add a `kind` field and
the context fields for that kind.

### WebAuthn registration

```json
{
  "id": 42,
  "kind": "webauthn.create",
  "rp_id": "google.com",
  "rp_name": "Google",
  "account": "sid@gmail.com",
  "display_name": "Siddharth",
  "host": "fedora-laptop",
  "digest": "<64 hex chars>"
}
```

### WebAuthn login

```json
{
  "id": 43,
  "kind": "webauthn.get",
  "rp_id": "google.com",
  "account": "sid@gmail.com",
  "host": "fedora-laptop",
  "digest": "<64 hex chars>"
}
```

If the credential was created before user metadata was stored, `account` is
absent. Show `(account unknown)` rather than guessing.

### `sudo` approval

```json
{
  "id": 44,
  "kind": "sudo.approve",
  "service": "sudo",
  "command": "rm -rf /var/cache/foo",
  "user": "sid",
  "tty": "pts/3",
  "cwd": "/home/sid",
  "host": "fedora-laptop",
  "digest": "<64 hex chars>"
}
```

The `sudo` payload never comes from CTAP2. It comes from a PAM module or host
helper that reads `SUDO_COMMAND`, `/proc/<pid>/cmdline`, `/proc/<pid>/cwd`, and
the PAM items, then sends the request to the daemon over a local Unix socket.

## Screen mockups

WebAuthn registration:

```text
+----------------------------------+
| Create a passkey?                |
|                                  |
| google.com                       |
| Account: sid@gmail.com           |
| This laptop: fedora-laptop       |
|                                  |
| [ Deny ]            [ Approve ]  |
+----------------------------------+
```

WebAuthn login:

```text
+----------------------------------+
| Sign in?                         |
|                                  |
| google.com                       |
| Account: sid@gmail.com           |
| This laptop: fedora-laptop       |
|                                  |
| [ Deny ]            [ Approve ]  |
+----------------------------------+
```

`sudo`:

```text
+----------------------------------+
| Approve sudo?                    |
|                                  |
| sudo rm -rf /var/cache/foo       |
|                                  |
| user: sid                        |
| tty:  pts/3                      |
| cwd:  /home/sid                  |
| host: fedora-laptop              |
|                                  |
| [ Deny ]            [ Approve ]  |
+----------------------------------+
```

The command must be rendered as plain text in a monospace block. Never render it
as HTML, never interpret escape sequences, and truncate with a visible warning if
it is too long.

## Digest binding

Displaying context is not enough. The phone must sign a digest that is bound to
the context it displayed.

### Current WebAuthn path

The daemon computes:

```text
auth_data = SHA256(rp_id) || flags || sign_count_be32
digest    = SHA256(auth_data || client_data_hash)
```

It sends `rp_id` and `digest` to the phone. The phone displays `rp_id` and signs
`digest`, but it cannot verify that `digest` really corresponds to `rp_id`. A
compromised or buggy daemon could display one RP and request a signature for
another.

### Stronger WebAuthn path

Send the components instead of only the digest:

```json
{
  "kind": "webauthn.get",
  "rp_id": "google.com",
  "flags": 5,
  "sign_count": 17,
  "client_hash": "<64 hex chars>",
  "digest": "<64 hex chars>"
}
```

The phone recomputes:

```text
rp_id_hash = SHA256(rp_id)
auth_data  = rp_id_hash || flags || sign_count_be32
expected   = SHA256(auth_data || client_hash)
```

It refuses to sign if `expected != digest`. Then the displayed `rp_id` is
cryptographically bound to the signature.

Registration is harder because `auth_data` includes the credential public key and
AAGUID. Implement the assertion path first; it is the one used on every login.

### `sudo` path

Canonicalize the context fields (sorted keys, UTF-8, no whitespace), hash them,
display the same fields, and sign that hash:

```text
digest = SHA256(canonical_json_without_digest)
```

The daemon verifies the signature over the same canonical bytes before returning
`PAM_SUCCESS`. This is what makes "see what you sign" true rather than advisory.

## Code touchpoints

- `daemon/ukey_daemon.py::_make_credential` — add `kind`, `rp_name`, `account`,
  `display_name`, `host` to `self.signer.request(...)`.
- `daemon/ukey_daemon.py::_get_assertion` — add `kind`, `account` (looked up from
  the credential store), `host`; send `flags`, `sign_count`, `client_hash` for
  digest verification.
- `daemon/ukey_daemon.py::Credential` — persist `user_name` and
  `user_display_name`; include them in `_save_credentials()` and
  `_load_credentials()`.
- `android/app/src/main/java/org/ukey/Protocol.kt` — extend `SignerRequest` with
  `kind`, `account`, `displayName`, `host`, `command`, `service`, `tty`, `cwd`,
  `flags`, `signCount`, `clientHash`.
- `android/app/src/main/java/org/ukey/BridgeState.kt` — extend `AuthChallenge`
  with the same context fields.
- `android/app/src/main/java/org/ukey/MainActivity.kt` — replace the biometric
  subtitle with an approval card that switches on `kind`.
- `android/app/src/main/java/org/ukey/UKeyService.kt` — `handleMakeCredential`
  currently creates a credential without a user-facing approval. Add an
  approval step so registration also shows the RP and account.
- New `pam_ukey.so` and `ukey-context` helper — Phase 3. Do not try to get the
  command out of `pam_u2f`; it is not there.

## Test plan

1. `webauthn.io` registration: phone shows `webauthn.io` and the account.
2. `webauthn.io` login: phone shows `webauthn.io` and the stored account.
3. GitHub security key registration/login.
4. Google passkey: expected to fail until resident credentials (`rk=true`) are
   implemented. Do not claim it works.
5. `sudo -k; sudo ls`: phone shows `sudo ls`, user, TTY, cwd, host.
6. Deny: command does not run.
7. Timeout: command does not run; password fallback still works.
8. Tamper with the display fields in a test harness: phone refuses to sign
   because the recomputed digest does not match.

## Honest limits

- Browser context is **weaker** than the browser's own UI: the phone sees the RP
  ID, not the full origin. Chrome's dialog is the authoritative origin display.
- `sudo` context is the differentiator because no standard terminal or PAM UI
  shows the exact command before authorization.
- A compromised host daemon can lie about the context it gathers. The signature
  binds the phone's approval to what the daemon sent, not to ground truth. This
  is a residual risk; document it in `docs/THREAT_MODEL.md`.
