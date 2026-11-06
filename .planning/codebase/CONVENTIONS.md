---
last_mapped_commit: 20aa48b012b01497d738980fff0dad10a7d85b96
last_mapped_at: 2026-11-06
---
# Code & Design Conventions

**Analysis Date:** 2026-11-06

## Python Architecture & Style (`daemon/`, `scripts/`, `tests/`)

- **Strict Type Annotations**:
  - All Python modules declare `from __future__ import annotations`.
  - Full typing coverage using `typing.Optional`, `typing.Callable`, `typing.Any`, `typing.Union`.
  - Type hints are enforced across daemon interfaces and configuration dataclasses.
- **Defensive File I/O & Atomic Persistence**:
  - Configuration files (`config.json`, `pairing.json`) are written atomically:
    1. Create a `NamedTemporaryFile` in the target directory.
    2. Write JSON and call `flush()` + `os.fsync(fileno)`.
    3. Close and perform atomic swap via `os.replace(temp.name, target_path)`.
    4. Enforce strict filesystem permissions (`os.chmod(target_path, 0o600)`).
- **Concurrency & Thread Safety**:
  - The daemon is multi-threaded: an accept thread (`_accept_loop`), a connection monitor thread (`_watch_conn`), a CTAPHID event thread, and an embedded web server thread.
  - Sockets and shared state are guarded by `threading.Lock` (`_io_lock`) and `threading.Condition` (`_conn_cond`).
- **Binary Struct Handling**:
  - Linux kernel `/dev/uhid` structures use standard `ctypes.Structure` with explicit field sizing (`c_uint32`, `c_uint8`, `c_char * 128`).
  - Network and CBOR framing use standard `struct.pack` and `struct.unpack` with explicit network endianness (`>I`, `>H`).
- **Logging & Diagnostics**:
  - Standard library `logging.getLogger("ukey.*")` with structured log levels (`DEBUG`, `INFO`, `WARNING`, `ERROR`).
  - No raw `print()` statements inside daemon modules; CLI scripts (`ukeyctl`) use `print()` for human-readable output.

## Android / Kotlin Style (`android/app/`)

- **Modern Kotlin & Coroutines**:
  - Asynchronous socket I/O runs inside `kotlinx.coroutines` managed by lifecycle-aware scopes (`lifecycleScope`, `repeatOnLifecycle`).
  - Data transfer across coroutine boundaries uses channels (`Channel<String>`).
  - Exponential backoff with random jitter on network reconnects (`Random.nextLong(0, 251)`).
- **Hardware Enclave Gating**:
  - StrongBox is preferred; TEE is used only as fallback if StrongBox is unavailable on device hardware.
  - Software keys are explicitly rejected via `keyInfo.isInsideSecureHardware`.
  - Biometric authentication is enforced per-use via `CryptoObject`.
- **Stateless Identifiers**:
  - Credential IDs are 32 bytes: 16-byte SHA-256 Relying Party prefix + 16-byte UUID bytes.

## Bash & Shell Conventions (`install.sh`, `scripts/`, `setup_udev.sh`)

- **Strict Execution Flags**:
  - All scripts declare `set -euo pipefail` at the header to fail immediately on unset variables or command errors.
  - Scripts verify syntax with `bash -n` in CI.
- **Cross-Distribution Detection**:
  - Parsing `/etc/os-release` (`ID`, `ID_LIKE`) to automatically handle package management differences between `dnf`, `apt-get`, `pacman`, and `zypper`.
- **Idempotency & Reversibility**:
  - Shell scripts maintain backups (`/etc/pam.d/sudo.ukey.bak`) and provide clean rollback flags (`--restore`, `--uninstall`).
