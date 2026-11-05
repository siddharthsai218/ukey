#!/usr/bin/env python3
"""Configuration loading and validation for uKey.

The daemon and ukeyctl share this module. Configuration is intentionally small
and explicit: unknown keys are rejected so a typo does not silently enable a
feature.

Defaults are safe:

- the signer bridge stays on loopback,
- phone disconnect does not lock the desktop,
- the virtual device keeps its established name.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Any, Mapping, Optional

CONFIG_ENV = "UKEY_CONFIG"
DEFAULT_CONFIG_PATH = "~/.config/ukey/config.json"


class ConfigError(ValueError):
    """Raised when a configuration file or value is invalid."""


@dataclass(frozen=True)
class UKeyConfig:
    wireless: bool = False
    auto_lock: bool = False
    auto_lock_grace_seconds: int = 5
    listen_host: str = "127.0.0.1"
    port: int = 8443
    device_name: str = "uKey FIDO2 Authenticator"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def config_path(env: Optional[Mapping[str, str]] = None) -> Path:
    """Return the configured path, honoring UKEY_CONFIG."""
    source = env if env is not None else os.environ
    raw = (source.get(CONFIG_ENV) or "").strip()
    return Path(raw or DEFAULT_CONFIG_PATH).expanduser()


def _require_bool(name: str, value: Any) -> bool:
    if not isinstance(value, bool):
        raise ConfigError(f"{name} must be true or false")
    return value


def _require_int(name: str, value: Any, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{name} must be an integer")
    if value < minimum or value > maximum:
        raise ConfigError(f"{name} must be between {minimum} and {maximum}")
    return value


def _require_text(name: str, value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise ConfigError(f"{name} must be a non-empty string")
    if value != value.strip():
        raise ConfigError(f"{name} must not have leading or trailing whitespace")
    if "\n" in value or "\r" in value:
        raise ConfigError(f"{name} must be a single line")
    return value


def validate_config(data: Mapping[str, Any]) -> dict[str, Any]:
    """Validate a partial or complete mapping and fill in defaults."""
    if not isinstance(data, Mapping):
        raise ConfigError("configuration must be a JSON object")

    known = {field.name for field in fields(UKeyConfig)}
    unknown = sorted(set(data) - known)
    if unknown:
        raise ConfigError(f"unknown configuration key(s): {', '.join(unknown)}")

    values = {field.name: data.get(field.name, field.default) for field in fields(UKeyConfig)}
    _require_bool("wireless", values["wireless"])
    _require_bool("auto_lock", values["auto_lock"])
    _require_int("auto_lock_grace_seconds", values["auto_lock_grace_seconds"], 0, 86400)
    _require_int("port", values["port"], 1, 65535)
    _require_text("listen_host", values["listen_host"])
    _require_text("device_name", values["device_name"])
    return values


def load_config(
    path: Optional[Path] = None,
    *,
    create: bool = False,
    env: Optional[Mapping[str, str]] = None,
) -> UKeyConfig:
    """Load configuration, creating a safe default file when requested."""
    target = Path(path).expanduser() if path is not None else config_path(env)
    if not target.exists():
        config = UKeyConfig()
        if create:
            save_config(config, target)
        return config

    try:
        raw = json.loads(target.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"cannot read {target}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{target} is not valid JSON: {exc}") from exc

    try:
        return UKeyConfig(**validate_config(raw))
    except ConfigError as exc:
        raise ConfigError(f"{target}: {exc}") from exc


def save_config(
    config: UKeyConfig | Mapping[str, Any],
    path: Optional[Path] = None,
    *,
    env: Optional[Mapping[str, str]] = None,
) -> Path:
    """Atomically write configuration with mode 0600."""
    if isinstance(config, UKeyConfig):
        values = config.to_dict()
    else:
        values = validate_config(config)

    target = Path(path).expanduser() if path is not None else config_path(env)
    parent = target.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    descriptor = -1
    temporary: Optional[str] = None
    try:
        descriptor, temporary = tempfile.mkstemp(
            prefix=".config-", suffix=".json", dir=str(parent)
        )
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = -1
            json.dump(values, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
        temporary = None
        os.chmod(target, 0o600)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary is not None:
            try:
                os.unlink(temporary)
            except OSError:
                pass
    return target


def resolve_config(
    args: Any,
    *,
    env: Optional[Mapping[str, str]] = None,
    path: Optional[Path] = None,
    create: bool = False,
) -> UKeyConfig:
    """Merge CLI arguments over the file configuration.

    A value of None on the argument namespace means "not supplied". This lets
    --wireless / --no-wireless and --auto-lock / --no-auto-lock be tri-state.
    """
    config = load_config(path=path, create=create, env=env)

    wireless = config.wireless
    if getattr(args, "wireless", None) is not None:
        wireless = bool(args.wireless)

    auto_lock = config.auto_lock
    if getattr(args, "auto_lock", None) is not None:
        auto_lock = bool(args.auto_lock)

    grace = config.auto_lock_grace_seconds
    if getattr(args, "auto_lock_grace_seconds", None) is not None:
        grace = args.auto_lock_grace_seconds

    listen_host = config.listen_host
    if getattr(args, "listen_host", None) is not None:
        listen_host = args.listen_host
    elif getattr(args, "wireless", None) is False:
        listen_host = "127.0.0.1"
    elif wireless:
        listen_host = "0.0.0.0"

    port = config.port
    if getattr(args, "port", None) is not None:
        port = args.port

    device_name = config.device_name
    if getattr(args, "device_name", None) is not None:
        device_name = args.device_name

    values = validate_config(
        {
            "wireless": wireless,
            "auto_lock": auto_lock,
            "auto_lock_grace_seconds": grace,
            "listen_host": listen_host,
            "port": port,
            "device_name": device_name,
        }
    )
    return UKeyConfig(**values)
