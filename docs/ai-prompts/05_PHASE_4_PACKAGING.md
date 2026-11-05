# Phase 4 — Cross-Distro Packaging (Lane D)

Read `00_MASTER_CONTEXT.md` and complete Phase 0 first. This phase can run in
parallel with Phases 2–3 if the branches do not conflict.

## Goal

Make uKey installable on Fedora, Debian/Ubuntu, and Arch with one command, a
systemd user service, udev rules, and a clean uninstall. No hardcoded
`~/Desktop/ukey` paths. No Fedora-only assumptions.

## Current problem

`install.sh` uses `rpm`/`dnf` and hardcodes the checkout path in the systemd unit.
It does not work on Debian/Ubuntu or Arch. The service starts with
`--wireless --auto-lock`, which Phase 0 changes.

## Tasks

### 1. `ukeyctl` install/uninstall/doctor

Extend `ukeyctl` (from Phase 0) with:

```text
ukeyctl install [--user|--system]
ukeyctl uninstall [--purge]
ukeyctl doctor
ukeyctl status
ukeyctl config get/set
```

Requirements:

- `install` detects the distro and package manager.
- `install` creates the venv and installs Python dependencies.
- `install` installs udev rules and reloads udev.
- `install` installs a systemd user unit and enables it.
- `install` does **not** start wireless or auto-lock by default.
- `uninstall` stops/disables the service, removes the unit and udev rule, and
  preserves user credentials/config unless `--purge` is passed.
- `doctor` checks dependencies, `/dev/uhid`, permissions, service state, and port
  availability. It must not install anything.

### 2. Distro detection

Parse `/etc/os-release` and support:

| Family | Package manager | Packages |
|---|---|---|
| Fedora / RHEL | `dnf` | `python3`, `python3-cbor2`, `fido2-tools`, `pam-u2f`, `pamu2fcfg` |
| Debian / Ubuntu | `apt-get` | `python3`, `python3-cbor2`, `fido2-tools`, `libpam-u2f` |
| Arch | `pacman` | `python`, `python-cbor2`, `fido2-tools`, `pam-u2f` |

Verify package names on each distro. If a package name differs, detect and report
it; do not silently skip a dependency.

Optional dependencies:

- `android-tools` / `adb` for USB reverse.
- `bluez` only if Bluetooth is implemented later.
- `qrencode` only if QR pairing is implemented.

### 3. Portable systemd unit

Create a unit that does not depend on a checkout path:

```ini
[Unit]
Description=uKey Virtual FIDO2 Security Key
Documentation=https://github.com/siddharthsai218/ukey
After=network.target

[Service]
Type=simple
ExecStart=%h/.local/share/ukey/.venv/bin/python %h/.local/share/ukey/daemon/ukey_daemon.py
Restart=on-failure
RestartSec=3
Environment=PYTHONUNBUFFERED=1
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=%h/.config/ukey %h/.local/state/ukey
DeviceAllow=/dev/uhid rw
IPAddressAllow=localhost

[Install]
WantedBy=default.target
```

Adjust paths if the install layout differs. Verify the sandbox does not break
`/dev/uhid`, the Unix socket, logs, or PAM helper access. If a hardening option is
incompatible, remove it and document why.

`IPAddressAllow=localhost` would block wireless mode; either omit it or provide a
drop-in for wireless users. Do not silently break Lane A.

### 4. udev rules

- Install a rule for `/dev/uhid` and the virtual hidraw device.
- Use `TAG+="uaccess"` so the logged-in user gets access without world-writable
  permissions.
- Ensure `uhid` module autoload.
- Test on Fedora, Debian/Ubuntu, and Arch.
- Do not require root to run the daemon after install.

### 5. Packages

Add packaging under `packaging/`:

- `packaging/debian/` — `control`, `rules`, `install`, `postinst`, `prerm`.
  Build a `.deb` with `dpkg-buildpackage` or `debuild`.
- `packaging/rpm/ukey.spec` — build an `.rpm` with `rpmbuild`.
- `packaging/arch/PKGBUILD` — build with `makepkg`.
- Include:
  - daemon,
  - Android APK? Probably not in Linux packages; link to releases instead.
  - systemd unit,
  - udev rule,
  - `ukeyctl`,
  - docs,
  - license.
- Do not include `.venv`, build artifacts, or local config.

### 6. Release workflow

Add `.github/workflows/release.yml` triggered on tags:

- Build `.deb`, `.rpm`, Arch package, source tarball, and APK.
- Generate SHA-256 checksums.
- Attach artifacts to the GitHub release.
- Include a changelog.
- Do not publish secrets.

### 7. Tests

Use containers/VMs for:

- Fedora latest,
- Ubuntu LTS,
- Debian stable,
- Arch latest.

For each:

1. Fresh install.
2. `ukeyctl doctor` passes.
3. `systemctl --user status ukey` is active.
4. `fido2-token -L` shows the virtual device.
5. Mock signer + `fido2-cred`/`fido2-assert` pass.
6. `ukeyctl uninstall` removes the unit/udev rule and leaves config unless
   `--purge`.
7. Reinstall works.

In CI, `/dev/uhid` may be unavailable. Split tests into:

- install/package tests that do not need UHID,
- hardware tests that are manual or run on a privileged runner.

## Acceptance criteria

1. One command installs on Fedora, Debian/Ubuntu, and Arch.
2. The service starts in safe mode (no wireless, no auto-lock).
3. `fido2-token -L` sees the device after install.
4. `ukeyctl doctor` reports missing dependencies clearly.
5. `ukeyctl uninstall` is clean.
6. No hardcoded `/home/<user>/Desktop/ukey` path in the unit or scripts.
7. Packages build and contain the expected files.
8. Release workflow produces artifacts and checksums.
9. Phase 0 auto-lock defaults remain intact.
10. The production service on 8443 is not disturbed during development.

## Out of scope

- Windows/macOS.
- Snap/Flatpak.
- A mobile app store release.
- Bluetooth packaging.
- System-wide (root) daemon mode unless needed for PAM; prefer user service.

Do not start Phase 5 until Phase 4 acceptance checks pass.
