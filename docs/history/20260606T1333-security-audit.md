# Security Audit Report

- Timestamp: 20260606T1333
- Timezone: Asia/Seoul
- Project: window-switcher
- Scope: Dependency review, install/release workflow review, and manual review of Windows-sensitive code paths.

## Summary

No source changes were made during the audit. The main security concerns are release supply-chain hardening, installer integrity verification, scheduled-task creation safety, sensitive debug logging, autorun command quoting, and a few local handle-lifetime hardening opportunities.

## Findings

### High: Release Workflow Supply-Chain Risk

The release workflow grants `contents: write` and uses tag-pinned third-party actions:

- `.github/workflows/release.yaml:10`
- `.github/workflows/release.yaml:32`
- `.github/workflows/release.yaml:48`
- `.github/workflows/release.yaml:54`
- `.github/workflows/release.yaml:111`

GitHub recommends pinning third-party actions to a full-length commit SHA for immutable action usage: https://docs.github.com/en/actions/reference/security/secure-use

Recommendation: pin `actions/checkout`, `dtolnay/rust-toolchain`, `taiki-e/install-action`, and `softprops/action-gh-release` to full-length commit SHAs. Keep `contents: write` scoped only to the release job/step that actually publishes assets.

### Medium: Predictable Temporary XML for Elevated Scheduled Task Creation

When startup is enabled while running elevated, the scheduled task XML is written to a predictable temp path:

- `src/utils/scheduled_task.rs:123`
- `src/utils/scheduled_task.rs:28`

The task XML is later passed to `schtasks /create`. Since the task can run at `HighestAvailable`, a local same-user race or tampering opportunity against the temp XML would be more sensitive than an ordinary config-file issue.

Recommendation: use the Task Scheduler COM API directly, or generate the XML with a unique random filename, restrictive ACLs, and immediate cleanup after `schtasks` completes.

### Medium: Installer Downloads Latest Release Without Integrity Verification

The README advertises a remote PowerShell execution one-liner:

- `README.md:23`

The installer downloads the latest release and moves the executable into place without checksum, signature, or attestation verification:

- `install.ps1:25`
- `install.ps1:43`
- `install.ps1:73`

PowerShell Team guidance warns against unnecessary `Invoke-Expression` use: https://devblogs.microsoft.com/powershell/invoke-expression-considered-harmful/

Recommendation: publish SHA256 checksums and verify them in `install.ps1`, or verify Authenticode signatures/GitHub artifact attestations before installing. Prefer documenting a download-then-review command over `iwr ... | iex`.

### Medium: Debug Logging Can Persist Sensitive User Activity

When the user enables log output, debug logs can record global keyboard hook events and window/application metadata:

- `src/main.rs:20`
- `src/keyboard.rs:97`
- `src/utils/window.rs:495`
- `src/foreground.rs:81`

The default level is `info`, so this is not active by default. However, once debug logging is enabled, window titles, executable paths, and key scan-code events can be persisted to disk.

Recommendation: remove or heavily reduce keyboard and window-title debug logs. If retained, require an explicit privacy warning/opt-in and redact title/path details where practical.

### Low: HKCU Run Startup Value Stores Unquoted Executable Path

The standard-user startup path writes the raw executable path to the `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` value:

- `src/startup.rs:77`
- `src/startup.rs:79`
- `src/utils/regedit.rs:93`

If the path contains spaces and Windows parses it as a command line, an unquoted autorun command can be ambiguous.

Recommendation: store a quoted command line in the Run value, or use a Startup shortcut / scheduled task flow consistently.

### Low: Process Handles Are Not Closed in Some Paths

`OpenProcess` results are used without being wrapped in `HandleWrapper` in these paths:

- `src/utils/window.rs:126`
- `src/utils/admin.rs:26`

This is primarily an availability and resource hygiene issue for a long-running tray application.

Recommendation: wrap process handles in the existing `HandleWrapper` so handles are closed reliably.

## Dependency Review

`cargo`, `rustc`, and `rustup` were not available in the current environment, so `cargo audit`, `cargo test`, and `cargo clippy` could not be executed locally.

Manual review of `Cargo.lock` and RustSec public advisories found that the checked locked versions of notable dependencies are beyond the patched ranges for the advisories checked:

- `windows 0.61.3` is newer than the patched range for RUSTSEC-2022-0008: https://rustsec.org/advisories/RUSTSEC-2022-0008.html
- `once_cell 1.21.4` is newer than the patched range for RUSTSEC-2019-0017: https://rustsec.org/advisories/RUSTSEC-2019-0017.html
- `smallvec 1.15.1` is newer than the patched range for older `smallvec` advisories listed in RustSec: https://rustsec.org/advisories/

Recommendation: add `cargo audit` or `cargo deny` to CI so dependency advisories are checked continuously.

## Verification Notes

- Read project manifest and lock files: `Cargo.toml`, `Cargo.lock`, `tools/inspect-windows/Cargo.toml`.
- Reviewed install script and GitHub workflows: `install.ps1`, `.github/workflows/ci.yaml`, `.github/workflows/release.yaml`.
- Reviewed Windows-sensitive code paths around scheduled tasks, registry startup, process handles, keyboard hooks, logging, and icon loading.
- Could not run Rust build/test/audit tools because Rust tooling was absent from the environment.
