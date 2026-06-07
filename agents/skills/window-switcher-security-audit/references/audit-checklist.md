# Window Switcher Security Audit Checklist

Use this checklist when auditing or re-auditing the `window-switcher` repository.

## Project Profile

- Rust 2021 Windows tray utility.
- Uses global low-level keyboard hooks and window enumeration.
- Supports standard-user startup through `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.
- Supports elevated startup through Windows scheduled tasks.
- Ships a PowerShell installer and GitHub Actions release workflow.

## Minimum File Review Set

- `Cargo.toml`
- `Cargo.lock`
- `tools/inspect-windows/Cargo.toml`
- `install.ps1`
- `README.md`
- `.github/workflows/ci.yaml`
- `.github/workflows/release.yaml`
- `src/main.rs`
- `src/startup.rs`
- `src/config.rs`
- `src/keyboard.rs`
- `src/foreground.rs`
- `src/utils/scheduled_task.rs`
- `src/utils/regedit.rs`
- `src/utils/window.rs`
- `src/utils/admin.rs`
- `src/utils/handle_wrapper.rs`
- `src/utils/app_icon.rs`

## Dependency Review

1. Run `cargo audit` if available.
2. Run `cargo tree` or inspect `Cargo.lock` for direct and transitive crates.
3. Check RustSec/GHSA for notable dependencies:
   - `windows`
   - `once_cell`
   - `smallvec`
   - `rust-ini`
   - `simple-logging`
   - `embed-resource`
   - `xml`
4. If tooling or network is unavailable, document the limitation and cite the locked versions reviewed.
5. Recommend CI coverage with `cargo audit` or `cargo deny`.

Known prior advisory context from the 20260606 audit:

- `windows 0.61.3` is newer than the patched range for RUSTSEC-2022-0008.
- `once_cell 1.21.4` is newer than the patched range for RUSTSEC-2019-0017.
- `smallvec 1.15.1` is newer than older patched advisory ranges checked during the audit.

Recheck these facts on each new audit because advisories change over time.

## Installer Review

Check `install.ps1` and README install instructions for:

- `iwr ... | iex` or other remote-code execution shortcuts.
- Latest-release download without checksum, Authenticode, or artifact-attestation verification.
- Archive extraction and executable replacement behavior.
- Architecture detection and unsupported platform handling.
- Whether downloaded content is constrained to HTTPS and expected GitHub repo/release paths.

Preferred recommendations:

- Publish and verify SHA256 checksums.
- Verify Authenticode signature or GitHub artifact attestation.
- Replace pipe-to-`iex` instructions with download-review-run instructions.

## GitHub Actions Review

Check:

- Release jobs with `permissions: contents: write`.
- Third-party actions pinned only by tags.
- Inline scripts that process untrusted event data.
- Release artifact packaging paths.
- Whether `cargo build --locked` is used.
- Whether dependency audit tooling is absent.

Treat tag-pinned third-party actions in a write-capable release job as high-priority supply-chain risk. Recommend pinning actions to full-length commit SHAs and keeping token permissions minimal.

## Windows Startup And Privilege Review

Check `src/startup.rs`, `src/utils/scheduled_task.rs`, and `src/utils/regedit.rs` for:

- Elevated scheduled task creation and `RunLevel`.
- Predictable temp files, especially XML passed to `schtasks`.
- XML escaping for executable paths, author, SID, and task name.
- Cleanup of temp task files.
- Standard-user startup value quoting in `HKCU Run`.
- Use of broad registry rights such as `KEY_ALL_ACCESS`.

Findings from the 20260606 audit to recheck:

- Scheduled task XML used a predictable temp path: `%TEMP%\window-switcher-task.xml`.
- Standard-user Run value stored the raw executable path rather than an explicitly quoted command line.

## Keyboard Hook, Window Metadata, And Privacy Review

Check `src/keyboard.rs`, `src/foreground.rs`, `src/utils/window.rs`, and `src/main.rs` for:

- Debug logging of keyboard hook structures.
- Debug logging of window titles, executable paths, and foreground app names.
- Log file path selection and permissions.
- Default log level and whether sensitive logs require explicit opt-in.

Default-disabled debug logging can still be a privacy issue if a user enables file logging. Recommend removing or minimizing logs that persist user activity.

## Process Handles And Windows API Hygiene

Check:

- Every `OpenProcess`, token handle, icon handle, DC, bitmap, and mutex handle has a clear owner and close path.
- Existing `HandleWrapper` is used for process/token handles.
- `unsafe` blocks have bounded assumptions and error handling.
- `Vec::with_capacity` followed by FFI writes sets length only after successful writes.
- Null, empty, and insufficient-buffer conditions are handled.

Known hardening item from the 20260606 audit:

- `OpenProcess` results in `src/utils/window.rs` and `src/utils/admin.rs` were not wrapped in `HandleWrapper`.

## Icon And File Loading Review

Check `src/config.rs` and `src/utils/app_icon.rs` for:

- User-configured `override_icons` paths.
- Loading untrusted or oversized icon/image data.
- Relative path resolution next to another app's executable.
- File extension checks and malformed data behavior.

Usually this is a denial-of-service or hardening area unless loading crosses a privilege boundary.

## Report Structure

For audit-only requests, write:

1. Summary and scope.
2. Findings ordered by severity.
3. Dependency review result.
4. Verification notes, including commands that could not run.
5. Recommended next actions.

For saved reports, use `docs/history/YYYYMMDDTHHMM-security-audit.md` unless the user asks for another naming scheme.
