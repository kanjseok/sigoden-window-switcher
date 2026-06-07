---
name: window-switcher-security-audit
description: Project-specific security audit workflow for the window-switcher repository, a Rust Windows tray utility. Use when Codex is asked to audit, re-audit, harden, or document security findings for this project, especially dependency/RustSec review, PowerShell installer safety, GitHub Actions release supply-chain risk, Windows registry/startup/scheduled-task behavior, keyboard-hook privacy, logging, and Windows handle/API hygiene.
---

# Window Switcher Security Audit

## Overview

Audit this repository as a Windows desktop utility, not as a generic web service. Prioritize release supply-chain integrity, installer trust, local privilege boundaries, privacy-sensitive keyboard/window logging, autorun behavior, and Rust dependency advisories.

## Workflow

1. Inspect repository state and key files first:
   - `Cargo.toml`, `Cargo.lock`, `tools/inspect-windows/Cargo.toml`
   - `install.ps1`, `README.md`
   - `.github/workflows/ci.yaml`, `.github/workflows/release.yaml`
   - `src/startup.rs`, `src/utils/scheduled_task.rs`, `src/utils/regedit.rs`, `src/keyboard.rs`, `src/utils/window.rs`, `src/utils/app_icon.rs`, `src/main.rs`, `src/utils/admin.rs`

2. Run dependency and validation tools when available:
   - `cargo audit`
   - `cargo test --all`
   - `cargo clippy --all --all-targets`
   - `cargo fmt --all --check`

   If Rust tooling is absent, explicitly record that limitation and continue with manual `Cargo.lock` and code review.

3. Use `references/audit-checklist.md` for the detailed project-specific checks and report structure. Load it before writing findings or making hardening changes.

4. Ground findings in exact file and line references. Distinguish:
   - confirmed vulnerabilities or exploitable weakness
   - hardening recommendations
   - tool/environment limitations
   - privacy risks that require configuration to become active

5. Do not change source code unless the user asks for remediation. For an audit-only request, produce a concise findings report. When asked to save history, write Markdown reports under `docs/history/` with a timestamped filename like `YYYYMMDDTHHMM-security-audit.md`.

## Finding Priorities

- Treat release workflows with `contents: write` and tag-pinned actions as high priority supply-chain risk.
- Treat elevated scheduled-task creation, installer integrity, and `iwr ... | iex` guidance as medium-to-high depending on exploitability and distribution context.
- Treat debug logging of keyboard events, window titles, and executable paths as privacy-sensitive even when disabled by default.
- Treat handle leaks, broad registry access, unquoted autorun paths, and oversized/untrusted icon files as hardening findings unless a concrete exploit path is present.

## Useful Search Patterns

Use `rg` first:

```powershell
rg -n "unsafe|Command|schtasks|ShellExecute|CreateProcess|CreateMutex|Registry|Reg|HKEY|Startup|runas|admin|token|password|secret|Invoke-|http|https|unwrap\(|expect\(" src tools install.ps1 build.rs Cargo.toml .github
rg -n "debug!\(|info!\(|log_to|log_file|keyboard|list windows|foreground" src
rg -n "permissions:|uses:|contents: write|action-gh-release|install-action|rust-cache|checkout|rust-toolchain" .github\workflows
```

## Output

Lead with findings ordered by severity. Include short recommendations and verification notes. If no high-confidence issue is found, say so plainly and identify residual risks or missing tool coverage.
