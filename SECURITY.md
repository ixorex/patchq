# Security policy

## Supported versions

Only the latest release on `main` gets fixes.

## Reporting a vulnerability in PatchQ

Please **don't open a public issue**. Use GitHub's private reporting instead: **Security → Report a vulnerability** on this repo. Expect a reply within 7 days.

Most useful in a report: the PatchQ version, the input file (lockfile, compose file or scanner report) that triggers the bug, and what happened.

## Threat model (short)

PatchQ treats every lockfile, compose file, scanner report, feed response and container label as untrusted. That includes repos you scan by URL.

- **Executes nothing from scanned content.** No hooks, builds or submodules. Docker, Trivy, git and systemctl are run with argument lists, never through a shell, and image names are validated so one can't be read as a command-line flag.
- **Upgrade commands are safe to paste.**
  - Commands are only generated for package names and versions that pass a strict per-ecosystem pattern, and everything is shell-quoted.
  - No command is generated when a folder path contains control characters, zero-width characters or bidi overrides (text that could make a printed command differ from what you paste).
- **Terminal output is cleaned.** Control characters, escape sequences and bidi/zero-width characters are stripped before printing.
- **No file reads outside the scan.** `requirements.txt` `-r` includes and symlinked inputs must stay inside the scanned folder; anything pointing elsewhere is skipped with a warning.
- **Hostile input can't hang or crash a scan.**
  - Parsers use linear-time patterns and cap version-string length.
  - Deeply nested JSON becomes a warning instead of a crash.
  - Files over 50 MB and feed responses over 64 MB are refused.
- **Feeds are HTTPS-only.** Redirects to `http:`, `file:` or anything else that isn't `https:` are refused.
- **The dashboard is local and protected.**
  - It binds to 127.0.0.1 only and rejects foreign Host headers (DNS rebinding).
  - Every action (scan, decisions, schedule) needs a per-session form token and a same-origin request.
  - It runs no JavaScript, uses a strict security policy and HTML-escapes everything.
  - Which folders get scanned can only be changed from a terminal (`patchq init`).
- **git is restricted.** Only https/ssh URLs are accepted, `ext::` and `file` transports are disabled for clones, and git never prompts for a password.
- **Service files are written safely.** systemd units are generated with escaped values, and anything containing a newline is refused.

Known limits:

- **Package names and versions are sent to OSV.dev.** This includes private or internal package names. CVE IDs go to FIRST and NVD.
- **`~/.patchqueue/queue.json` is a map of your unpatched vulnerabilities.** It is mode 0600 but not encrypted.
- **The dashboard has no login.** Anyone who can already run commands as you on that machine can use it. That's no more access than they'd have to the files themselves.
- **Only use `--pull` on folders you trust.** It runs `git pull` with that repo's own git config.
- **`--docker` asks Trivy to scan images.** Trivy may pull image metadata from registries.
