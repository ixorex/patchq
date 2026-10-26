# Security policy

## Reporting a vulnerability in PatchQ

Please **don't open a public issue**. Use GitHub's private reporting instead: **Security → Report a vulnerability** on this repo. Expect a reply within 7 days.

Most useful in a report: the PatchQ version, the input file (lockfile, compose file or scanner report) that triggers the bug, and what happened.

## Threat model (short)

PatchQ treats every lockfile, scanner report and feed response as untrusted.

- **Executes nothing from scanned content.** No hooks, builds or submodules.
- **Upgrade commands are safe to paste.** They are only generated for names and versions that pass a strict per-ecosystem pattern, and are shell-quoted.
- **Terminal output is cleaned.** Control characters and escape sequences are stripped before printing.
- **The dashboard is locked down.** It binds 127.0.0.1 only, rejects foreign Host headers, is read-only, runs no JavaScript and HTML-escapes everything.
- **git is restricted.** Only https/ssh URLs are accepted, and `ext::`/`file` transports are disabled for clones.
- **Symlinks can't pull in outside files.** A symlinked input pointing outside the scanned folder is skipped.

Known limits:

- **Package names and versions are sent to OSV.dev.** This includes private or internal package names.
- **`~/.patchqueue/queue.json` is a map of your unpatched vulnerabilities.** It is mode 0600 but not encrypted.
- **Only use `--pull` on folders you trust.** It runs `git pull` with that repo's own git config.
