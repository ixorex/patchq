# Changelog

## 0.2.1 — 2026-10-27

### Security
- Fixed scans that could hang on hostile files. Crafted compose, Dockerfile, requirements, npm and version strings triggered catastrophic regex backtracking; one compose input ran for over 5 minutes. All parsers are now linear-time, and version strings are length-capped.
- Deeply nested JSON (in a scanner report, lockfile, cache or feed) no longer crashes the scan; it becomes a warning.
- `requirements.txt` `-r` includes can no longer read files outside the scanned folder. Before, a hostile repo could make PatchQ read arbitrary local files and send `name==version`-shaped lines to OSV.
- Upgrade commands are no longer generated for folder paths that contain control, zero-width or bidi characters. All printed lines and scan labels are cleaned of those characters.
- Feed downloads refuse redirects that leave HTTPS.
- systemd `Environment=` lines are escaped correctly, and newlines are refused.

### Added
- `~/.patchqueue/patchqueue.yml`: a global inventory, so container-only setups can mark services as exposed. `exposed: false` silences the "publishes ports" hint.
- Containers are matched by compose service name (from container labels), container name or image. Podman port mappings are detected.
- `patchq init`:
  - pre-selects your own folders and compose stacks; vendor software under `/opt` isn't pre-selected
  - proposes compose/lock files sitting directly in your home folder
  - accepts ranges like `2-4`
  - asks again on invalid answers instead of silently replacing them
- `patchq init` removes stored results for folders you've dropped from the setup. Decisions are kept.
- `--quiet` prints a one-line summary, useful in `journalctl` and cron mail.
- README: Troubleshooting section.
- GitHub Actions CI on Python 3.9 to 3.14.

### Fixed
- Compose images covered by `--docker` are no longer reported as "NOT checked".
- A scheduled scan now waits for a running scan instead of being skipped.
- A stale dashboard tab (after a restart) shows a friendly message instead of a bare 403.
- `--import` without a folder now gives a clear error instead of being ignored.
- Scan progress lines say which folder they're about.
- License metadata uses the current format (`license = "MIT"`); the old format would break builds after Feb 2027.

## 0.2.0 — 2026-10-26

### Added
- `patchq init` guided setup:
  - finds folders with compose files and lockfiles in `~`, `/opt` and `/srv`
  - asks about running containers, the scan schedule and the dashboard
  - runs the first scan
- `patchq init --yes` for non-interactive setup (`--path`, `--docker`, `--schedule`, `--time`, `--weekday`).
- `patchq scan --docker`: scans images of running Docker/Podman containers with Trivy. Reports are cached for 24h, and missing Trivy or Docker permissions come with the exact fix.
- `patchq scan` with no arguments scans everything configured by `init`.
- Grouped queue (default): one action per package, with upgrade targets for the same minor line, same major and newest fix. Each target shows how many advisories it clears and its breaks-risk. `--by-cve` keeps the per-advisory view.
- Dashboard actions:
  - Scan now (runs in the background with a progress banner)
  - mark patched / defer / not affected / put back in queue
  - schedule settings page
- `patchq service install|uninstall|status`: always-on dashboard and scan timer via `systemd --user`, with a cron line where systemd isn't available.
- `patchq reopen <id>`.
- `--quiet` mode for timers and cron.

### Changed
- The dashboard is no longer read-only. Actions need a per-session form token plus a same-origin request, and the dashboard still binds to 127.0.0.1 only.
- File locking, so the timer, the dashboard and the CLI never overwrite each other's results or decisions.

### Fixed
- Browser form posts were rejected because `Referrer-Policy: no-referrer` makes browsers send `Origin: null`. It's now `same-origin`.
- Dashboard horizontal overflow on phones.

## 0.1.0 — 2026-10-26

First release:
- tiered queue (KEV / EPSS / CVSS)
- npm, Python and compose parsing
- Trivy, Grype and OSV-Scanner import
- OSV / KEV / EPSS / NVD feeds with offline cache
- read-only dashboard
