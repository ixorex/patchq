# Changelog

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
