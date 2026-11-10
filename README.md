# PatchQ

**One ranked patch queue for your homelab / dev stack.** Point it at a folder or a git repo. It finds your lockfiles, compose files and scanner reports by itself, and gives back a single queue: **Patch Today / This Week / This Sprint / Watching**.

Each item comes with:
- the fixed version, or a plain "no fix yet"
- the exact upgrade command
- a one-line reason for its rank
- a breaks-risk flag (patch / minor / major bump)

PatchQ makes a decision. It does not send alerts or dump 200 unordered findings on you.

Free, MIT-licensed, no account, no telemetry, standard-library Python only.


## What's new in 0.2

- **`patchq init`**: one-time guided setup that finds your projects, asks a few questions, and handles the rest.
- **Running containers**: `patchq scan --docker` checks the images of containers running right now (via Trivy).
- **One action per package**: the queue groups CVEs by package and shows which upgrade clears how many.
- **Dashboard with buttons**: Scan now, mark patched / defer / not affected, and change the schedule from the browser.
- **Always on**: background dashboard and daily/weekly scans via `systemd --user` (cron fallback).

Full list in [CHANGELOG.md](CHANGELOG.md).

## Quickstart (about 2 minutes)

```bash
pipx install git+https://github.com/ixorex/patchq.git
patchq init
```

`patchq init` walks you through setup in about a minute:

1. **Finds what to scan.** It looks in your home folder, `/opt` and `/srv` for compose files and lockfiles, and you pick which to include. Your own folders and compose stacks are pre-selected; vendor software under `/opt` isn't.
2. **Running containers.** If Docker or Podman is installed, it offers to scan the containers running right now (uses Trivy).
3. **Automatic scans.** Daily, weekly or off, at a time you choose.
4. **Dashboard.** It keeps the dashboard running in the background at http://127.0.0.1:8765.

Then it runs the first scan. After that you don't need to type anything: scans happen on schedule and the dashboard is always up. Open the dashboard to see what to patch, mark things patched / deferred / not affected, change the schedule, or hit **Scan now**.

On a headless box (Pi, server), view the dashboard from your PC through SSH:

```bash
ssh -N -L 8765:127.0.0.1:8765 you@your-server     # then open http://127.0.0.1:8765
```

Needs Python 3.9+. Built for Linux; macOS should work but is untested. Background services use `systemd --user`; where that's missing, `init` prints a cron line instead. Container scanning needs [Trivy](https://trivy.dev) (`sudo apt install trivy` on Kali; other distros see trivy.dev).

Other ways to install:

```bash
pip install git+https://github.com/ixorex/patchq.git
git clone https://github.com/ixorex/patchq.git && cd patchq && python3 -m patchqueue init
```

## Commands

```bash
patchq init                                 # guided setup (re-run any time to change it)
patchq scan                                 # scan everything init set up
patchq scan ~/homelab                       # or scan one folder right now
patchq scan --docker                        # include containers running on this machine
patchq scan https://github.com/me/app.git   # shallow-clone (https/ssh), then scan
patchq scan . --pull                        # git pull --ff-only first
patchq scan . --import trivy-nginx.json     # include a Trivy / Grype / OSV-Scanner report
patchq queue                                # one line per package, with upgrade options
patchq queue --by-cve                       # one line per CVE
patchq queue --all                          # expand Watching + decision history
patchq done   CVE-2021-23337
patchq defer  CVE-2014-6271 --reason "box retired next sprint" --recheck 2026-11-15
patchq ignore CVE-2020-8203 --reason "zipObjectDeep never called" [--recheck 2027-01-01]
patchq reopen CVE-2020-8203                 # put it back in the queue (history kept)
patchq serve                                # dashboard in the foreground
patchq service status|install|uninstall     # background dashboard + scheduled scans
```

**One action per package.** Forty CVEs in one old Django are one decision, so the queue groups them by package and offers up to three upgrade targets:
- stay on your minor line
- stay on your major version
- newest fix

Each target shows how many of the advisories it clears and its breaks-risk. `--by-cve` shows the per-advisory view.

Decisions are stored in `~/.patchqueue/queue.json` with their full history. Six months from now, `patchq queue --all` still tells you why something was ignored. Re-running `scan` keeps every decision. If you mark something done but it is still in your lockfile, PatchQ says so instead of hiding it.

## Example output

This is real output from `tests/fixtures/sample-homelab` (default grouped view; `--by-cve` lists each advisory). It ran offline against the test fixture feeds, so the EPSS/KEV numbers are illustrative.

```
PatchQ 0.2.1 — scan for: homelab (scanned 2026-10-26 20:34)
Data as of (UTC): OSV 2026-10-26 20:34 (cache) · KEV 2026-10-26 20:34 (cache) · EPSS 2026-10-26 20:34 (cache) · NVD —

PATCH TODAY · 2 packages
  1  openssl 1.0.1e-2+deb7u4  (Debian) · 1 vuln · CISA KEV · top EPSS 0.974
     where  legacy (trivy-legacy.json)  [exposed, critical]
     why    worst: CVE-2014-0160 — Tier 0 (Patch Today): in CISA KEV — confirmed exploited (added 2022-05-04, CISA due 2022-05-25); fix available. EPSS 0.974 · CVSS 7.5.
     fix    → 1.0.1e-2+deb7u5  breaks risk: low — patch bump
            apt-get update && apt-get install -y --only-upgrade openssl
  …

THIS WEEK · 3 packages
  5  lodash 4.17.15  (npm) · 2 vulns (2 This Week) · top EPSS 0.006
     where  web (web/package-lock.json)  [exposed]
     why    worst: CVE-2021-23337 — Tier 1 (This Week): CVSS 7.2 ≥ 7.0; fix available; +1 tier: web marked exposed in patchqueue.yml. EPSS 0.006 · CVSS 7.2.
     fix    → 4.17.21  clears all 2  breaks risk: low — patch bump
            cd ~/homelab/web && npm install lodash@4.17.21
     ids    CVE-2021-23337, CVE-2020-8203   (`patchq queue --by-cve` for each one)
  …

THIS SPRINT / PLAN · 3 packages
  7  jinja2 2.10  (PyPI) · 2 vulns (1 Sprint, 1 Watching) · top EPSS 0.003
     where  api (api/requirements.txt); worker (worker/poetry.lock)
     why    worst: CVE-2019-10906 — Tier 2 (This Sprint / Plan): CVSS 8.6 ≥ 7.0; fix available. EPSS 0.003 · CVSS 8.6.
     upgrade options:
       → 2.10.1  clears 1 of 2  (same minor line)  breaks risk: low — patch bump
         cd ~/homelab/api && pip install jinja2==2.10.1
         cd ~/homelab/worker && poetry add 'jinja2>=2.10.1'
         then change the pin in api/requirements.txt to jinja2==2.10.1
       → 3.1.3  clears all 2  (newest fix)  breaks risk: high — major bump, test in staging
         cd ~/homelab/api && pip install jinja2==3.1.3
         cd ~/homelab/worker && poetry add 'jinja2>=3.1.3'
         then change the pin in api/requirements.txt to jinja2==3.1.3
  …

WATCHING · 1 package  (collapsed — `patchq queue --all`)
  9  apt 0.9.7.9+deb7u7  (Debian) · 1 vuln · top EPSS 0.001  → no fix yet

PatchQ is a triage aid, not a guarantee. It ranks what it can see from public feeds. It cannot see private advisories, zero-days, or code you didn't tell it about.
```

## How ranking works

The ranking uses tiers rather than a black-box score, so you can always tell why item #1 beats item #2.

| Tier | Rule (a fix must exist) | Order inside the tier |
|---|---|---|
| 0 · Patch Today | In CISA KEV (confirmed exploited), or known ransomware use | KEV due date ↑, then EPSS ↓, then CVSS ↓ |
| 1 · This Week | EPSS ≥ 0.10, or public PoC + internet-facing | EPSS ↓, then CVSS ↓ |
| 2 · This Sprint / Plan | EPSS ≥ 0.01, or CVSS ≥ 7.0 | EPSS ↓, then CVSS ↓ |
| 3 · Watching | Everything else, plus no-fix-yet, deferred, not-affected | Exploited-no-fix first; always listed, never hidden |

- **Internet-facing systems move up one tier.** Mark them in `patchqueue.yml` (see below).
- **A major-version bump only adds a warning:** "breaks risk: high — test in staging". It never demotes anything. For KEV items, security beats convenience.
- **No fix means Tier 3, stated plainly,** with mitigate / isolate / watch guidance. If the item is also in KEV, it is flagged CONFIRMED EXPLOITED at the top of Watching.
- **Missing CVSS shows as "CVSS pending".** It is never guessed. When an advisory publishes a CVSS v3 vector, PatchQ computes the score from that vector.
- **Honest limitation:** scanners match package + version. They don't know whether your code actually calls the vulnerable function. Use `patchq ignore … --reason` when you know it doesn't.

### `patchqueue.yml`: mark what's internet-facing (optional)

```yaml
systems:
  proxy:            # compose service name, container name, image name, or folder path
    exposed: true
    critical: true  # tie-breaker inside a tier
  web: {exposed: true}
  dns: {exposed: false}   # LAN-only: also silences the "publishes ports" hint
```

You can put it in two places:
- **Next to a compose file or project** in a scanned folder. It applies to that folder.
- **`~/.patchqueue/patchqueue.yml`**. It applies everywhere, including running containers scanned with `--docker`. Use this one if you only scan containers.

## What it reads

| Input | Files |
|---|---|
| npm | `package-lock.json` / `npm-shrinkwrap.json` (v1–v3), `package.json` (approximate, flagged) |
| Python | `requirements*.txt` (incl. `-r` includes, markers, hashes), `poetry.lock`, `Pipfile.lock` |
| Docker / homelab | `docker-compose*.yml`, `compose*.yml`, `Dockerfile` FROM lines |
| Scanner reports | Trivy JSON, Grype JSON, OSV-Scanner JSON (auto-picked up when named `*trivy*.json`, `*grype*.json`, `*osv-scanner*.json`, or via `--import`) |

**Docker images:** PatchQ doesn't re-implement image scanning. `patchq scan --docker` (or saying yes in `init`) runs Trivy on the containers that are running right now. For images that are in a compose file but not running, PatchQ prints the exact `trivy image …` command to run; drop the JSON next to your compose file and re-scan.

**Unsupported files are reported, not skipped.** This covers `yarn.lock`, `pnpm-lock.yaml`, `uv.lock`, Go, Rust, Ruby, PHP and Maven files. Each comes with a workaround, usually osv-scanner JSON plus `--import`.

## What leaves your machine

Lockfiles are parsed **locally**. No source code or files are uploaded, and nothing is sent anywhere else. The only network requests are:

- **OSV.dev**: package names, versions and ecosystem (public data)
- **FIRST EPSS** and **NVD**: CVE IDs
- **CISA KEV**: one download per day
- **Trivy** (only with `--docker`): downloads its vulnerability database and may contact the image's registry. That's Trivy's own traffic.

There is no telemetry or tracking, and no account is needed.

Everything is cached in `~/.patchqueue/cache/`: KEV and EPSS daily, OSV 24h, NVD 7 days. If a feed is down, PatchQ uses the cache and shows `Data as of …` with a ⚠. If there's no cache, it says loudly what was **not** checked. It never fails silently and never invents a score. Use `patchq scan --offline` on air-gapped boxes. NVD is rate-limited, so PatchQ caps lookups per run; set a free `NVD_API_KEY` to raise the cap, or pass `--no-nvd`.

## Dashboard

`patchq serve` (or the background service from `init`) shows the same queue through the same ranking code. You can:

- scan now
- mark items patched, deferred or not affected, and reopen them
- change the scan schedule

Security:

- **Local only.** It binds to 127.0.0.1 and rejects foreign Host headers (DNS rebinding).
- **Protected actions.** Every action needs a per-session form token and a same-origin request, so another website can't drive it.
- **Locked-down page.** No JavaScript, strict security headers, and everything is HTML-escaped.
- **Folders stay out of the browser.** Which folders get scanned can only be changed with `patchq init` in a terminal.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Dashboard at http://127.0.0.1:8765 won't load from another computer | It only listens on the machine running PatchQ. Keep `ssh -N -L 8765:127.0.0.1:8765 you@host` open in a terminal while you browse. On that machine, `patchq service status` should say the dashboard is `active`. |
| Dashboard service not active | `journalctl --user -u patchq-serve -n 30` shows why. To run it once in the foreground: `patchq serve`. |
| "That page was out of date" in the dashboard | The dashboard restarted. Reload the page and click again; nothing was changed. |
| `--docker: no permission to talk to docker` | `sudo usermod -aG docker $USER`, then log out and back in. (Being in the docker group is effectively root.) |
| "Trivy isn't installed" | `sudo apt install trivy` (Kali), or see trivy.dev. |
| `NVD ⚠` / HTTP 503 in "Data as of" | NVD is often slow or down. PatchQ keeps going with cached data; CVSS shows "pending" until NVD answers. Set a free `NVD_API_KEY` for higher limits. |
| "image(s) found but NOT checked" | That image is in a compose file but not running. Run the `trivy image …` command shown, or start the container and use `--docker`. |
| Scheduled scans don't run while you're logged out | Run once: `sudo loginctl enable-linger $USER`. |

## Roadmap

PyPI release (`pip install patchq`), GitHub Releases binaries, Homebrew; notifications (ntfy / Discord / email) when something lands in Patch Today; Go / Rust / Ruby / PHP lockfiles; CycloneDX / SPDX SBOM import; SARIF import; a GitHub Action that fails only on Tier 0; an auto-PR that opens (never merges) upgrades.

Never planned: network scanning, auto-patching, auto-merging, Windows OS patching, enterprise dashboards, an AI chatbot.

## Disclaimer

PatchQ is a triage aid, not a guarantee. It ranks what it can see from public feeds. It cannot see private advisories, zero-days, or code you didn't tell it about.

MIT licensed. See [LICENSE](LICENSE) and [CONTRIBUTING.md](CONTRIBUTING.md).
