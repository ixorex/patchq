# PatchQ

**One ranked patch queue for your homelab / dev stack.** Point it at a folder or a git repo. It finds your lockfiles, compose files and scanner reports by itself, and gives back a single queue: **Patch Today / This Week / This Sprint / Watching**.

Each item comes with:
- the fixed version, or a plain "no fix yet"
- the exact upgrade command
- a one-line reason for its rank
- a breaks-risk flag (patch / minor / major bump)

PatchQ makes a decision. It does not send alerts or dump 200 unordered findings on you.

Free, MIT-licensed, no account, no telemetry, standard-library Python only.


## Install

```bash
pipx install git+https://github.com/ixorex/patchq.git     # recommended
patchq scan .
```

Fallbacks:

```bash
pip install git+https://github.com/ixorex/patchq.git

git clone https://github.com/ixorex/patchq.git
cd patchq
python3 -m patchqueue scan .
```

Needs Python 3.9+ and `git` (only for scanning git URLs or `--pull`). Built for Linux; macOS should work but is untested.

## Use it

```bash
patchq scan ~/homelab                       # walk a folder, build the queue
patchq scan https://github.com/me/app.git   # shallow-clone (https/ssh), then scan
patchq scan . --pull                        # git pull --ff-only first
patchq scan . --import trivy-nginx.json     # include a Trivy / Grype / OSV-Scanner report
patchq queue                                # show the queue again (no network)
patchq queue --all                          # expand Watching + decision history
patchq done   CVE-2021-23337
patchq defer  CVE-2014-6271 --reason "box retired next sprint" --recheck 2026-11-15
patchq ignore CVE-2020-8203 --reason "zipObjectDeep never called" [--recheck 2027-01-01]
patchq serve                                # dashboard at http://127.0.0.1:8765 (read-only)
```

Decisions are stored in `~/.patchqueue/queue.json` with their full history. Six months from now, `patchq queue --all` still tells you why something was ignored. Re-running `scan` keeps every decision. If you mark something done but it is still in your lockfile, PatchQ says so instead of hiding it.

## Example output

This is real output from `tests/fixtures/sample-homelab`. It ran offline against the test fixture feeds, so the EPSS/KEV numbers are illustrative.

```
PatchQ 0.1.0 — scan for: homelab (scanned 2026-10-26 17:53)
Data as of (UTC): OSV 2026-10-26 17:53 (cache) · KEV 2026-10-26 17:53 (cache) · EPSS 2026-10-26 17:53 (cache) · NVD —

Heads-up (5):
  • old-frontend/yarn.lock: Yarn lockfiles aren't parsed in v1 — run `osv-scanner --format json -L yarn.lock > osv-scanner.json` and PatchQ will import it
  • 1 image(s) found but NOT checked — PatchQ needs a Trivy/Grype report for image contents. Run `trivy image --format json -o trivy-nginx-1.25-alpine.json nginx:1.25-alpine` in this folder; PatchQ picks up trivy*/grype*.json automatically.
  …

PATCH TODAY · 2
  1  CVE-2014-0160  openssl 1.0.1e-2+deb7u4 → 1.0.1e-2+deb7u5   breaks risk: low — patch bump
     where  legacy (trivy-legacy.json → example/legacy-shell:1.0 (debian 7.11))  [exposed, critical]
     why    Tier 0 (Patch Today): in CISA KEV — confirmed exploited (added 2022-05-04, CISA due 2022-05-25); fix available. EPSS 0.974 · CVSS 7.5.
     fix    apt-get update && apt-get install -y --only-upgrade openssl
            add to the image's Dockerfile as a RUN step and rebuild (inside image example/legacy-shell:1.0) — or move to a newer base image tag
  2  CVE-2014-6271  bash 4.2+dfsg-0.1 → 4.2+dfsg-0.1+deb7u1   breaks risk: low — patch bump
     …

THIS WEEK · 4
  3  CVE-2020-14343  PyYAML 5.3 → 5.4   breaks risk: medium — minor bump
     where  api (api/requirements.txt)
     why    Tier 1 (This Week): EPSS 0.12 ≥ 0.10 (≈12% chance of exploitation in the next 30 days); fix available. EPSS 0.120 · CVSS 9.8.
     fix    cd ~/homelab/api && pip install PyYAML==5.4
            then change the pin in api/requirements.txt to PyYAML==5.4
  4  CVE-2021-44906  minimist 1.2.5 → 1.2.6   breaks risk: low — patch bump
     where  web (web/package-lock.json) [transitive]  [exposed]
     why    Tier 1 (This Week): CVSS 9.8 ≥ 7.0; fix available; +1 tier: web marked exposed in patchqueue.yml. EPSS 0.008 · CVSS 9.8.
     fix    cd ~/homelab/web && npm update minimist
            transitive dependency: if the lockfile still shows < 1.2.6, add "overrides": {"minimist": "1.2.6"} to package.json and run npm install
  …

WATCHING · 2  (collapsed — `patchq queue --all` for full detail)
 10  CVE-2024-22195  jinja2 2.10 → 3.1.3  ·  recheck: next scan
 11  CVE-2011-3374  apt 0.9.7.9+deb7u7 → no fix yet  ·  recheck: next scan — no fix yet

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

### `patchqueue.yml` (optional, in the scanned folder)

```yaml
systems:
  proxy:            # compose service name, image name, or folder path
    exposed: true
    critical: true  # tie-breaker inside a tier
  web: {exposed: true}
```

## What it reads

| Input | Files |
|---|---|
| npm | `package-lock.json` / `npm-shrinkwrap.json` (v1–v3), `package.json` (approximate, flagged) |
| Python | `requirements*.txt` (incl. `-r` includes, markers, hashes), `poetry.lock`, `Pipfile.lock` |
| Docker / homelab | `docker-compose*.yml`, `compose*.yml`, `Dockerfile` FROM lines |
| Scanner reports | Trivy JSON, Grype JSON, OSV-Scanner JSON (auto-picked up when named `*trivy*.json`, `*grype*.json`, `*osv-scanner*.json`, or via `--import`) |

**Docker images:** PatchQ doesn't re-implement image scanning. For every image it finds without a report, it prints the exact `trivy image …` command to run. Drop the JSON next to your compose file and re-scan.

**Unsupported files are reported, not skipped.** This covers `yarn.lock`, `pnpm-lock.yaml`, `uv.lock`, Go, Rust, Ruby, PHP and Maven files. Each comes with a workaround, usually osv-scanner JSON plus `--import`.

## What leaves your machine

Lockfiles are parsed **locally**. No source code or files are uploaded, and nothing is sent anywhere else. The only network requests are:

- **OSV.dev**: package names, versions and ecosystem (public data)
- **FIRST EPSS** and **NVD**: CVE IDs
- **CISA KEV**: one download per day

There is no telemetry or tracking, and no account is needed.

Everything is cached in `~/.patchqueue/cache/`: KEV and EPSS daily, OSV 24h, NVD 7 days. If a feed is down, PatchQ uses the cache and shows `Data as of …` with a ⚠. If there's no cache, it says loudly what was **not** checked. It never fails silently and never invents a score. Use `patchq scan --offline` on air-gapped boxes. NVD is rate-limited, so PatchQ caps lookups per run; set a free `NVD_API_KEY` to raise the cap, or pass `--no-nvd`.

## Dashboard

`patchq serve` serves the same `queue.json` through the same ranking code. It binds to 127.0.0.1 only, rejects foreign Host headers (DNS rebinding), runs no JavaScript, and is read-only. Actions stay in the CLI, so a malicious web page can't change your queue.

## Roadmap (not in v1)

PyPI release (`pip install patchq`), GitHub Releases binaries, Homebrew; Go / Rust / Ruby / PHP lockfiles; CycloneDX / SPDX SBOM import; SARIF import; a GitHub Action that fails only on Tier 0; an auto-PR that opens (never merges) upgrades.

Never planned: network scanning, auto-patching, auto-merging, Windows OS patching, enterprise dashboards, an AI chatbot.

## Support

PatchQ is free forever. Donations keep it going: *add your GitHub Sponsors / Ko-fi link here before publishing.*

## Disclaimer

PatchQ is a triage aid, not a guarantee. It ranks what it can see from public feeds. It cannot see private advisories, zero-days, or code you didn't tell it about.

MIT licensed. See [LICENSE](LICENSE) and [CONTRIBUTING.md](CONTRIBUTING.md).
