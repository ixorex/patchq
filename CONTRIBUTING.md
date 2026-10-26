# Contributing to PatchQ

PatchQ is maintained solo in a few hours a week. Contributions that keep it small, boring and correct are the easiest to merge.

## Run the tests

```bash
python3 -m unittest discover -s tests -t .
```

Standard library only: no pytest, no network. Tested on Python 3.9, 3.10 and 3.13. Network calls are blocked in tests (`tests/helpers.py`), and feed data comes from `tests/fixtures/feeds/`.

## How the feeds update

Nothing is curated by hand. Every `patchq scan` refreshes what's stale:

| Feed | Refresh | Code |
|---|---|---|
| CISA KEV | once per UTC day, whole catalog | `patchqueue/sources/kev.py` |
| FIRST EPSS | once per UTC day per CVE, batched 100 per request | `patchqueue/sources/epss.py` |
| OSV.dev | 24h per package@version (querybatch) and per advisory | `patchqueue/sources/osv.py` |
| NVD | 7 days per CVE, capped per run (rate limits) | `patchqueue/sources/nvd.py` |

If a feed is down, the stale cache is used and the `Data as of` line says so. **A wrong fixed version is almost always an upstream data issue.** Report it to OSV / GitHub Advisories, not as a code change here. If PatchQ misread correct data, open a "Wrong answer" issue.

## Add a parser (one small file + tests)

1. Add `patchqueue/parsers/<name>.py` with `parse(path) -> ParseResult` returning `{name, version, ecosystem, direct, dev}` dicts. Put anything you couldn't read into `ParseResult.warnings`. Never skip silently.
2. Register it in `PARSERS` (`patchqueue/parsers/__init__.py`) and in `discovery.classify()`.
3. If it's a new ecosystem, add it to `osv.SUPPORTED`, check `version.compare()` handles its version scheme (add tests to `tests/test_version.py`), and add an upgrade command in `fixcmd.py` behind a strict name regex.
4. Add a real (trimmed) sample to `tests/fixtures/parsers/` and a test in `tests/test_parsers.py`.

## Ground rules

- **Ranking stays auditable.** `rank.py` is pure. Any change needs a test that shows why item A beats item B.
- **Never string-compare versions.** Use `version.compare(a, b, ecosystem)`.
- **Untrusted input everywhere.** Lockfiles, reports and feed text are attacker-controllable. Shell-quote and validate anything that becomes a command, HTML-escape anything that reaches the dashboard, and strip control characters before printing to the terminal.
- **No new dependencies** without a one-sentence justification. No telemetry, ever.
- If a feature needs more than ~2 hours/week of upkeep, it doesn't ship.

## Release checklist

1. All tests pass on 3.9 and the latest Python.
2. Bump `version` in `pyproject.toml` and `patchqueue/__init__.py`.
3. `pipx install git+https://github.com/ixorex/patchq.git@<tag>` works on a clean machine.
