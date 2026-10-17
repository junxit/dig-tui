# CLAUDE.md

## Dependency pinning

Pin everything this project builds with or depends on to an exact version, so no install,
build, or CI run downloads a release that has not been tested here. A version range is allowed
only where we know for sure it cannot break us, with a comment saying why.

| What | Where | Pinned as |
| :--- | :--- | :--- |
| Runtime and dev dependencies | `pyproject.toml` | `name==X.Y.Z` |
| Full dependency tree | `uv.lock` | committed; CI installs with `uv sync --locked` |
| Build backend | `pyproject.toml` `[build-system]` | `hatchling==X.Y.Z` |
| GitHub Actions | `.github/workflows/` | full commit SHA plus a `# vX.Y.Z` comment |
| uv in CI | `setup-uv` `version:` input | `X.Y.Z` |
| CI runner | `runs-on:` | a versioned image such as `ubuntu-24.04`, never `ubuntu-latest` |

- Python 3.9 is still supported, but the latest pytest, pytest-asyncio, and hatchling have
  dropped it. Pin each side with an environment marker (`pytest==9.1.1; python_version >= '3.10'`
  and `pytest==8.4.2; python_version < '3.10'`) instead of loosening the pin.
- Declare and pin anything the code imports directly, even when another dependency already
  pulls it in: `rich` comes with `textual`, but `app.py` imports it and the S2 protections
  depend on its markup handling.
- Upgrades are deliberate: change the pin, run `uv lock`, then run `ruff check`,
  `ruff format --check`, and `pytest` on every Python version in the CI matrix before committing.
