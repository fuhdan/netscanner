# Contributing

Two ways to contribute: submit a plugin, or improve the framework itself.

---

## Contributing a plugin

Plugins are developed in **[netscanner-plugins](https://github.com/fuhdan/netscanner-plugins)** —
a separate repo where plugins are reviewed and tested. That repo is the single source of
truth for every plugin, bundled and community alike. When a plugin is merged there, a
pipeline validates it once more and opens a pull request here, which lands by auto-merge
once CI is green and a maintainer approves it.

**Do not open plugin PRs here.** Go to netscanner-plugins instead.

---

## Improving the framework

The framework is `netscanner.py` — TCP connection management, threading, pcap capture,
output formatting, CLI. Protocol-agnostic. Changes here affect every plugin.

1. Fork this repo and create a feature branch off `main`.
2. Write tests first — new code must come with new tests.
3. Run the full suite: `python3 -m pytest tests/ -v`
4. Open a PR against `main`. CI must be green before review.

### Framework changes that plugins depend on

netscanner-plugins validates every plugin against **this repository's `main`**:
its CI clones netscanner, copies the plugin in, and runs the whole suite. A
framework change that plugins will use therefore has to be merged here before a
plugin pull request using it can pass CI there.

Merge the framework change first, then re-run the checks on the plugin side —
GitHub does not notice that another repository moved, so those checks stay red
until someone asks for them again.

### What belongs in the framework vs. a plugin

**Framework** (`netscanner.py`): anything that applies to all protocols.

**Plugin** (`plugins/*.py`): everything protocol-specific. If it only makes sense
for one protocol, it belongs in a plugin.

> **Note:** `plugins/` is managed automatically by the netscanner-plugins sync pipeline.
> Do not edit files in `plugins/` directly in this repo — the sync mirrors that repo, so a
> hand edit here is overwritten, and a plugin removed there is removed here.

---

## CI

Every PR runs `pytest tests/` on Python 3.9, 3.11, and 3.12.
PRs cannot be merged until all checks pass and at least one maintainer has approved.
Main is protected — no direct pushes. Plugin syncs arrive as pull requests and go
through the same gate.

---

## Licence

Apache-2.0 — see [LICENSE](LICENSE). Contributions are accepted under that licence.
