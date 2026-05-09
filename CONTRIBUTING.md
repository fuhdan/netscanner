# Contributing

Two ways to contribute: submit a plugin, or improve the framework itself.

---

## Contributing a plugin

Plugins are developed in **[netscanner-plugins](https://github.com/fuhdan/netscanner-plugins)** —
a separate repo where plugins are reviewed and tested. When a plugin is merged there,
a pipeline automatically syncs it into this repo.

**Do not open plugin PRs here.** Go to netscanner-plugins instead.

---

## Improving the framework

The framework is `netscanner.py` — TCP connection management, threading, pcap capture,
output formatting, CLI. Protocol-agnostic. Changes here affect every plugin.

1. Fork this repo and create a feature branch off `main`.
2. Write tests first — new code must come with new tests.
3. Run the full suite: `python3 -m pytest tests/ -v`
4. Open a PR against `main`. CI must be green before review.

### What belongs in the framework vs. a plugin

**Framework** (`netscanner.py`): anything that applies to all protocols.

**Plugin** (`plugins/*.py`): everything protocol-specific. If it only makes sense
for one protocol, it belongs in a plugin.

> **Note:** `plugins/` is managed automatically by the netscanner-plugins sync pipeline.
> Do not edit files in `plugins/` directly in this repo.

---

## CI

Every PR runs `pytest tests/` on Python 3.9, 3.11, and 3.12.
PRs cannot be merged until all checks pass and at least one maintainer has approved.
Main is protected — no direct pushes.
