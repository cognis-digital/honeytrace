# HONEYTRACE — Active-decoy network lure system — SSH, RDP, SMB, web honeypots

> Part of the **[Cognis Neural Suite](https://github.com/cognis-digital)** by [Cognis Digital](https://cognis.digital)
> MIT License · domain: `blue-team`

[![PyPI](https://img.shields.io/pypi/v/cognis-honeytrace.svg)](https://pypi.org/project/cognis-honeytrace/)
[![CI](https://github.com/cognis-digital/honeytrace/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/honeytrace/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Active-decoy network lure system — SSH, RDP, SMB, web honeypots.

## Install

```bash
pip install cognis-honeytrace
```

For local development from this repo:

```bash
pip install -e .
```

## Quick start

```bash
honeytrace --version
honeytrace scan demos/                          # run against bundled demo
honeytrace scan demos/ --format sarif --out r.sarif --fail-on high
honeytrace mcp                                   # start as MCP server (Cognis.Studio / Claude Desktop / Cursor)
```

## Built-in demo scenarios

Every scenario folder includes a `SCENARIO.md` describing what it represents and what findings to expect.

- `demos/01-active-scanning/` — see [`SCENARIO.md`](demos/01-active-scanning/SCENARIO.md)
- `demos/02-quiet-period/` — see [`SCENARIO.md`](demos/02-quiet-period/SCENARIO.md)
- `demos/03-targeted-recon/` — see [`SCENARIO.md`](demos/03-targeted-recon/SCENARIO.md)

## How it fits the Cognis Neural Suite

This tool is one of 52 in the [Cognis Neural Suite](https://github.com/cognis-digital). The full suite + launcher lives at:

- Suite landing: https://cognis.digital
- All 52 repos: https://github.com/cognis-digital
- Cognis.Studio (Enterprise AI Workforce, MCP host): https://cognis.studio

Every Suite tool ships an MCP server, so Cognis.Studio agents can call them as scoped capabilities.

## License

MIT. See [LICENSE](LICENSE).

## About

**[Cognis Digital](https://cognis.digital)** — Wyoming, USA · *Making Tomorrow Better Today: Advanced Cybersecurity, AI Innovation, and Blockchain Expertise.*
