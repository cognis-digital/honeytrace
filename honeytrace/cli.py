"""HONEYTRACE command-line interface."""

from __future__ import annotations

import argparse
import json
import sys

from honeytrace import TOOL_NAME, TOOL_VERSION
from honeytrace.core import (
    SERVICE_PROFILES,
    simulate_session,
    parse_events,
    analyze_events,
)


def _print_json(obj):
    print(json.dumps(obj, indent=2, sort_keys=False))


def _emit(rows, headers, fmt, json_obj):
    if fmt == "json":
        _print_json(json_obj)
        return
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))
    line = "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    print(line)
    print("  ".join("-" * widths[i] for i in range(len(headers))))
    for row in rows:
        print("  ".join(str(c).ljust(widths[i]) for i, c in enumerate(row)))


def _cmd_services(args):
    rows = []
    payload = []
    for name in sorted(SERVICE_PROFILES):
        svc = SERVICE_PROFILES[name]
        rows.append([svc.name, svc.port, svc.banner])
        payload.append({"name": svc.name, "port": svc.port,
                        "banner": svc.banner, "prompt": svc.prompt})
    _emit(rows, ["service", "port", "banner"], args.format,
          {"services": payload})
    return 0


def _cmd_simulate(args):
    if args.accept_after < 1:
        print(
            f"error: --accept-after must be >= 1, got {args.accept_after}",
            file=sys.stderr,
        )
        return 1
    commands = []
    if args.script:
        try:
            with open(args.script, "r", encoding="utf-8") as fh:
                commands = [ln.rstrip("\n") for ln in fh]
        except OSError as exc:
            print(f"error: cannot read script file {args.script!r}: {exc}",
                  file=sys.stderr)
            return 1
    elif args.command:
        commands = list(args.command)

    report = simulate_session(
        args.service,
        commands,
        src_ip=args.src_ip,
        accept_after=args.accept_after,
        seed=args.seed,
    )

    if args.format == "json":
        _print_json(report.to_dict())
    else:
        rows = [
            ["session", report.session_id],
            ["src_ip", report.src_ip],
            ["service", report.service],
            ["auth_attempts", report.auth_attempts],
            ["commands", report.command_count],
            ["tactics", ", ".join(report.tactics) or "-"],
            ["threat_score", report.threat_score],
            ["verdict", report.verdict.upper()],
        ]
        _emit(rows, ["field", "value"], "table", {})
    # Non-zero exit when the decoy caught a serious actor (useful for alerting).
    return 2 if report.verdict in ("critical", "high") else 0


def _cmd_analyze(args):
    try:
        if args.events == "-":
            lines = sys.stdin.read().splitlines()
        else:
            with open(args.events, "r", encoding="utf-8") as fh:
                lines = fh.read().splitlines()
        events = parse_events(lines)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    reports = analyze_events(events)
    rows = []
    payload = []
    for r in reports:
        rows.append([r.src_ip, r.service, r.auth_attempts, r.command_count,
                     ", ".join(r.tactics) or "-", r.threat_score,
                     r.verdict.upper()])
        payload.append(r.to_dict())
    _emit(rows,
          ["src_ip", "service", "auth", "cmds", "tactics", "score", "verdict"],
          args.format, {"event_count": len(events), "sources": payload})

    worst = reports[0].verdict if reports else "benign"
    return 2 if worst in ("critical", "high") else 0


def build_parser():
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="HONEYTRACE — active-decoy network lure system "
                    "(SSH/RDP/SMB/HTTP honeypots).")
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    p.add_argument("--format", choices=["table", "json"], default="table",
                   help="output format (default: table)")

    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("services", help="list configured decoy services")
    s.set_defaults(func=_cmd_services)

    sim = sub.add_parser("simulate",
                         help="emulate a decoy session + score the attacker")
    sim.add_argument("service", choices=sorted(SERVICE_PROFILES))
    sim.add_argument("-c", "--command", action="append",
                     help="scripted attacker input (repeatable)")
    sim.add_argument("--script", help="file of attacker inputs, one per line")
    sim.add_argument("--src-ip", default=None, help="override source IP")
    sim.add_argument("--accept-after", type=int, default=2,
                     help="auth attempt at which decoy accepts login")
    sim.add_argument("--seed", default="honeytrace",
                     help="determinism seed for synthetic IP/session-id")
    sim.set_defaults(func=_cmd_simulate)

    an = sub.add_parser("analyze",
                        help="ingest JSONL decoy events -> per-IP threat intel")
    an.add_argument("events", help="path to JSONL event log, or '-' for stdin")
    an.set_defaults(func=_cmd_analyze)

    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
