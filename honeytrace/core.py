"""HONEYTRACE core engine.

Real (non-stub) decoy session logic:

- ``SERVICE_PROFILES`` define banner/prompt behavior for SSH/RDP/SMB/HTTP decoys.
- ``simulate_session`` deterministically generates a decoy interaction from a
  seed + scripted attacker inputs (no real sockets — replay/emulation).
- ``classify_command`` maps attacker input to a TTP tactic + base severity.
- ``score_session`` aggregates events into a 0-100 threat score + verdict.
- ``parse_events`` / ``analyze_events`` ingest JSONL event logs and roll them
  up into per-source-IP intelligence.

All deterministic and offline. No third-party deps.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone


# --------------------------------------------------------------------------
# Service profiles: how each decoy presents itself to an attacker.
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class DecoyService:
    name: str
    port: int
    banner: str
    prompt: str


SERVICE_PROFILES = {
    "ssh": DecoyService(
        name="ssh",
        port=22,
        banner="SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
        prompt="root@web-prod-01:~# ",
    ),
    "rdp": DecoyService(
        name="rdp",
        port=3389,
        banner="RDP Protocol 8.1 (build 9600) — WIN-FILESRV01",
        prompt="C:\\Users\\Administrator> ",
    ),
    "smb": DecoyService(
        name="smb",
        port=445,
        banner="Windows Server 2016 Standard 14393 (SAMBA 4.7.6)",
        prompt="smb: \\> ",
    ),
    "http": DecoyService(
        name="http",
        port=80,
        banner="Apache/2.4.41 (Ubuntu) — admin-portal",
        prompt="HTTP/1.1 ",
    ),
}


# --------------------------------------------------------------------------
# Threat-intel classification rules. Each rule: (regex, tactic, severity, tag)
# Severity is a base 0-10 contribution; MITRE-style tactic for triage.
# --------------------------------------------------------------------------

_RULES = [
    (r"\b(wget|curl)\b.*\bhttp", "ingress-tool-transfer", 8, "malware-download"),
    (r"\b(nc|ncat|netcat)\b.*-e", "command-and-control", 9, "reverse-shell"),
    (r"/bin/(ba)?sh\s+-i", "command-and-control", 9, "reverse-shell"),
    (r"\bchmod\s+\+?x", "execution", 6, "make-executable"),
    (r"\b(rm\s+-rf\s+/|mkfs|dd\s+if=)", "impact", 9, "destructive"),
    (r"\bcat\b.*/etc/(passwd|shadow)", "credential-access", 7, "cred-dump"),
    (r"\b(history\s+-c|unset\s+HISTFILE|rm\s+.*\.bash_history)", "defense-evasion", 7, "anti-forensics"),
    (r"\b(uname|whoami|id|hostname|lscpu)\b", "discovery", 3, "recon"),
    (r"\b(ps\s+aux|netstat|ss\s+-|ifconfig|ip\s+a)\b", "discovery", 3, "recon"),
    (r"\b(crontab|systemctl\s+enable|\.ssh/authorized_keys)\b", "persistence", 8, "persistence"),
    (r"\b(useradd|adduser|net\s+user\s+.*\s*/add)\b", "persistence", 8, "add-account"),
    (r"(\.\./){2,}|/etc/passwd|cmd\.exe|union\s+select|<script>", "initial-access", 7, "web-exploit"),
    (r"\b(masscan|nmap|hydra|sqlmap)\b", "reconnaissance", 5, "scanner-tool"),
]

_COMPILED = [(re.compile(p, re.IGNORECASE), tac, sev, tag) for p, tac, sev, tag in _RULES]


def classify_command(text: str):
    """Classify a single attacker input line.

    Returns dict with tactic, severity (0-10), tag. Unknown -> low-severity
    'uncategorized' so noise is still recorded but down-weighted.
    """
    for rx, tactic, sev, tag in _COMPILED:
        if rx.search(text):
            return {"tactic": tactic, "severity": sev, "tag": tag}
    return {"tactic": "uncategorized", "severity": 1, "tag": "noise"}


# --------------------------------------------------------------------------
# Event + report dataclasses
# --------------------------------------------------------------------------

@dataclass
class Event:
    ts: str
    src_ip: str
    service: str
    session_id: str
    kind: str          # connect | auth | command | response | disconnect
    data: str
    tactic: str = "n/a"
    severity: int = 0
    tag: str = "n/a"

    def to_dict(self):
        return asdict(self)


@dataclass
class SessionReport:
    session_id: str
    src_ip: str
    service: str
    started: str
    ended: str
    auth_attempts: int
    accepted_login: bool
    command_count: int
    tactics: list = field(default_factory=list)
    threat_score: int = 0
    verdict: str = "benign"
    events: list = field(default_factory=list)

    def to_dict(self):
        d = asdict(self)
        d["events"] = [e.to_dict() if isinstance(e, Event) else e for e in self.events]
        return d


# --------------------------------------------------------------------------
# Deterministic session simulation (replay/emulation — no real sockets)
# --------------------------------------------------------------------------

def _seeded_ip(seed: str) -> str:
    h = hashlib.sha256(seed.encode()).digest()
    # Avoid reserved/private-looking first octet collisions; keep deterministic.
    return f"{45 + h[0] % 180}.{h[1]}.{h[2]}.{1 + h[3] % 254}"


def _clock(start: datetime):
    t = {"now": start}

    def tick(seconds=1):
        t["now"] = t["now"] + timedelta(seconds=seconds)
        return t["now"].isoformat()

    return tick


def simulate_session(service_name, commands, src_ip=None, accept_after=2,
                     seed="honeytrace", start_ts=None):
    """Emulate a decoy session and return a SessionReport.

    ``commands`` is the scripted list of attacker inputs. ``accept_after``
    auth attempts the decoy "accepts" the login (luring the attacker in,
    cowrie-style) and begins recording command activity.
    """
    if service_name not in SERVICE_PROFILES:
        raise ValueError(f"unknown service '{service_name}' "
                         f"(have: {', '.join(sorted(SERVICE_PROFILES))})")
    svc = SERVICE_PROFILES[service_name]
    src_ip = src_ip or _seeded_ip(f"{seed}:{service_name}")
    session_id = hashlib.sha256(
        f"{seed}:{service_name}:{src_ip}".encode()).hexdigest()[:12]

    start = start_ts or datetime(2026, 6, 8, 12, 0, 0, tzinfo=timezone.utc)
    tick = _clock(start)
    events = []

    events.append(Event(start.isoformat(), src_ip, service_name, session_id,
                        "connect", f"banner={svc.banner}"))

    auth_attempts = max(1, int(accept_after))
    creds = ["admin:admin", "root:123456", "root:toor", "administrator:Password1"]
    for i in range(auth_attempts):
        ok = (i + 1) >= accept_after
        cred = creds[i % len(creds)]
        events.append(Event(tick(1), src_ip, service_name, session_id, "auth",
                            f"attempt={i + 1} cred={cred} accepted={ok}",
                            tactic="credential-access",
                            severity=4 if not ok else 6,
                            tag="brute-force"))
    accepted = True  # decoy always eventually accepts to capture TTPs

    cmd_count = 0
    tactics = []
    for cmd in commands:
        cmd = str(cmd).strip()
        if not cmd:
            continue
        cls = classify_command(cmd)
        cmd_count += 1
        tactics.append(cls["tactic"])
        events.append(Event(tick(2), src_ip, service_name, session_id,
                            "command", cmd, cls["tactic"], cls["severity"],
                            cls["tag"]))

    events.append(Event(tick(1), src_ip, service_name, session_id,
                        "disconnect", "session closed"))

    report = SessionReport(
        session_id=session_id,
        src_ip=src_ip,
        service=service_name,
        started=events[0].ts,
        ended=events[-1].ts,
        auth_attempts=auth_attempts,
        accepted_login=accepted,
        command_count=cmd_count,
        tactics=sorted(set(tactics)),
        events=events,
    )
    score_session(report)
    return report


# --------------------------------------------------------------------------
# Scoring
# --------------------------------------------------------------------------

def score_session(report: SessionReport) -> SessionReport:
    """Compute 0-100 threat score + verdict, mutating + returning the report."""
    sev_total = sum(e.severity for e in report.events if isinstance(e, Event))
    # Distinct high-value tactics widen the kill-chain footprint.
    distinct = set(report.tactics)
    high_value = distinct & {
        "command-and-control", "impact", "persistence",
        "credential-access", "ingress-tool-transfer",
    }
    # Brute-force volume signal.
    brute = max(0, report.auth_attempts - 1)

    raw = sev_total + 8 * len(high_value) + 2 * brute
    score = min(100, raw)
    report.threat_score = score

    if score >= 70 or {"impact", "command-and-control"} & distinct:
        report.verdict = "critical"
    elif score >= 40:
        report.verdict = "high"
    elif score >= 15:
        report.verdict = "medium"
    elif score > 0:
        report.verdict = "low"
    else:
        report.verdict = "benign"
    return report


# --------------------------------------------------------------------------
# Event-log ingestion + intelligence rollup
# --------------------------------------------------------------------------

def parse_events(lines):
    """Parse JSONL decoy event lines into Event objects.

    Tolerant: blank lines skipped; malformed JSON raises ValueError with the
    offending line number so a caller can exit non-zero.
    """
    events = []
    for n, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"malformed JSON on line {n}: {exc}") from exc
        if not isinstance(obj, dict):
            raise ValueError(f"line {n}: expected JSON object")
        ev = Event(
            ts=str(obj.get("ts", "")),
            src_ip=str(obj.get("src_ip", "0.0.0.0")),
            service=str(obj.get("service", "unknown")),
            session_id=str(obj.get("session_id", "")),
            kind=str(obj.get("kind", "command")),
            data=str(obj.get("data", "")),
        )
        if ev.kind == "command" and ev.data:
            cls = classify_command(ev.data)
            ev.tactic, ev.severity, ev.tag = cls["tactic"], cls["severity"], cls["tag"]
        else:
            ev.tactic = str(obj.get("tactic", ev.tactic))
            ev.severity = int(obj.get("severity", ev.severity) or 0)
            ev.tag = str(obj.get("tag", ev.tag))
        events.append(ev)
    return events


def analyze_events(events):
    """Roll Event objects into per-source-IP threat intelligence."""
    by_ip = {}
    for ev in events:
        agg = by_ip.setdefault(ev.src_ip, {
            "src_ip": ev.src_ip,
            "services": set(),
            "sessions": set(),
            "auth_attempts": 0,
            "commands": 0,
            "tactics": {},
            "sev_total": 0,
        })
        agg["services"].add(ev.service)
        if ev.session_id:
            agg["sessions"].add(ev.session_id)
        if ev.kind == "auth":
            agg["auth_attempts"] += 1
        if ev.kind == "command":
            agg["commands"] += 1
        if ev.tactic and ev.tactic not in ("n/a", "uncategorized"):
            agg["tactics"][ev.tactic] = agg["tactics"].get(ev.tactic, 0) + 1
        agg["sev_total"] += int(ev.severity or 0)

    results = []
    for ip, agg in by_ip.items():
        rep = SessionReport(
            session_id=",".join(sorted(agg["sessions"])) or "-",
            src_ip=ip,
            service=",".join(sorted(agg["services"])),
            started="", ended="",
            auth_attempts=agg["auth_attempts"],
            accepted_login=agg["commands"] > 0,
            command_count=agg["commands"],
            tactics=sorted(agg["tactics"]),
        )
        # Score directly from aggregates for fidelity.
        distinct = set(agg["tactics"])
        high_value = distinct & {
            "command-and-control", "impact", "persistence",
            "credential-access", "ingress-tool-transfer",
        }
        brute = max(0, agg["auth_attempts"] - 1)
        raw = agg["sev_total"] + 8 * len(high_value) + 2 * brute
        rep.threat_score = min(100, raw)
        if rep.threat_score >= 70 or {"impact", "command-and-control"} & distinct:
            rep.verdict = "critical"
        elif rep.threat_score >= 40:
            rep.verdict = "high"
        elif rep.threat_score >= 15:
            rep.verdict = "medium"
        elif rep.threat_score > 0:
            rep.verdict = "low"
        else:
            rep.verdict = "benign"
        rep.events = []
        results.append(rep)

    results.sort(key=lambda r: r.threat_score, reverse=True)
    return results
