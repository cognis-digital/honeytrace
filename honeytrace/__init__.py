"""HONEYTRACE — active-decoy network lure system.

Stdlib-only honeypot session simulator and event analyzer for SSH, RDP,
SMB, and HTTP decoys. Replays or generates decoy sessions, classifies
attacker behavior, scores threat severity, and emits structured event
logs (in the spirit of cowrie).
"""

from honeytrace.core import (
    DecoyService,
    Event,
    SessionReport,
    SERVICE_PROFILES,
    classify_command,
    score_session,
    simulate_session,
    analyze_events,
    parse_events,
)

TOOL_NAME = "honeytrace"
TOOL_VERSION = "1.0.0"

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "DecoyService",
    "Event",
    "SessionReport",
    "SERVICE_PROFILES",
    "classify_command",
    "score_session",
    "simulate_session",
    "analyze_events",
    "parse_events",
]
