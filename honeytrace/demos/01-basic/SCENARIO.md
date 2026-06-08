# Demo 01 — Basic: catching an SSH intruder

HONEYTRACE stands up decoy SSH/RDP/SMB/HTTP services, lets attackers "in",
and records every move (cowrie-style) so the blue team gets attacker TTPs
without exposing real assets.

## Service inventory

```sh
python -m honeytrace services
```

## Emulate an SSH attacker dropping a reverse shell

The decoy accepts the login on the 2nd brute-force attempt, then replays the
scripted attacker session in `ssh_session.txt`, classifies each command into a
MITRE-style tactic, and scores the session.

```sh
python -m honeytrace --format json simulate ssh --script honeytrace/demos/01-basic/ssh_session.txt
```

Expected: a `critical` verdict (the reverse shell maps to command-and-control),
and the process exits with code **2** so it can trip an alerting pipeline.

## Roll up captured events into per-IP threat intel

`events.jsonl` is a raw decoy event log (the format HONEYTRACE itself emits).
`analyze` groups by source IP, sums severity, ranks attackers, and assigns a
verdict.

```sh
python -m honeytrace analyze honeytrace/demos/01-basic/events.jsonl
python -m honeytrace --format json analyze honeytrace/demos/01-basic/events.jsonl
```

The noisiest / most-dangerous source IP sorts to the top; exit code is **2** if
any source reaches `high`/`critical`.
