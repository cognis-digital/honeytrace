# Scenario: Coordinated SSH brute + web admin scan

Two attacker IPs hitting two different services in the same minute.

## Expected findings

- HT-HIT-001 × 2 (SSH)
- HT-HIT-002 × 3 (web admin paths)

## Why this matters

Use this for IP-block lists + correlate with your real assets to find overlap.
