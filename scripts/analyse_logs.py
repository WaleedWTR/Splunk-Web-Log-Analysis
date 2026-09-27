#!/usr/bin/env python3
"""Small dependency-free analyser for the synthetic Apache-style access log."""

from __future__ import annotations
from collections import Counter
from pathlib import Path
import re

LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^]]+)] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>[^"]+)" '
    r'(?P<status>\d{3}) (?P<bytes>\S+) "[^"]*" "(?P<agent>[^"]*)"'
)

def parse_line(line: str) -> dict[str, str] | None:
    match = LOG_PATTERN.match(line.strip())
    return match.groupdict() if match else None

def analyse(path: Path) -> dict[str, object]:
    records = [r for line in path.read_text().splitlines() if (r := parse_line(line))]
    statuses = Counter(r["status"][0] + "xx" for r in records)
    paths = Counter(r["path"] for r in records)
    sources = Counter(r["ip"] for r in records)
    suspicious = [
        r for r in records
        if any(token in r["agent"].lower() for token in ("sqlmap", "nikto", "nmap"))
        or r["path"].startswith(("/.env", "/admin", "/wp-admin", "/config", "/backup"))
    ]
    return {
        "events": len(records),
        "status_classes": dict(statuses),
        "top_paths": paths.most_common(5),
        "top_sources": sources.most_common(5),
        "suspicious_events": len(suspicious),
    }

if __name__ == "__main__":
    log_path = Path(__file__).resolve().parents[1] / "data" / "sample_access.log"
    result = analyse(log_path)
    print(f"Events parsed: {result['events']}")
    print(f"Status classes: {result['status_classes']}")
    print(f"Top paths: {result['top_paths']}")
    print(f"Top sources: {result['top_sources']}")
    print(f"Suspicious events: {result['suspicious_events']}")
