#!/usr/bin/env python3
"""Analyze normalized agent tool-call events and emit JSON SOC findings."""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any


SENSITIVE_CATEGORIES = {"write", "shell", "network_egress"}


def analyze(event: dict[str, Any]) -> list[dict[str, Any]]:
    """Return evidence-backed alerts for one normalized tool-call event."""
    findings: list[dict[str, Any]] = []
    base = {
        "event_id": event["event_id"],
        "trace_id": event["trace_id"],
        "agent_id": event["agent_id"],
        "tool_name": event["tool_name"],
    }
    if event["tool_name"] not in event["allowed_tools"]:
        findings.append({
            **base,
            "rule_id": "AGENT-003",
            "title": "Tool invoked outside declared agent scope",
            "severity": "high",
            "evidence": {"tool_name": event["tool_name"], "allowed_tools": event["allowed_tools"]},
            "triage": "Confirm the deployed agent configuration and identify who introduced or authorized this tool.",
        })
    if event["tool_category"] in SENSITIVE_CATEGORIES and event["approval_id"] is None:
        findings.append({
            **base,
            "rule_id": "AGENT-001",
            "title": "Sensitive tool action has no approval reference",
            "severity": "medium",
            "evidence": {"tool_category": event["tool_category"], "approval_id": None},
            "triage": "Check the approval system and agent policy; absence of a reference is not proof that approval was bypassed.",
        })
    untrusted = sorted(label for label in event["source_labels"] if label.startswith("untrusted_"))
    if untrusted and event["tool_category"] in SENSITIVE_CATEGORIES and event["approval_id"] is None:
        findings.append({
            **base,
            "rule_id": "AGENT-002",
            "title": "Untrusted source lineage reaches an unapproved side effect",
            "severity": "high",
            "evidence": {"untrusted_source_labels": untrusted, "tool_category": event["tool_category"], "approval_id": None},
            "triage": "Review the trace from the untrusted source through the tool call and determine whether the action was expected.",
        })
    return findings


def validate(event: Any, line_number: int) -> dict[str, Any]:
    required = {"event_id", "timestamp", "trace_id", "agent_id", "tool_name", "tool_category", "allowed_tools", "source_labels", "approval_id"}
    categories = {"read", "write", "shell", "network_egress", "other"}
    if not isinstance(event, dict):
        raise ValueError(f"line {line_number}: expected a JSON object")
    missing = required - event.keys()
    if missing:
        raise ValueError(f"line {line_number}: missing required fields: {', '.join(sorted(missing))}")
    extra = event.keys() - required
    if extra:
        raise ValueError(f"line {line_number}: unexpected fields: {', '.join(sorted(extra))}")
    for key in ("event_id", "timestamp", "trace_id", "agent_id", "tool_name"):
        if not isinstance(event[key], str) or not event[key]:
            raise ValueError(f"line {line_number}: {key} must be a non-empty string")
    try:
        parsed_timestamp = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"line {line_number}: timestamp must be ISO 8601") from exc
    if parsed_timestamp.tzinfo is None:
        raise ValueError(f"line {line_number}: timestamp must include a timezone")
    if not isinstance(event["tool_category"], str) or event["tool_category"] not in categories:
        raise ValueError(f"line {line_number}: invalid tool_category {event['tool_category']!r}")
    for key in ("allowed_tools", "source_labels"):
        if not isinstance(event[key], list) or not all(isinstance(item, str) for item in event[key]):
            raise ValueError(f"line {line_number}: {key} must be an array of strings")
    if event["approval_id"] is not None and not isinstance(event["approval_id"], str):
        raise ValueError(f"line {line_number}: approval_id must be a string or null")
    return event


def main(argv: list[str] | None = None) -> int:
    argv = argv or sys.argv
    if len(argv) != 2 or argv[1] in {"-h", "--help"}:
        print(f"Usage: {argv[0]} EVENTS.jsonl", file=sys.stderr)
        return 0 if len(argv) == 2 else 2
    path = Path(argv[1])
    findings: list[dict[str, Any]] = []
    try:
        with path.open(encoding="utf-8") as source:
            for line_number, line in enumerate(source, 1):
                if not line.strip():
                    continue
                try:
                    event = validate(json.loads(line), line_number)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"line {line_number}: invalid JSON: {exc.msg}") from exc
                findings.extend(analyze(event))
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps({"finding_count": len(findings), "findings": findings}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
