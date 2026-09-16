"""Rule evaluation over normalized Sysmon event records."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

RULES = {
    "SYSMON-POWERSHELL-ENCODED-001": ("T1059.001", "Encoded PowerShell metadata"),
    "SYSMON-OFFICE-CHILD-SHELL-001": ("T1204.002", "Office application spawned a shell"),
    "SYSMON-RUNKEY-PERSISTENCE-001": ("T1547.001", "Run-key persistence metadata"),
    "SYSMON-REMOTE-ADMIN-NETWORK-001": ("T1021", "Outbound remote administration port"),
}


def match(event: dict[str, Any]) -> str | None:
    image = str(event.get("image", "")).lower()
    command = str(event.get("command_line", "")).lower()
    parent = str(event.get("parent_image", "")).lower()
    target = str(event.get("target_object", "")).lower()
    if event.get("event_id") == 1 and "powershell.exe" in image and "-encodedcommand" in command:
        return "SYSMON-POWERSHELL-ENCODED-001"
    if event.get("event_id") == 1 and image.endswith("\\cmd.exe") and "winword.exe" in parent:
        return "SYSMON-OFFICE-CHILD-SHELL-001"
    if event.get("event_id") == 13 and "\\currentversion\\run\\" in target:
        return "SYSMON-RUNKEY-PERSISTENCE-001"
    if event.get("event_id") == 3 and event.get("destination_port") in {5985, 5986, 3389}:
        return "SYSMON-REMOTE-ADMIN-NETWORK-001"
    return None


def detect(events_file: Path, alerts_file: Path) -> list[dict[str, Any]]:
    """Evaluate JSONL telemetry and persist structured alerts."""
    alerts = []
    for line in events_file.read_text(encoding="utf-8").splitlines():
        event = json.loads(line)
        rule_id = match(event)
        if rule_id:
            technique, title = RULES[rule_id]
            alerts.append(
                {
                    "rule_id": rule_id,
                    "technique": technique,
                    "title": title,
                    "scenario": event["scenario"],
                }
            )
    alerts_file.parent.mkdir(parents=True, exist_ok=True)
    alerts_file.write_text(json.dumps(alerts, indent=2) + "\n", encoding="utf-8")
    return alerts

