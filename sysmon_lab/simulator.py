"""Inert Sysmon-like event generation for local validation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

SCENARIOS: dict[str, list[dict[str, Any]]] = {
    "encoded-powershell": [{
        "event_id": 1, "image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "command_line": "powershell.exe -NoProfile -EncodedCommand <simulated>",
        "parent_image": r"C:\Windows\explorer.exe", "user": "LAB\\analyst",
    }],
    "office-child-shell": [{
        "event_id": 1, "image": r"C:\Windows\System32\cmd.exe",
        "command_line": "cmd.exe /c <simulated-document-action>",
        "parent_image": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
        "user": "LAB\\analyst",
    }],
    "runkey-persistence": [{
        "event_id": 13, "image": r"C:\Windows\System32\reg.exe",
        "target_object": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\LabUpdater",
        "details": r"C:\Users\analyst\AppData\Roaming\Lab\updater.exe",
        "user": "LAB\\analyst",
    }],
    "remote-admin-network": [{
        "event_id": 3, "image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "destination_ip": "203.0.113.25", "destination_port": 5985,
        "protocol": "tcp", "user": "LAB\\analyst",
    }],
}


def simulate(scenario: str, output: Path) -> int:
    """Write inert normalized telemetry; no command is ever executed."""
    names = list(SCENARIOS) if scenario == "all" else [scenario]
    unknown = set(names).difference(SCENARIOS)
    if unknown:
        raise ValueError(f"Unknown scenario: {', '.join(sorted(unknown))}")
    output.parent.mkdir(parents=True, exist_ok=True)
    events = []
    for name in names:
        for event in SCENARIOS[name]:
            events.append(
                {"source": "sysmon-lab-simulator", "simulation": True, "scenario": name, **event}
            )
    contents = "\n".join(json.dumps(event, sort_keys=True) for event in events) + "\n"
    output.write_text(contents, encoding="utf-8")
    return len(events)

