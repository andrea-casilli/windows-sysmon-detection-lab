from pathlib import Path

from sysmon_lab.engine import detect, match
from sysmon_lab.simulator import SCENARIOS, simulate


def test_every_scenario_generates_one_alert(tmp_path: Path) -> None:
    for scenario in SCENARIOS:
        events = tmp_path / f"{scenario}.jsonl"
        alerts = tmp_path / f"{scenario}.json"
        assert simulate(scenario, events) == 1
        assert len(detect(events, alerts)) == 1


def test_benign_event_does_not_alert() -> None:
    event = {
        "event_id": 1,
        "image": r"C:\Windows\notepad.exe",
        "command_line": "notepad",
    }
    assert match(event) is None

