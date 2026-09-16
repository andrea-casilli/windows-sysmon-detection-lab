"""CLI for local simulation, detection, and validation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .engine import detect
from .simulator import SCENARIOS, simulate

ROOT = Path.cwd()
EVENTS = ROOT / "data" / "events.jsonl"
ALERTS = ROOT / "reports" / "alerts.json"


def validate() -> int:
    results = []
    for scenario in SCENARIOS:
        simulate(scenario, EVENTS)
        alerts = detect(EVENTS, ALERTS)
        matched = bool(alerts)
        results.append((scenario, matched, alerts[0]["rule_id"] if alerts else "none"))
    passed = sum(ok for _, ok, _ in results)
    report = [
        "# Sysmon Detection Coverage",
        "",
        "| Scenario | Result | Rule |",
        "| --- | --- | --- |",
    ]
    report.extend(f"| {name} | {'PASS' if ok else 'FAIL'} | {rule} |" for name, ok, rule in results)
    report.append(f"\nCoverage: {passed}/{len(results)} ({passed / len(results):.0%})")
    (ROOT / "reports").mkdir(exist_ok=True)
    report_path = ROOT / "reports" / "coverage-report.md"
    report_path.write_text("\n".join(report) + "\n", encoding="utf-8")
    (ROOT / "mitre").mkdir(exist_ok=True)
    coverage = {"passed": passed, "total": len(results)}
    (ROOT / "mitre" / "coverage.json").write_text(
        json.dumps(coverage, indent=2),
        encoding="utf-8",
    )
    for name, ok, rule in results:
        print(f"{name:<22} {'PASS' if ok else 'FAIL'}  {rule}")
    return 0 if passed == len(results) else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Safe Windows/Sysmon detection lab")
    sub = parser.add_subparsers(dest="command", required=True)
    simulation = sub.add_parser("simulate")
    simulation.add_argument("scenario", choices=[*SCENARIOS, "all"])
    sub.add_parser("detect")
    sub.add_parser("validate")
    sub.add_parser("coverage")
    args = parser.parse_args()
    if args.command == "simulate":
        print(f"Wrote {simulate(args.scenario, EVENTS)} inert Sysmon event(s).")
    elif args.command == "detect":
        print(f"Created {len(detect(EVENTS, ALERTS))} alert(s).")
    elif args.command == "validate":
        return validate()
    else:
        print((ROOT / "reports" / "coverage-report.md").read_text(encoding="utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

