# Windows / Sysmon Detection Lab

A safe, Python-only detection-engineering lab for Windows Sysmon telemetry. It demonstrates how process, registry, and network events become validated detections and triage-ready alerts.

> Safety boundary: the simulator creates JSONL records only. It does not invoke PowerShell, alter the registry, spawn processes, connect to hosts, or require Windows.

## Detection coverage

| Scenario | Sysmon event | ATT&CK | Rule |
| --- | --- | --- | --- |
| Encoded PowerShell metadata | Process Create (1) | T1059.001 | `SYSMON-POWERSHELL-ENCODED-001` |
| Office child shell | Process Create (1) | T1204.002 | `SYSMON-OFFICE-CHILD-SHELL-001` |
| Run-key persistence metadata | Registry value set (13) | T1547.001 | `SYSMON-RUNKEY-PERSISTENCE-001` |
| Unusual outbound admin tooling | Network connection (3) | T1021 | `SYSMON-REMOTE-ADMIN-NETWORK-001` |

## Quick start

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
python -m sysmon_lab validate
```

On Linux/macOS, activate with `source .venv/bin/activate`.

## Commands

```text
python -m sysmon_lab simulate all
python -m sysmon_lab detect
python -m sysmon_lab validate
python -m sysmon_lab coverage
```

The simulator writes normalized event records to `data/events.jsonl`; detection writes `reports/alerts.json` and validation writes `reports/coverage-report.md`.

## Structure

```text
sysmon_lab/       CLI, simulation, rules, validation
detection/        Sigma-style rule intent
mitre/            ATT&CK mapping and measured coverage
tests/            Unit and end-to-end tests
```

## License

MIT. See [LICENSE](LICENSE).

