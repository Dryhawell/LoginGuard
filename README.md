# LoginGuard — Login Attack Detector

Defensive, offline analysis of authentication logs. LoginGuard is a learning and portfolio project for Blue Team practice. It will read logs you are authorized to examine, look for suspicious authentication patterns, and explain why an alert was raised.

**Current status: Phase 6 — brute-force detection.** Password spraying, reports, and a dashboard are not implemented yet.

LoginGuard does not replace an enterprise SIEM, and a future alert will mean “this pattern deserves investigation,” not “this account was compromised.”

## Overview

Operators in a Security Operations Center (SOC) review authentication logs to spot repeated failures, password spraying, and successful logins that follow a burst of failures. LoginGuard will practice that workflow on synthetic JSON Lines logs first. It analyzes files locally. It does not attempt logins, guess passwords, or send log contents to an external service.

## Why This Project Exists

The project is a way to practice, in one codebase:

- Blue Team log analysis and SOC-style triage
- Authentication event modeling
- Rule-based detection with explainable evidence
- Python package layout, typing, and automated tests

## What Phase 1 Contains

| Path | Role |
| --- | --- |
| `main.py` | CLI entry point. Prints version and status. |
| `loginguard/` | Importable package. |
| `loginguard/utils/logger.py` | Stderr logging that avoids secrets and identity fields. |
| `requirements.txt` | Development dependency (`pytest`) for later tests. |
| `LICENSE` | MIT License. |
| `.gitignore` | Ignores virtual environments, caches, and future generated output. |

The runtime uses the Python standard library only. `pytest` runs the event-model tests.

## Authentication event model

`loginguard.models.AuthEvent` is the normalized record later rules will count. Required fields are a timezone-aware timestamp and an event type. Username, source IP, method, hostname, application, and failure reason may be missing.

Timestamps are stored as timezone-aware UTC. `2026-09-10T13:00:00+03:00` and `2026-09-10T10:00:00Z` are the same instant. A timestamp with no offset is rejected and is not assumed to be UTC. The original numeric offset is not kept after conversion.

Event types are `LOGIN_SUCCESS`, `LOGIN_FAILURE`, `LOGOUT`, `ACCOUNT_LOCKED`, `PASSWORD_CHANGE`, and `UNKNOWN`. Common labels such as `login-failure` or `logoff` normalize to that set. An unrecognized label becomes `UNKNOWN` and the original text is kept on `original_event_type`. `UNKNOWN` is not a successful login.

The model does not store passwords, tokens, cookies, or raw log lines. `raw_source` is a short origin label, such as a file name.

```python
from loginguard.models import AuthEvent

event = AuthEvent.create(
    timestamp="2026-09-10T10:00:00Z",
    event_type="LOGIN_FAILURE",
    username="alice",
    source_ip="192.0.2.10",
)
```

`192.0.2.10` is a documentation address, not a host on the public internet.

## JSONL ingestion

`loginguard.ingestion.parse_jsonl` reads a UTF-8 JSON Lines file. Each physical line is one JSON object. Parsing uses the `json` module and never calls `eval`.

A blank line is skipped. A broken line becomes a `ParseIssue` with its 1-based line number, and the parser continues with the next line. A missing username or source IP is still a valid event. A missing timestamp, a naive timestamp, an invalid IP, or malformed JSON is an invalid line.

```python
from loginguard.ingestion import parse_jsonl

result = parse_jsonl("data/samples/auth_logs.jsonl")
result.valid_count
result.issues
```

The checked-in sample is described below. The parser does not copy the raw line into the event or the issue. `raw_source` is the file name. A missing `event_id` becomes `<file name>:<line number>`, so reading the same file again produces the same ids. That id is not unique across two directories that use the same file name.

One JSON object split across several lines is rejected. JSONL keeps each object on a single line. A file that is not valid UTF-8 fails as a whole; a single bad record does not.

## Sample logs

`data/samples/auth_logs.jsonl` is synthetic demonstration data. It is not a capture from a real system. Source addresses use documentation ranges only (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, and `2001:db8::/32`). The file contains no passwords, hashes, tokens, or cookies.

Each valid line is labeled with `metadata.dataset` set to `synthetic` and a `metadata.scenario` name:

| Scenario | What the lines illustrate |
| --- | --- |
| `normal_success` | Ordinary successful logins and a logout from several accounts and addresses, including one IPv6 address and one offset timestamp. |
| `ordinary_mistakes` | Two failures, then a success, for one account. |
| `repeated_failures` | Six failures for one account and one source address inside five minutes. |
| `password_spraying` | Failures for six usernames from one source address inside ten minutes. |
| `failure_then_success` | Five failures followed by a success for the same account and source. |
| `missing_optional` | Valid events with no username, or with a username and no source IP. |
| `out_of_order` | A later line carries an earlier timestamp. |
| `duplicate` | The same `event_id` appears twice. |

The file also contains a comment banner, a broken JSON line, a JSON array, a timestamp with no offset, an invalid IP, and a line with two JSON values. Those lines become parse issues. They are not alerts, and this phase does not score the file.

From the repository root:

```powershell
python -c "from loginguard.ingestion import parse_jsonl; r = parse_jsonl('data/samples/auth_logs.jsonl'); print(r.valid_count, r.invalid_count)"
```

## Detection engine

`DetectionEngine` runs registered rules over `AuthEvent` values and returns `Finding` values. A finding explains why it was created. It means the rule saw something worth investigating. It is not proof of an attack.

Importing the package leaves the registry empty. `build_default_engine` registers the shipped brute-force rule. Password spraying is not registered.

`DetectionConfig` holds the demonstration defaults:

| Setting | Default | Read by |
| --- | --- | --- |
| `brute_force_min_failures` | 5 | `brute-force-same-account` |
| `brute_force_window` | 5 minutes | `brute-force-same-account` |
| `password_spray_min_usernames` | 5 | not yet |
| `password_spray_window` | 10 minutes | not yet |

The engine orders events by timestamp before rules see them. It does not assign a risk score. `CRITICAL` is part of the severity scale and is reserved. Registration rejects it.

### Brute-force rule

Rule id: `brute-force-same-account`.

The rule counts `LOGIN_FAILURE` events for one username and one source IP. Usernames are compared with their original case. Events missing a username or a source IP are skipped. Five failures inside a rolling five-minute window is the demonstration default. A finding uses severity `MEDIUM`. It means the pattern is worth investigating. It does not mean the account was attacked or compromised. A person mistyping a password, or a script retrying one, can look the same.

One ongoing burst produces one finding. The events in that burst are not reused for a second overlapping finding. A later, separate burst can still produce another finding. Duplicate `event_id` values inside a group are counted once.

On the synthetic sample, `alice` from `192.0.2.10` has six failures inside five minutes. `bob` has two ordinary failures and does not match. `nora` has five failures before a later success, so this rule also flags that failure burst. The following success is not counted and is not, by itself, a separate finding yet.

```python
from loginguard.detection import build_default_engine
from loginguard.ingestion import parse_jsonl

events = parse_jsonl("data/samples/auth_logs.jsonl").events
findings = build_default_engine().run(events)
```

## Requirements

- Windows, macOS, or Linux
- Python 3.12 or newer
- No administrator privileges
- No network access required to run the program

## Installation

From the repository root in Windows PowerShell. `py -3` selects the newest installed Python 3. It must be 3.12 or newer (this workspace was verified with 3.13):

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

To pin an interpreter explicitly: `py -3.13 -m venv .venv`. If no 3.12+ runtime exists, install one from [python.org](https://www.python.org/downloads/) and open a new terminal. If execution policy blocks activation, run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once, then activate again.

## Usage

```powershell
python main.py
python main.py --help
python main.py --version
python main.py --log-level DEBUG
```

Exit codes:

| Code | Meaning |
| --- | --- |
| 0 | The process completed. |
| 1 | Runtime failure, including an unsupported Python version. |
| 2 | Invalid command-line usage (`argparse`). |

Finding a suspicious pattern in a future phase will not be treated as a program error.

## Testing

From the repository root, with the virtual environment activated:

```powershell
python -m pytest
```

## Privacy and Data Handling

- Analysis stays on the machine that runs LoginGuard.
- The MVP will not make external network calls.
- Application logs go to stderr and must not contain passwords, tokens, cookies, or full raw log lines.
- Routine logs omit usernames and source IP addresses.
- When you later use real logs, remove secrets and unnecessary personal data before sharing a file or committing it. Sample data in this repository will be synthetic only.

Generated files, once later phases create them, are stored locally:

- `logs/` — application log files
- `data/events/` — normalized events
- `data/reports/` — alerts and summaries

Those directories are listed in `.gitignore` so generated output is not committed by accident. `data/samples/` holds the labeled synthetic log and is meant to be committed.

## Responsible Use

Use LoginGuard only on logs you own or are allowed to analyze. The project must not be used to guess passwords, log in to systems, collect credentials, bypass authentication, exfiltrate logs, or change authentication settings.

## Roadmap

Brute-force detection is in place. Later phases add, in order: password-spraying detection, suspicious-success and credential-stuffing heuristics, alerts and risk scoring, correlation, local JSON storage, the full CLI, reports, broader tests, and documentation. A Windows Event Log adapter and a dashboard are optional later phases and are not part of the first release path.

## License

Released under the [MIT License](LICENSE). The copyright holder is Talha Tarlabaz.
