# LoginGuard — Login Attack Detector

Defensive, offline analysis of authentication logs. LoginGuard is a learning and portfolio project for Blue Team practice. It will read logs you are authorized to examine, look for suspicious authentication patterns, and explain why an alert was raised.

**Current status: Phase 13 — command line.** JSON and CSV report export, and a dashboard, are not implemented yet.

LoginGuard does not replace an enterprise SIEM. An alert means “this pattern deserves investigation,” not “this account was compromised.”

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
| `failure_then_success` | Five failures, then a success, for Nora from `192.0.2.40`. The suspicious-success rule flags that success. |
| `distributed_failures` | Failures for five usernames from three documentation addresses inside fifteen minutes. No single address has five usernames, so this group is not a spray. |
| `missing_optional` | Valid events with no username, or with a username and no source IP. |
| `out_of_order` | A later line carries an earlier timestamp. |
| `duplicate` | The same `event_id` appears twice. |

A source address that has not been seen before is not labeled as an attack. The file has no geolocation, so it cannot show impossible travel. Those two ideas are out of scope for detection.

The file also contains a comment banner, a broken JSON line, a JSON array, a timestamp with no offset, an invalid IP, and a line with two JSON values. Those lines become parse issues. They are not alerts. The detection rules score the valid events in a separate step.

From the repository root:

```powershell
python -c "from loginguard.ingestion import parse_jsonl; r = parse_jsonl('data/samples/auth_logs.jsonl'); print(r.valid_count, r.invalid_count)"
```

## Detection engine

`DetectionEngine` runs registered rules over `AuthEvent` values and returns `Finding` values. A finding explains why it was created. It means the rule saw something worth investigating. It is not proof of an attack.

Importing the package leaves the registry empty. `build_default_engine` registers the brute-force rule, the password-spraying rule, the suspicious successful login rule, and the distributed-failure heuristic. An empty `RuleRegistry` still runs nothing.

`DetectionConfig` holds the demonstration defaults:

| Setting | Default | Read by |
| --- | --- | --- |
| `brute_force_min_failures` | 5 | `brute-force-same-account` |
| `brute_force_window` | 5 minutes | `brute-force-same-account` |
| `password_spray_min_usernames` | 5 | `password-spray-distinct-usernames` |
| `password_spray_window` | 10 minutes | `password-spray-distinct-usernames` |
| `success_after_failure_min_failures` | 5 | `success-after-failures` |
| `success_after_failure_window` | 10 minutes | `success-after-failures` |
| `distributed_min_usernames` | 5 | `distributed-failure-heuristic` |
| `distributed_min_source_ips` | 3 | `distributed-failure-heuristic` |
| `distributed_window` | 15 minutes | `distributed-failure-heuristic` |

The engine orders events by timestamp before rules see them. It does not assign a risk score. Scoring is a separate step and reads the findings the rules already produced. `CRITICAL` is part of the severity scale and is reserved. Registration rejects it. No current rule emits it.

### Brute-force rule

Rule id: `brute-force-same-account`.

The rule counts `LOGIN_FAILURE` events for one username and one source IP. Usernames are compared with their original case. Events missing a username or a source IP are skipped. Five failures inside a rolling five-minute window is the demonstration default. A finding uses severity `MEDIUM`. It means the pattern is worth investigating. It does not mean the account was attacked or compromised. A person mistyping a password, or a script retrying one, can look the same.

This pattern is not password spraying. Password spraying is many distinct usernames from one source address, and that is a separate rule.

One ongoing burst produces one finding. The events in that burst are not reused for a second overlapping finding. A later, separate burst can still produce another finding. Duplicate `event_id` values inside a group are counted once.

On the synthetic sample, `alice` from `192.0.2.10` has six failures inside five minutes. `bob` has two ordinary failures and does not match. `nora` has five failures before a later success, so this rule also flags that failure burst. The following success is not counted by this rule. `success-after-failures` reports that success separately.

```python
from loginguard.detection import build_default_engine
from loginguard.ingestion import parse_jsonl

events = parse_jsonl("data/samples/auth_logs.jsonl").events
findings = build_default_engine().run(events)
```

### Password-spraying rule

Rule id: `password-spray-distinct-usernames`.

Brute force asks whether one account is failing repeatedly from one address. Password spraying asks a different question: did one source address fail against many distinct usernames inside the window? The demonstration default is 5 distinct usernames inside 10 minutes. Both values come from `DetectionConfig`.

Repeated failures against one username do not match this rule, even when there are many of them. That pattern belongs to `brute-force-same-account`. Failures from two source addresses are not added together. A missing source IP is skipped and is not merged with a real address. A missing username is skipped. Usernames are compared with their original case, so `Alice` and `alice` are different accounts.

Only `LOGIN_FAILURE` events count. A successful login is not a failure. A success for one of the usernames does not erase the failures and does not raise the severity.

The window is inclusive. A failure exactly `window` after the oldest failure in the cluster still counts. A failure any later than that does not. When a cluster meets the threshold, those events are consumed and the rule emits one finding for that source address and that cluster. It does not emit one finding per username or one finding per failure. A later burst from the same address can still produce another finding. That consumption is narrower than the Phase 11 alert deduplication.

`observed_count` is the number of distinct usernames, not the number of failures. The finding stores the source IP on `source_ip` and the distinct usernames, in first-seen order, on `affected_usernames`. `affected_username` stays empty because the pattern is not one account. `repr` does not print the usernames or the source address. The description may name them when the text still fits. Related event ids, and the stored username list, are capped at 100. The observed count still reports the full number of distinct usernames.

Severity is `MEDIUM`. The finding is a suspicion, not proof of a spray. A misconfigured client can try several accounts. The recommendation is to review the source, check whether it is a misconfigured client or a spray, not to guess passwords, and not to block an address solely on this signal.

On the synthetic sample, `203.0.113.50` fails against six usernames inside about ten minutes, so this rule flags that group. `alice` from `192.0.2.10` is a single-account burst. It can still produce a brute-force finding. It is not a spray finding. `bob` in `ordinary_mistakes` is not a spray finding either.

### Suspicious successful login rule

Rule id: `success-after-failures`.

Brute force asks whether one account is failing repeatedly from one address. Password spraying asks whether one address is failing against many accounts. This rule asks whether one account succeeded after a recent burst of failures. The demonstration default is 5 `LOGIN_FAILURE` events inside a 10-minute window. Both values come from `DetectionConfig`: `success_after_failure_min_failures` and `success_after_failure_window`. A couple of typos, such as Bob's two mistakes, stay below the threshold.

The window ends at the `LOGIN_SUCCESS` timestamp and looks backward. A failure for the same username counts when its timestamp is inside that span, including a failure exactly `window` before the success. A failure any earlier does not. Failures after the success do not count for that success. The success event is the trigger. It is not added to the failure count. Only `LOGIN_FAILURE` events count. Logouts, lockouts, and other types are ignored.

Grouping is by username only. Names keep their original case, so `Alice` and `alice` are different accounts. Source IP is not part of the group key. Failures may come from one address or several. The success may come from the same address or from a different one. The success address does not have to match a failure address. The finding stores the success address on `source_ip` when the success has one. Failure addresses are listed in the description when they are present. A missing username is skipped and is not merged with other nameless events. A missing source IP does not drop the event. Duplicate `event_id` values count once; the earliest copy is kept.

Each success that meets the threshold produces one finding. The failures are not consumed, so two qualifying successes can produce two findings even when they share failures. Related event ids are the counted failure ids in time order, then the success id, capped at 100. When the list would be longer, the earliest 99 failure ids and the success id are kept. `observed_count` is still the full failure count. `first_event_time` is the earliest counted failure. `last_event_time` is the success time. `repr` does not print the username or any address.

Severity is `HIGH`. The description states that this is an investigative signal, not proof of compromise. Someone can mistype a password and then type it correctly. The recommendation is to investigate the account, ask the user whether they eventually typed the right password, and review the source of the success. It does not suggest guessing passwords, blocking the account as automatic proof, or calling the pattern a confirmed takeover. `CRITICAL` is not used.

An unfamiliar source IP is not detected as an attack. A successful login from an address that has not been seen before does not, by itself, produce a finding. Impossible travel is not detected. The logs have no geolocation, and this rule does not invent geography from an IP address.

On the synthetic sample, `failure_then_success` is Nora from `192.0.2.40`: five failures, then a success. `parse_jsonl` and `build_default_engine` produce this rule's finding for Nora. Alice in `repeated_failures` has failures and no success, so this rule does not flag her. The brute-force rule still can. Bob in `ordinary_mistakes` has two failures and a success, which is below this threshold.

### Distributed-failure heuristic

Rule id: `distributed-failure-heuristic`.

Ordinary authentication logs cannot prove credential stuffing. The log records that a login failed. It does not record a reliable copy of the password that was offered, and it cannot show that a password came from a leak. This rule does not query a breach database and does not invent breach evidence. The finding says the pattern is consistent with credential-stuffing-like or distributed guessing behavior. It does not say that stuffing occurred.

Password spraying is a different rule, `password-spray-distinct-usernames`. That rule is one source IP and at least 5 distinct usernames inside 10 minutes, with severity `MEDIUM`. A single-IP multi-username failure pattern stays with that rule only. This heuristic does not emit a second finding that calls the same events credential stuffing.

This rule looks for a distributed shape: many source addresses and many usernames with `LOGIN_FAILURE` events inside one window. The demonstration defaults, all overridable on `DetectionConfig`, are 5 distinct usernames, 3 distinct source addresses, and 15 minutes. `Finding.threshold` is the username minimum. `observed_count` is the distinct username count. The distinct source-address count is written into the description. `Finding` keeps a single `source_ip`, so that field stays empty here. `affected_username` stays empty. The usernames are stored on `affected_usernames`.

Only `LOGIN_FAILURE` events count. A success is not a failure. A missing username or a missing source IP is skipped and is not merged into a shared bucket. Usernames keep their original case. Duplicate `event_id` values count once. The window is inclusive. When a cluster meets both minimums, those events are consumed and the rule emits one finding for the whole cluster. It does not emit one finding per address or one finding per username. Related event ids, and the stored username list, are capped at 100. `repr` does not print usernames or addresses.

Severity is `LOW`, not `MEDIUM`. The username minimum is the same as the spray rule, and the window is longer than the spray window, so the evidence bar is not clearly higher. Requiring three source addresses changes the shape. It does not outweigh that comparison, and the log still cannot show a leaked password. `HIGH` and `CRITICAL` are not used.

The recommendation is to investigate the source addresses and the accounts. Do not assume a breach. Do not guess passwords.

On the synthetic sample, `distributed_failures` is five usernames from three documentation addresses inside fifteen minutes. No one of those addresses has five usernames, so the spray rule does not own that group, and this heuristic does. `203.0.113.50` in `password_spraying` is one address and stays with the spray rule only. Alice in `repeated_failures` is one account and one address. Nora in `failure_then_success` is one account. Neither of those scenarios produces this finding on its own.

## Alerts

`alert_from_finding` builds one `Alert` from one `Finding`. It does not run a detector. `dedupe_alerts` then drops a later finding that repeats the same rule, account, and source address before the previous finding has been quiet for its window. A finding that starts after that quiet gap is kept, so a later incident can still raise an alert. The tradeoff is that a second burst inside the quiet gap does not raise a second alert.

The alert copies the rule id, the severity the rule already chose, the recommendation, the related event ids, and the optional account and source address. `status` is `OPEN`. LoginGuard does not assign, acknowledge, or close alerts.

`description` and `evidence` state the rule id, the observed count, the threshold, and the window. They also state that a finding is a suspicion, not proof of compromise. `repr` omits usernames and source addresses. Passwords, tokens, cookies, and raw log lines are rejected. The alert timestamp defaults to the finding's last event time, then its first event time. The clock is not read.

Brute force stays `MEDIUM`. Password spraying stays `MEDIUM`. Success after failures stays `HIGH`. The distributed-failure heuristic stays `LOW`. `CRITICAL` exists on the severity scale and is unused by these rules.

```python
from loginguard.detection import build_default_engine
from loginguard.ingestion import parse_jsonl
from loginguard.models import alert_from_finding

events = parse_jsonl("data/samples/auth_logs.jsonl").events
findings = build_default_engine().run(events)
alert = alert_from_finding(findings[0])
```

`dedupe_alerts(findings)` is the path that applies the quiet-gap rule before building alerts.

## Correlation

`correlate_events` groups authentication events after sorting them and keeping one copy of each `event_id`. The earliest copy wins. Select one or more keys: username, source address, and event type. An event missing a selected key is left out, so blank usernames are not treated as one account.

Inside a key, a new group starts when the next event is later than the previous one by more than the window. A gap equal to the window stays in the same group. A chain of small gaps can become one long group. That keeps a continuing story together. It can also hide a second burst that never quite goes quiet.

## Local storage

`EventStore` appends normalized events to a JSON Lines file. The default path is `data/events/events.jsonl`. `AlertStore` replaces one JSON document. The default path is `data/reports/alerts.json`, with schema `loginguard.alerts.v1`. Both paths are ignored by git. The stores create a missing parent directory. A missing file loads as an empty collection.

Event lines are appended. A second batch does not rewrite earlier lines, and a sibling file in the same directory is left alone. One malformed line becomes a `ParseIssue`. The valid lines around it are still returned. The issue text does not quote the line. A file that is not UTF-8 is refused before more text is added.

The alert document is written to a temporary file in the same directory and then moved into place with `os.replace`. A failed replace leaves the previous document in place. An empty save writes a valid document with no alerts. A document with a different schema is rejected. `data/reports/analysis_summary.json` is reserved for the reporting phase and is not written here.

File storage has no lock and no database. Two writers can interleave event lines or lose one alert save. A crash during an append can leave a partial last line, which the next load reports as malformed JSON. Duplicate `event_id` values stay in the file; detection still counts one of them. Saving alerts replaces that document only. It does not keep earlier alert documents.

`append` adds lines and leaves earlier lines in place. `replace` writes one snapshot and drops the previous contents of that file. The `analyze` command uses `replace`, so a second analysis stores that run only. A sibling file in the directory is left alone.

```python
from loginguard.storage import AlertStore, EventStore

events = EventStore("data/events/events.jsonl")
events.replace(result.events)
alerts = AlertStore("data/reports/alerts.json")
alerts.save(stored_alerts)
```

## Risk score

`score_finding` turns one finding into an integer from 0 through 100. The score is a project heuristic. It is not a probability of compromise, and the bands are not an industry standard.

| Score | Band |
| --- | --- |
| 0–20 | LOW |
| 21–50 | MEDIUM |
| 51–75 | HIGH |
| 76–100 | CRITICAL |

The breakdown is a list of point terms. Those terms sum to the score.

| Term | Points |
| --- | --- |
| Severity base | INFO 10, LOW 15, MEDIUM 35, HIGH 65. Each base sits inside the matching band. A CRITICAL finding would start at 85. No current rule emits CRITICAL. |
| Failures above the threshold | 2 points each, capped at 8. Used only by `brute-force-same-account` and `success-after-failures`, because those rules count failures. Spray and the distributed heuristic count usernames, so they do not receive this term. |
| Affected accounts | 1 point per distinct account named on the finding, capped at 6. Omitted when the finding names no account. A name stored twice counts once. |

Extras stop at the top of the severity band, and the score also stops at 100. A MEDIUM finding stays inside 21–50. A HIGH finding stays inside 51–75. An ordinary single finding does not reach 76. The CRITICAL band is part of the scale and is unused by current rules.

A brute-force finding does not receive points for a later success. That pattern is a separate finding from `success-after-failures`. Its higher score is the HIGH base that rule already chose, not a success bonus added onto brute force. An unfamiliar source address adds nothing. The address stored on the finding does not add points by itself.

With `findings` from the example above:

```python
from loginguard.risk import score_finding

score = score_finding(findings[0])
score.score
score.band
score.components
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

## Command line

Global options come before the subcommand. `--log-level` writes the application log to stderr. That log records counts. It does not record usernames, source addresses, or raw lines.

`analyze` parses a JSONL file, runs the built-in rules, deduplicates alerts, and replaces the event and alert snapshot. The summary prints counts and the highest heuristic score. It states that the score is not a probability. Detecting a pattern exits 0.

`validate` parses a file and prints rejected lines. It does not run rules and it does not write the snapshot. Issue text does not quote the raw line.

`alerts` lists the stored alerts. `--severity HIGH` keeps one severity. The account and source address are on this list because it is the triage view.

`stats` counts stored events, event types, distinct usernames, distinct source addresses, and alerts. It prints those counts, not the names or addresses.

`report` prints a text report from the same snapshot: counts, evidence, recommendations, and the project limitations. The numeric score is printed by `analyze` and is not stored in the alert file. JSON and CSV export are the next phase.

A missing or unreadable file exits 1. An invalid command line exits 2. Invalid log lines are data issues, so `validate` and `analyze` still exit 0 when the file itself can be read.

```powershell
python main.py
python main.py --help
python main.py analyze --input data/samples/auth_logs.jsonl
python main.py validate --input data/samples/auth_logs.jsonl
python main.py alerts
python main.py alerts --severity HIGH
python main.py stats
python main.py report
```

`analyze` writes `data/events/events.jsonl` and `data/reports/alerts.json` unless `--events` and `--alerts` point somewhere else. Those default paths are gitignored.

## Usage

```powershell
python main.py
python main.py --help
python main.py --version
python main.py --log-level DEBUG analyze --input data/samples/auth_logs.jsonl
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

Generated files are stored locally:

- `logs/` — application log files
- `data/events/` — normalized events
- `data/reports/` — alerts and summaries

Those directories are listed in `.gitignore` so generated output is not committed by accident. `data/samples/` holds the labeled synthetic log and is meant to be committed.

## Responsible Use

Use LoginGuard only on logs you own or are allowed to analyze. The project must not be used to guess passwords, log in to systems, collect credentials, bypass authentication, exfiltrate logs, or change authentication settings.

## Roadmap

Brute-force detection, password-spraying detection, suspicious successful login detection, a conservative distributed-failure heuristic, alerts, risk scoring, correlation, alert deduplication, local JSON storage, and the text command line are in place. Later phases add, in order: JSON and CSV reports, broader tests, and documentation. A Windows Event Log adapter and a dashboard are optional later phases and are not part of the first release path. Unfamiliar source addresses and impossible travel stay out of scope.

## License

Released under the [MIT License](LICENSE). The copyright holder is Talha Tarlabaz.
