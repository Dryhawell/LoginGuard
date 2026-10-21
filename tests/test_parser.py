"""JSONL ingestion. Files are temporary and synthetic."""

from pathlib import Path

import pytest

from loginguard.ingestion import IngestionError, parse_jsonl
from loginguard.models import EventType

_SUCCESS = (
    '{"timestamp":"2026-09-10T10:00:00Z","event_type":"LOGIN_SUCCESS","username":"alice"}'
)
_FAILURE = (
    '{"timestamp":"2026-09-10T10:05:00Z","event_type":"login-failure",'
    '"username":"alice","source_ip":"192.0.2.10"}'
)


def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8", newline="")
    return path


def test_valid_lines_keep_missing_optional_fields_as_valid(tmp_path: Path) -> None:
    path = _write(tmp_path / "auth.jsonl", _SUCCESS + "\n" + _FAILURE + "\n")

    result = parse_jsonl(path)

    assert result.valid_count == 2
    assert result.invalid_count == 0
    assert result.events[0].username == "alice"
    assert result.events[0].source_ip is None
    assert result.events[0].event_type is EventType.LOGIN_SUCCESS
    assert result.events[1].event_type is EventType.LOGIN_FAILURE
    assert result.events[1].source_ip == "192.0.2.10"
    assert result.events[0].event_id == "auth.jsonl:1"
    assert result.events[0].raw_source == "auth.jsonl"


def test_blank_lines_do_not_shift_later_line_numbers(tmp_path: Path) -> None:
    path = _write(tmp_path / "spaced.jsonl", "\n" + _SUCCESS + "\n\n" + _FAILURE + "\n")

    result = parse_jsonl(path)

    assert [event.event_id for event in result.events] == ["spaced.jsonl:2", "spaced.jsonl:4"]
    assert result.invalid_count == 0


def test_malformed_line_is_reported_and_neighbors_are_kept(tmp_path: Path) -> None:
    path = _write(tmp_path / "mixed.jsonl", _SUCCESS + "\n{\n" + _FAILURE + "\n")

    result = parse_jsonl(path)

    assert result.valid_count == 2
    assert result.issues[0].line_number == 2
    assert result.issues[0].code == "malformed_json"
    assert result.issues[0].messages == ("malformed JSON",)
    assert result.events[1].event_type is EventType.LOGIN_FAILURE


def test_secret_text_in_a_bad_line_is_not_copied_into_the_issue(tmp_path: Path) -> None:
    path = _write(tmp_path / "secret.jsonl", '{"password":"hunter2"\n')

    result = parse_jsonl(path)

    assert result.valid_count == 0
    assert "hunter2" not in str(result.issues[0])


def test_python_expression_is_not_executed(tmp_path: Path) -> None:
    marker = tmp_path / "should-not-exist.txt"
    expression = f"(__import__('pathlib').Path({str(marker)!r}).write_text('x'))"
    path = _write(tmp_path / "expr.jsonl", expression + "\n")

    result = parse_jsonl(path)

    assert result.issues[0].code == "malformed_json"
    assert not marker.exists()


def test_non_object_json_is_distinct_from_a_record_with_missing_fields(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "shapes.jsonl",
        "\n".join(
            [
                "[]",
                "null",
                '"LOGIN_FAILURE"',
                '{"timestamp":"2026-09-10T10:00:00Z","event_type":"LOGIN_FAILURE"}',
            ]
        )
        + "\n",
    )

    result = parse_jsonl(path)

    assert [issue.code for issue in result.issues] == ["not_an_object", "not_an_object", "not_an_object"]
    assert result.valid_count == 1
    assert result.events[0].username is None


def test_two_json_values_on_one_line_are_rejected(tmp_path: Path) -> None:
    path = _write(tmp_path / "double.jsonl", _SUCCESS + " " + _FAILURE + "\n")

    result = parse_jsonl(path)

    assert result.valid_count == 0
    assert result.issues[0].messages == ("line contains more than one JSON value",)


def test_invalid_fields_report_the_file_line_and_keep_the_next_event(tmp_path: Path) -> None:
    bad_ip = '{"timestamp":"2026-09-10T10:00:00Z","event_type":"LOGIN_FAILURE","source_ip":"192.0.2.010"}'
    missing = '{"username":"alice","event_type":"LOGIN_FAILURE"}'
    naive = '{"timestamp":"2026-09-10T10:00:00","event_type":"LOGIN_FAILURE"}'
    path = _write(tmp_path / "bad.jsonl", "\n".join([bad_ip, missing, naive, _SUCCESS]) + "\n")

    result = parse_jsonl(path)

    assert [issue.line_number for issue in result.issues] == [1, 2, 3]
    assert {issue.code for issue in result.issues} == {"invalid_event"}
    assert "not a valid IP address" in result.issues[0].messages[0]
    assert any("timestamp:" in message for message in result.issues[1].messages)
    assert "not assumed to be UTC" in str(result.issues[2])
    assert result.events[0].event_type is EventType.LOGIN_SUCCESS


def test_unknown_event_label_is_valid_and_a_blank_type_is_not(tmp_path: Path) -> None:
    unknown = '{"timestamp":"2026-09-10T10:00:00Z","event_type":"Kerberos_Error"}'
    blank = '{"timestamp":"2026-09-10T10:00:00Z","event_type":"  "}'
    path = _write(tmp_path / "types.jsonl", unknown + "\n" + blank + "\n")

    result = parse_jsonl(path)

    assert result.events[0].event_type is EventType.UNKNOWN
    assert result.events[0].original_event_type == "Kerberos_Error"
    assert result.issues[0].line_number == 2
    assert "event_type: a value is required" in result.issues[0].messages


def test_supplied_event_id_is_preserved(tmp_path: Path) -> None:
    line = (
        '{"event_id":"vendor-9","timestamp":"2026-09-10T10:00:00Z",'
        '"event_type":"LOGOUT","raw_source":"lab-export"}'
    )
    path = _write(tmp_path / "ids.jsonl", line + "\n")

    event = parse_jsonl(path).events[0]

    assert event.event_id == "vendor-9"
    assert event.raw_source == "lab-export"


def test_crlf_and_bom_still_parse(tmp_path: Path) -> None:
    path = tmp_path / "windows.jsonl"
    body = (_SUCCESS + "\r\n" + _FAILURE + "\r\n").encode("utf-8")
    path.write_bytes(b"\xef\xbb\xbf" + body)

    result = parse_jsonl(path)

    assert result.valid_count == 2
    assert result.events[0].event_id == "windows.jsonl:1"


def test_utf8_username_is_preserved(tmp_path: Path) -> None:
    line = '{"timestamp":"2026-09-10T10:00:00Z","event_type":"LOGIN_SUCCESS","username":"Ayşe"}'
    path = _write(tmp_path / "utf8.jsonl", line + "\n")

    assert parse_jsonl(path).events[0].username == "Ayşe"


def test_empty_file_has_no_events_and_no_issues(tmp_path: Path) -> None:
    path = _write(tmp_path / "empty.jsonl", "")

    result = parse_jsonl(path)

    assert result.valid_count == 0
    assert result.invalid_count == 0


def test_pretty_printed_json_is_not_treated_as_jsonl(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "pretty.jsonl",
        '{\n  "timestamp": "2026-09-10T10:00:00Z",\n  "event_type": "LOGIN_FAILURE"\n}\n',
    )

    result = parse_jsonl(path)

    assert result.valid_count == 0
    assert result.invalid_count == 4


def test_missing_file_and_directory_fail_before_parsing(tmp_path: Path) -> None:
    with pytest.raises(IngestionError) as missing:
        parse_jsonl(tmp_path / "absent.jsonl")
    assert "file not found" in str(missing.value)

    with pytest.raises(IngestionError) as directory:
        parse_jsonl(tmp_path)
    assert "expected a file" in str(directory.value)


def test_invalid_utf8_fails_the_file_without_echoing_bytes(tmp_path: Path) -> None:
    path = tmp_path / "bad-encoding.jsonl"
    path.write_bytes(b'{"event_type":"LOGIN_FAILURE","username":"alice"}\xff\n')

    with pytest.raises(IngestionError) as exc:
        parse_jsonl(path)

    message = str(exc.value)
    assert "not valid UTF-8" in message
    assert "alice" not in message


def test_top_level_secret_field_is_an_invalid_event(tmp_path: Path) -> None:
    line = (
        '{"timestamp":"2026-09-10T10:00:00Z","event_type":"LOGIN_FAILURE","password":"hunter2"}'
    )
    path = _write(tmp_path / "secret-field.jsonl", line + "\n" + _SUCCESS + "\n")

    result = parse_jsonl(path)

    assert result.issues[0].code == "invalid_event"
    assert "hunter2" not in str(result.issues[0])
    assert result.valid_count == 1
