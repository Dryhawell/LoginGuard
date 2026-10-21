"""Timestamp parsing. These tests use fixed instants and do not read the clock."""

from datetime import datetime, timedelta, timezone

import pytest

from loginguard.utils.time_utils import TimestampParseError, format_timestamp, parse_timestamp


def test_zulu_suffix_becomes_utc() -> None:
    parsed = parse_timestamp("2026-09-10T10:00:00Z")

    assert parsed == datetime(2026, 9, 10, 10, 0, tzinfo=timezone.utc)
    assert parsed.tzinfo is not None


def test_lowercase_z_and_explicit_offset_are_the_same_instant() -> None:
    zulu = parse_timestamp("2026-09-10T10:00:00z")
    offset = parse_timestamp("2026-09-10T13:00:00+03:00")

    assert zulu == offset
    assert zulu.utcoffset() == timedelta(0)


def test_whitespace_around_an_offset_is_ignored() -> None:
    parsed = parse_timestamp("  2026-09-10T10:00:00+00:00  ")

    assert parsed == datetime(2026, 9, 10, 10, 0, tzinfo=timezone.utc)


def test_aware_datetime_is_converted_to_utc() -> None:
    local = datetime(2026, 9, 10, 13, 0, tzinfo=timezone(timedelta(hours=3)))

    assert parse_timestamp(local) == datetime(2026, 9, 10, 10, 0, tzinfo=timezone.utc)


def test_naive_datetime_is_not_treated_as_utc() -> None:
    with pytest.raises(TimestampParseError) as exc:
        parse_timestamp(datetime(2026, 9, 10, 10, 0))

    assert "not assumed to be UTC" in str(exc.value)


def test_naive_iso_string_is_not_treated_as_utc() -> None:
    with pytest.raises(TimestampParseError) as exc:
        parse_timestamp("2026-09-10T10:00:00")

    assert "not assumed to be UTC" in str(exc.value)


def test_date_only_string_is_rejected() -> None:
    with pytest.raises(TimestampParseError):
        parse_timestamp("2026-09-10")


def test_unix_timestamp_is_rejected() -> None:
    with pytest.raises(TimestampParseError) as exc:
        parse_timestamp(1_757_500_800)

    assert "Unix timestamps are not accepted" in str(exc.value)


def test_empty_timestamp_is_rejected() -> None:
    with pytest.raises(TimestampParseError) as exc:
        parse_timestamp("   ")

    assert "required" in str(exc.value)


def test_format_timestamp_uses_z_suffix() -> None:
    parsed = parse_timestamp("2026-09-10T13:00:00.123456+03:00")

    assert format_timestamp(parsed) == "2026-09-10T10:00:00.123456Z"


def test_long_unparsed_text_is_truncated_in_the_error() -> None:
    with pytest.raises(TimestampParseError) as exc:
        parse_timestamp("x" * 200)

    message = str(exc.value)
    assert "..." in message
    assert "x" * 80 not in message
