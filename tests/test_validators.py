"""Record-shape checks. These do not open files."""

import pytest

from loginguard.ingestion import RecordShapeError, require_json_object


def test_json_object_is_accepted() -> None:
    record = {"event_type": "LOGIN_FAILURE", "username": "alice"}

    assert require_json_object(record) == record


def test_non_objects_are_rejected_without_echoing_the_value() -> None:
    for value in (["alice"], "password=hunter2", 5, None, True):
        with pytest.raises(RecordShapeError) as exc:
            require_json_object(value)

        assert str(exc.value) == "expected a JSON object"
        assert "hunter2" not in str(exc.value)
