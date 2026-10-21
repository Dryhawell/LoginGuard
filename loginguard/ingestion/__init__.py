"""Read local authentication logs into normalized events."""

from loginguard.ingestion.log_reader import IngestionError
from loginguard.ingestion.parser import (
    JsonlParser,
    ParseIssue,
    ParseResult,
    parse_jsonl,
    parse_log_file,
)
from loginguard.ingestion.validators import RecordShapeError, require_json_object

__all__ = [
    "IngestionError",
    "JsonlParser",
    "ParseIssue",
    "ParseResult",
    "RecordShapeError",
    "parse_jsonl",
    "parse_log_file",
    "require_json_object",
]
