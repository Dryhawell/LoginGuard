"""Rule-based detection over normalized authentication events.

Importing this package does not register a rule. ``build_default_engine``
registers the brute-force rule, the password-spraying rule, and the
suspicious successful login rule. An empty ``RuleRegistry`` still runs nothing.
"""

from loginguard.detection.brute_force import (
    BruteForceRule,
    build_default_engine,
    register_brute_force,
    register_builtin_rules,
)
from loginguard.detection.password_spraying import (
    PasswordSprayRule,
    register_password_spraying,
)
from loginguard.detection.suspicious_login import (
    SuspiciousLoginRule,
    register_suspicious_login,
)
from loginguard.detection.config import DetectionConfig, DetectionConfigError
from loginguard.detection.engine import DetectionEngine
from loginguard.detection.finding import Finding, FindingValidationError, Severity
from loginguard.detection.rules import (
    DetectionRule,
    DuplicateRuleError,
    InvalidRuleError,
    RuleRegistry,
    UnknownRuleError,
)

__all__ = [
    "BruteForceRule",
    "DetectionConfig",
    "PasswordSprayRule",
    "SuspiciousLoginRule",
    "DetectionConfigError",
    "DetectionEngine",
    "DetectionRule",
    "DuplicateRuleError",
    "Finding",
    "FindingValidationError",
    "InvalidRuleError",
    "RuleRegistry",
    "Severity",
    "UnknownRuleError",
    "build_default_engine",
    "register_brute_force",
    "register_builtin_rules",
    "register_password_spraying",
    "register_suspicious_login",
]
