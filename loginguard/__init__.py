"""LoginGuard: offline analysis of authentication logs.

This package detects suspicious authentication patterns in logs the operator
is authorized to examine. It does not attempt logins, collect credentials,
or contact external services.
"""

from __future__ import annotations

__app_name__ = "LoginGuard"
__version__ = "0.1.0"
__description__ = "Defensive authentication log analysis for learning and portfolio use."
