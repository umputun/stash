"""Data types for the Stash client library."""

from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass
class KeyInfo:
    """Metadata about a stored key."""

    key: str
    size: int
    format: str
    secret: bool
    zk_encrypted: bool
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "KeyInfo":
        """Create KeyInfo from a dictionary (JSON response)."""
        return cls(
            key=data["key"],
            size=data["size"],
            format=data.get("format", "text"),
            secret=data.get("secret", False),
            zk_encrypted=data.get("zk_encrypted", False),
            created_at=_parse_datetime(data["created_at"]),
            updated_at=_parse_datetime(data["updated_at"]),
        )


def _parse_datetime(value: str) -> datetime:
    """Parse ISO 8601 datetime string from JSON.

    Handles Go's RFC3339/RFC3339Nano format with up to 9 fractional digits.
    Python 3.10's fromisoformat only accepts 0, 3, or 6 fractional digits,
    so we truncate to 6 (microseconds) for compatibility.
    """
    # replace Z with +00:00
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"

    # find the fractional seconds part and truncate to 6 digits for Python 3.10 compatibility
    # format: 2024-01-15T10:30:00.123456789+00:00
    if "." in value:
        # split at decimal point
        before_dot, after_dot = value.split(".", 1)
        # find where timezone starts (+ or - after the dot)
        tz_start = -1
        for i, c in enumerate(after_dot):
            if c in "+-":
                tz_start = i
                break
        if tz_start > 6:
            # truncate fractional part to 6 digits
            after_dot = after_dot[:6] + after_dot[tz_start:]
        value = before_dot + "." + after_dot

    return datetime.fromisoformat(value)
