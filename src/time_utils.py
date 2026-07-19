"""Central datetime helpers for authentication event processing."""

from datetime import datetime


DEFAULT_LOG_YEAR = 2026
SYSLOG_TIMESTAMP_FORMAT = "%Y %b %d %H:%M:%S"


def normalize_syslog_timestamp(timestamp: str, default_year: int) -> str | None:
    """Return an ISO 8601 timestamp, or ``None`` when the input is invalid."""
    try:
        parsed = datetime.strptime(
            f"{default_year} {timestamp}", SYSLOG_TIMESTAMP_FORMAT
        )
    except (TypeError, ValueError):
        return None
    return parsed.isoformat(timespec="seconds")


def parse_event_timestamp(timestamp: str) -> datetime:
    """Parse a normalized event timestamp produced by this application."""
    return datetime.fromisoformat(timestamp)


def validate_window_minutes(window_minutes: int | float) -> None:
    """Reject detection windows that are zero or negative."""
    if window_minutes <= 0:
        raise ValueError("window_minutes must be greater than 0")
