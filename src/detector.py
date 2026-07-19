"""Time-windowed detection rules for suspicious authentication activity."""

import sqlite3
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Callable, TypedDict

from database import Alert
from time_utils import parse_event_timestamp, validate_window_minutes


class DetectionEvent(TypedDict):
    """The event fields needed by detection rules."""

    id: int
    timestamp: datetime
    timestamp_text: str
    username: str
    ip_address: str
    event_type: str
    is_invalid_user: bool


def _validate_threshold(threshold: int) -> None:
    """Reject thresholds that cannot represent a useful event count."""
    if threshold < 1:
        raise ValueError("threshold must be at least 1")


def _load_events(connection: sqlite3.Connection) -> list[DetectionEvent]:
    """Load normalized events in timestamp order, using ID as a tie-breaker."""
    rows = connection.execute(
        """
        SELECT id, event_timestamp, username, ip_address, event_type,
               is_invalid_user
        FROM auth_events
        WHERE event_timestamp IS NOT NULL
        ORDER BY event_timestamp, id
        """
    ).fetchall()
    return [
        {
            "id": row[0],
            "timestamp": parse_event_timestamp(row[1]),
            "timestamp_text": row[1],
            "username": row[2],
            "ip_address": row[3],
            "event_type": row[4],
            "is_invalid_user": bool(row[5]),
        }
        for row in rows
    ]


def _group_by_ip(events: list[DetectionEvent]) -> dict[str, list[DetectionEvent]]:
    """Group already ordered events by source IP."""
    grouped: dict[str, list[DetectionEvent]] = defaultdict(list)
    for event in events:
        grouped[event["ip_address"]].append(event)
    return grouped


def _find_windows(
    events: list[DetectionEvent],
    threshold: int,
    window_minutes: int | float,
    qualifies: Callable[[list[DetectionEvent]], bool],
) -> list[list[DetectionEvent]]:
    """Find deterministic, non-overlapping sliding windows in ordered events."""
    maximum_span = timedelta(minutes=window_minutes)
    active: deque[DetectionEvent] = deque()
    matches: list[list[DetectionEvent]] = []

    for event in events:
        active.append(event)
        while active and event["timestamp"] - active[0]["timestamp"] > maximum_span:
            active.popleft()
        active_events = list(active)
        if len(active_events) >= threshold and qualifies(active_events):
            matches.append(active_events)
            active.clear()

    return matches


def _count_qualifies(threshold: int) -> Callable[[list[DetectionEvent]], bool]:
    """Build a threshold predicate for event-count rules."""
    return lambda events: len(events) >= threshold


def _distinct_user_qualifies(
    threshold: int,
) -> Callable[[list[DetectionEvent]], bool]:
    """Build a threshold predicate for distinct-username rules."""
    return lambda events: len({event["username"] for event in events}) >= threshold


def detect_ssh_brute_force(
    connection: sqlite3.Connection,
    threshold: int = 3,
    window_minutes: int | float = 5,
) -> list[Alert]:
    """Return alerts for failed-login clusters from individual IP addresses."""
    _validate_threshold(threshold)
    validate_window_minutes(window_minutes)
    failed_events = [
        event for event in _load_events(connection)
        if event["event_type"] == "failed_password"
    ]

    alerts: list[Alert] = []
    for source_ip, events in sorted(_group_by_ip(failed_events).items()):
        windows = _find_windows(
            events, threshold, window_minutes, _count_qualifies(threshold)
        )
        for window in windows:
            alerts.append(
                {
                    "alert_type": "ssh_brute_force",
                    "title": "Possible SSH brute-force attempt",
                    "severity": "high",
                    "source_ip": source_ip,
                    "event_count": len(window),
                    "window_start": window[0]["timestamp_text"],
                    "window_end": window[-1]["timestamp_text"],
                    "description": (
                        f"IP address {source_ip} generated {len(window)} failed SSH "
                        f"logins within {window_minutes:g} minutes."
                    ),
                    "recommendation": (
                        "Review the failed logins, verify whether the source IP is "
                        "expected, and block or restrict it if the activity is malicious."
                    ),
                }
            )
    return alerts


def detect_password_spraying(
    connection: sqlite3.Connection,
    username_threshold: int = 3,
    window_minutes: int | float = 10,
) -> list[Alert]:
    """Return alerts for an IP failing against many users inside one window."""
    _validate_threshold(username_threshold)
    validate_window_minutes(window_minutes)
    failed_events = [
        event for event in _load_events(connection)
        if event["event_type"] == "failed_password"
    ]

    alerts: list[Alert] = []
    for source_ip, events in sorted(_group_by_ip(failed_events).items()):
        windows = _find_windows(
            events,
            username_threshold,
            window_minutes,
            _distinct_user_qualifies(username_threshold),
        )
        for window in windows:
            distinct_count = len({event["username"] for event in window})
            alerts.append(
                {
                    "alert_type": "password_spraying",
                    "title": "Possible SSH password spraying",
                    "severity": "high",
                    "source_ip": source_ip,
                    "event_count": len(window),
                    "distinct_username_count": distinct_count,
                    "window_start": window[0]["timestamp_text"],
                    "window_end": window[-1]["timestamp_text"],
                    "description": (
                        f"IP address {source_ip} generated {len(window)} failed SSH "
                        f"logins across {distinct_count} users within "
                        f"{window_minutes:g} minutes."
                    ),
                    "recommendation": (
                        "Review the targeted accounts, restrict the source IP if it is "
                        "untrusted, and check whether any targeted account was accessed."
                    ),
                }
            )
    return alerts


def detect_successful_login_after_failures(
    connection: sqlite3.Connection,
    failure_threshold: int = 3,
    window_minutes: int | float = 15,
) -> list[Alert]:
    """Return alerts when a success follows failures from the same IP in time."""
    _validate_threshold(failure_threshold)
    validate_window_minutes(window_minutes)
    maximum_span = timedelta(minutes=window_minutes)
    alerts: list[Alert] = []

    for source_ip, events in sorted(_group_by_ip(_load_events(connection)).items()):
        failures: deque[DetectionEvent] = deque()
        for event in events:
            while (
                failures
                and event["timestamp"] - failures[0]["timestamp"] > maximum_span
            ):
                failures.popleft()

            if event["event_type"] == "failed_password":
                failures.append(event)
                continue

            if (
                event["event_type"] == "accepted_password"
                and len(failures) >= failure_threshold
            ):
                alerts.append(
                    {
                        "alert_type": "successful_login_after_failures",
                        "title": "Successful SSH login after repeated failures",
                        "severity": "critical",
                        "source_ip": source_ip,
                        "event_count": len(failures),
                        "username": event["username"],
                        "window_start": failures[0]["timestamp_text"],
                        "window_end": event["timestamp_text"],
                        "successful_login_timestamp": event["timestamp_text"],
                        "description": (
                            f"IP address {source_ip} logged in as {event['username']} "
                            f"after {len(failures)} failures within "
                            f"{window_minutes:g} minutes."
                        ),
                        "recommendation": (
                            "Confirm the login with the account owner, review the "
                            "session, and reset credentials if access was unauthorized."
                        ),
                    }
                )
                failures.clear()
    return alerts


def detect_invalid_user_enumeration(
    connection: sqlite3.Connection,
    username_threshold: int = 3,
    window_minutes: int | float = 10,
) -> list[Alert]:
    """Return alerts for structured invalid-user probes inside one window."""
    _validate_threshold(username_threshold)
    validate_window_minutes(window_minutes)
    invalid_events = [
        event for event in _load_events(connection)
        if event["event_type"] == "failed_password" and event["is_invalid_user"]
    ]

    alerts: list[Alert] = []
    for source_ip, events in sorted(_group_by_ip(invalid_events).items()):
        windows = _find_windows(
            events,
            username_threshold,
            window_minutes,
            _distinct_user_qualifies(username_threshold),
        )
        for window in windows:
            distinct_count = len({event["username"] for event in window})
            alerts.append(
                {
                    "alert_type": "invalid_user_enumeration",
                    "title": "Possible SSH invalid-user enumeration",
                    "severity": "medium",
                    "source_ip": source_ip,
                    "event_count": len(window),
                    "distinct_username_count": distinct_count,
                    "window_start": window[0]["timestamp_text"],
                    "window_end": window[-1]["timestamp_text"],
                    "description": (
                        f"IP address {source_ip} tried {distinct_count} invalid users "
                        f"in {len(window)} failed logins within "
                        f"{window_minutes:g} minutes."
                    ),
                    "recommendation": (
                        "Review the source, restrict SSH exposure, and block or "
                        "rate-limit the IP if the probing is unauthorized."
                    ),
                }
            )
    return alerts
