"""Detection rules for suspicious authentication activity."""

import sqlite3

from database import Alert


def _validate_threshold(threshold: int) -> None:
    """Reject thresholds that cannot represent a useful event count."""
    if threshold < 1:
        raise ValueError("threshold must be at least 1")


def detect_ssh_brute_force(
    connection: sqlite3.Connection, threshold: int = 3
) -> list[Alert]:
    """Return alerts for IPs with at least ``threshold`` failed logins."""
    _validate_threshold(threshold)

    # SQLite performs the filtering, grouping, counting, and threshold check.
    cursor = connection.execute(
        """
        SELECT ip_address, COUNT(*) AS failed_attempt_count
        FROM auth_events
        WHERE event_type = ?
        GROUP BY ip_address
        HAVING COUNT(*) >= ?
        ORDER BY ip_address
        """,
        ("failed_password", threshold),
    )

    alerts: list[Alert] = []
    for source_ip, failed_attempt_count in cursor.fetchall():
        alerts.append(
            {
                "alert_type": "ssh_brute_force",
                "title": "Possible SSH brute-force attempt",
                "severity": "high",
                "source_ip": source_ip,
                "event_count": failed_attempt_count,
                "description": (
                    f"IP address {source_ip} generated {failed_attempt_count} "
                    "failed SSH login attempts."
                ),
                "recommendation": (
                    "Review the failed logins, verify whether the source IP is "
                    "expected, and block or restrict it if the activity is malicious."
                ),
            }
        )

    return alerts


def detect_password_spraying(
    connection: sqlite3.Connection, username_threshold: int = 3
) -> list[Alert]:
    """Return alerts for IPs failing against many distinct usernames."""
    _validate_threshold(username_threshold)

    cursor = connection.execute(
        """
        SELECT ip_address, COUNT(*) AS failed_attempt_count,
               COUNT(DISTINCT username) AS distinct_username_count
        FROM auth_events
        WHERE event_type = ?
        GROUP BY ip_address
        HAVING COUNT(DISTINCT username) >= ?
        ORDER BY ip_address
        """,
        ("failed_password", username_threshold),
    )

    alerts: list[Alert] = []
    for source_ip, event_count, distinct_username_count in cursor.fetchall():
        alerts.append(
            {
                "alert_type": "password_spraying",
                "title": "Possible SSH password spraying",
                "severity": "high",
                "source_ip": source_ip,
                "event_count": event_count,
                "distinct_username_count": distinct_username_count,
                "description": (
                    f"IP address {source_ip} generated {event_count} failed SSH "
                    f"logins across {distinct_username_count} distinct usernames."
                ),
                "recommendation": (
                    "Review the targeted accounts, restrict the source IP if it is "
                    "untrusted, and check whether any targeted account was accessed."
                ),
            }
        )

    return alerts


def detect_successful_login_after_failures(
    connection: sqlite3.Connection, failure_threshold: int = 3
) -> list[Alert]:
    """Return alerts when a success follows enough failures from the same IP."""
    _validate_threshold(failure_threshold)

    # Row IDs preserve ingestion order, so only earlier failures are counted.
    cursor = connection.execute(
        """
        SELECT success.ip_address, success.username,
               COUNT(failure.id) AS failed_attempt_count
        FROM auth_events AS success
        JOIN auth_events AS failure
          ON failure.ip_address = success.ip_address
         AND failure.id < success.id
         AND failure.event_type = ?
        WHERE success.event_type = ?
        GROUP BY success.id, success.ip_address, success.username
        HAVING COUNT(failure.id) >= ?
        ORDER BY success.id
        """,
        ("failed_password", "accepted_password", failure_threshold),
    )

    alerts: list[Alert] = []
    for source_ip, username, event_count in cursor.fetchall():
        alerts.append(
            {
                "alert_type": "successful_login_after_failures",
                "title": "Successful SSH login after repeated failures",
                "severity": "critical",
                "source_ip": source_ip,
                "event_count": event_count,
                "username": username,
                "description": (
                    f"IP address {source_ip} successfully logged in as {username} "
                    f"after {event_count} earlier failed SSH login attempts."
                ),
                "recommendation": (
                    "Confirm the login with the account owner, review the session, "
                    "and reset credentials if the access was not authorized."
                ),
            }
        )

    return alerts


def detect_invalid_user_enumeration(
    connection: sqlite3.Connection, username_threshold: int = 3
) -> list[Alert]:
    """Return alerts for IPs probing many distinct invalid usernames."""
    _validate_threshold(username_threshold)

    cursor = connection.execute(
        """
        SELECT ip_address, COUNT(*) AS failed_attempt_count,
               COUNT(DISTINCT username) AS distinct_username_count
        FROM auth_events
        WHERE event_type = ?
          AND raw_message LIKE ?
        GROUP BY ip_address
        HAVING COUNT(DISTINCT username) >= ?
        ORDER BY ip_address
        """,
        ("failed_password", "%Failed password for invalid user %", username_threshold),
    )

    alerts: list[Alert] = []
    for source_ip, event_count, distinct_username_count in cursor.fetchall():
        alerts.append(
            {
                "alert_type": "invalid_user_enumeration",
                "title": "Possible SSH invalid-user enumeration",
                "severity": "medium",
                "source_ip": source_ip,
                "event_count": event_count,
                "distinct_username_count": distinct_username_count,
                "description": (
                    f"IP address {source_ip} tried {distinct_username_count} "
                    f"distinct invalid usernames in {event_count} failed SSH logins."
                ),
                "recommendation": (
                    "Review the source, restrict SSH exposure, and block or rate-limit "
                    "the IP if the probing is unauthorized."
                ),
            }
        )

    return alerts
