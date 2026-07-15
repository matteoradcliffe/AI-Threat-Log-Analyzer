"""Detection rules for suspicious authentication activity."""

import sqlite3

from database import Alert


def detect_ssh_brute_force(
    connection: sqlite3.Connection, threshold: int = 3
) -> list[Alert]:
    """Return alerts for IPs with at least ``threshold`` failed logins."""
    if threshold < 1:
        raise ValueError("threshold must be at least 1")

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
