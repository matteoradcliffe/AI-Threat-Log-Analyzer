"""Tests for normalized event storage and safe SQLite migrations."""

import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path


SRC_DIRECTORY = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(SRC_DIRECTORY))

from database import (  # noqa: E402
    Alert,
    create_alerts_table,
    create_auth_events_table,
    get_all_alerts,
    get_all_auth_events,
    insert_alert,
    insert_alerts,
    insert_auth_event,
    insert_auth_events,
    open_database,
)
from parser import AuthEvent  # noqa: E402


def make_event(number: int = 1, invalid: bool = False) -> AuthEvent:
    """Build one normalized authentication event."""
    return {
        "timestamp": f"Jul 11 09:15:{number:02d}",
        "event_timestamp": f"2026-07-11T09:15:{number:02d}",
        "username": "alice",
        "ip_address": "203.0.113.42",
        "event_type": "failed_password",
        "is_invalid_user": invalid,
        "raw_message": f"fake normalized authentication message {number}",
    }


def make_alert(day: int = 11) -> Alert:
    """Build one window-aware alert."""
    return {
        "alert_type": "ssh_brute_force",
        "title": "Possible SSH brute-force attempt",
        "severity": "high",
        "source_ip": "203.0.113.42",
        "event_count": 3,
        "window_start": f"2026-07-{day:02d}T09:15:01",
        "window_end": f"2026-07-{day:02d}T09:15:03",
        "description": "Three failed SSH login attempts were detected.",
        "recommendation": "Review the source IP.",
    }


class DatabaseTests(unittest.TestCase):
    """Verify storage, migration, and window-based duplicate prevention."""

    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        database_path = Path(self.temporary_directory.name) / "test.db"
        self.connection = open_database(database_path)

    def tearDown(self) -> None:
        self.connection.close()
        self.temporary_directory.cleanup()

    def test_normalized_timestamp_and_invalid_user_storage(self) -> None:
        create_auth_events_table(self.connection)
        insert_auth_event(self.connection, make_event(invalid=True))
        stored = get_all_auth_events(self.connection)[0]
        self.assertEqual(stored["event_timestamp"], "2026-07-11T09:15:01")
        self.assertTrue(stored["is_invalid_user"])

    def test_insert_multiple_and_prevent_duplicate_events(self) -> None:
        create_auth_events_table(self.connection)
        self.assertEqual(
            insert_auth_events(self.connection, [make_event(1), make_event(2)]), 2
        )
        self.assertFalse(insert_auth_event(self.connection, make_event(1)))
        self.assertEqual(len(get_all_auth_events(self.connection)), 2)

    def test_migrate_older_auth_events_table_without_data_loss(self) -> None:
        self.connection.execute(
            """
            CREATE TABLE auth_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                username TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                event_type TEXT NOT NULL,
                raw_message TEXT NOT NULL UNIQUE
            )
            """
        )
        self.connection.execute(
            """
            INSERT INTO auth_events
                (timestamp, username, ip_address, event_type, raw_message)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                "Jul 11 09:15:01",
                "ghost",
                "192.0.2.10",
                "failed_password",
                "Failed password for invalid user ghost",
            ),
        )
        create_auth_events_table(self.connection)
        stored = get_all_auth_events(self.connection)[0]
        self.assertIsNone(stored["event_timestamp"])
        self.assertTrue(stored["is_invalid_user"])
        self.assertEqual(stored["username"], "ghost")

    def test_reingestion_backfills_legacy_timestamp(self) -> None:
        create_auth_events_table(self.connection)
        event = make_event()
        self.connection.execute(
            """
            INSERT INTO auth_events
                (timestamp, username, ip_address, event_type, raw_message)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                event["timestamp"],
                event["username"],
                event["ip_address"],
                event["event_type"],
                event["raw_message"],
            ),
        )
        self.assertFalse(insert_auth_event(self.connection, event))
        self.assertEqual(
            get_all_auth_events(self.connection)[0]["event_timestamp"],
            event["event_timestamp"],
        )

    def test_alert_time_fields_are_stored(self) -> None:
        create_alerts_table(self.connection)
        insert_alerts(self.connection, [make_alert()])
        stored = get_all_alerts(self.connection)[0]
        self.assertEqual(stored["window_start"], "2026-07-11T09:15:01")
        self.assertEqual(stored["window_end"], "2026-07-11T09:15:03")

    def test_duplicate_alert_for_same_window_is_prevented(self) -> None:
        create_alerts_table(self.connection)
        alert = make_alert()
        self.assertTrue(insert_alert(self.connection, alert))
        self.assertFalse(insert_alert(self.connection, alert))

    def test_separate_windows_create_separate_alerts(self) -> None:
        create_alerts_table(self.connection)
        self.assertTrue(insert_alert(self.connection, make_alert(11)))
        self.assertTrue(insert_alert(self.connection, make_alert(12)))
        self.assertEqual(len(get_all_alerts(self.connection)), 2)

    def test_migrate_old_alert_constraint_and_preserve_rows(self) -> None:
        self.connection.execute(
            """
            CREATE TABLE alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_type TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                event_count INTEGER NOT NULL,
                description TEXT NOT NULL,
                recommendation TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (alert_type, source_ip, event_count)
            )
            """
        )
        self.connection.execute(
            """
            INSERT INTO alerts (
                alert_type, title, severity, source_ip, event_count,
                description, recommendation
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            ("legacy", "Legacy", "low", "192.0.2.1", 3, "Old row", "Review"),
        )
        create_alerts_table(self.connection)
        self.assertEqual(len(get_all_alerts(self.connection)), 1)
        self.assertTrue(insert_alert(self.connection, make_alert(11)))
        self.assertTrue(insert_alert(self.connection, make_alert(12)))


if __name__ == "__main__":
    unittest.main()
