"""Unit tests for SQLite authentication event storage."""

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


FIRST_EVENT: AuthEvent = {
    "timestamp": "Jul 11 09:15:01",
    "username": "alice",
    "ip_address": "203.0.113.42",
    "event_type": "failed_password",
    "raw_message": "first fake SSH authentication message",
}

SECOND_EVENT: AuthEvent = {
    "timestamp": "Jul 11 09:20:12",
    "username": "bob",
    "ip_address": "192.0.2.25",
    "event_type": "accepted_password",
    "raw_message": "second fake SSH authentication message",
}

BRUTE_FORCE_ALERT: Alert = {
    "alert_type": "ssh_brute_force",
    "title": "Possible SSH brute-force attempt",
    "severity": "high",
    "source_ip": "203.0.113.42",
    "event_count": 3,
    "description": "Three failed SSH login attempts were detected.",
    "recommendation": "Review the source IP and block it if malicious.",
}

PASSWORD_SPRAYING_ALERT: Alert = {
    "alert_type": "password_spraying",
    "title": "Possible SSH password spraying",
    "severity": "high",
    "source_ip": "192.0.2.10",
    "event_count": 3,
    "distinct_username_count": 3,
    "description": "Three usernames were targeted.",
    "recommendation": "Review the targeted accounts.",
}


class DatabaseTests(unittest.TestCase):
    """Verify table creation, inserts, retrieval, and duplicate prevention."""

    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        database_path = Path(self.temporary_directory.name) / "test.db"
        self.connection = open_database(database_path)

    def tearDown(self) -> None:
        self.connection.close()
        self.temporary_directory.cleanup()

    def test_create_auth_events_table(self) -> None:
        create_auth_events_table(self.connection)

        row = self.connection.execute(
            "SELECT name FROM sqlite_master WHERE type = ? AND name = ?",
            ("table", "auth_events"),
        ).fetchone()

        self.assertEqual(row, ("auth_events",))

    def test_insert_one_event(self) -> None:
        create_auth_events_table(self.connection)

        inserted = insert_auth_event(self.connection, FIRST_EVENT)

        self.assertTrue(inserted)
        self.assertEqual(len(get_all_auth_events(self.connection)), 1)

    def test_insert_multiple_events(self) -> None:
        create_auth_events_table(self.connection)

        inserted_count = insert_auth_events(
            self.connection, [FIRST_EVENT, SECOND_EVENT]
        )

        self.assertEqual(inserted_count, 2)

    def test_retrieve_stored_events(self) -> None:
        create_auth_events_table(self.connection)
        insert_auth_events(self.connection, [FIRST_EVENT, SECOND_EVENT])

        stored_events = get_all_auth_events(self.connection)

        self.assertEqual(stored_events[0]["id"], 1)
        self.assertEqual(stored_events[0]["username"], "alice")
        self.assertEqual(stored_events[1]["event_type"], "accepted_password")

    def test_duplicate_event_is_not_inserted(self) -> None:
        create_auth_events_table(self.connection)
        first_insert = insert_auth_event(self.connection, FIRST_EVENT)

        duplicate_insert = insert_auth_event(self.connection, FIRST_EVENT)

        self.assertTrue(first_insert)
        self.assertFalse(duplicate_insert)
        self.assertEqual(len(get_all_auth_events(self.connection)), 1)

    def test_create_alerts_table(self) -> None:
        create_alerts_table(self.connection)

        row = self.connection.execute(
            "SELECT name FROM sqlite_master WHERE type = ? AND name = ?",
            ("table", "alerts"),
        ).fetchone()

        self.assertEqual(row, ("alerts",))

        columns = {
            row[1]
            for row in self.connection.execute("PRAGMA table_info(alerts)").fetchall()
        }
        self.assertIn("distinct_username_count", columns)
        self.assertIn("username", columns)

    def test_insert_and_retrieve_alerts(self) -> None:
        create_alerts_table(self.connection)

        inserted_count = insert_alerts(self.connection, [BRUTE_FORCE_ALERT])
        stored_alerts = get_all_alerts(self.connection)

        self.assertEqual(inserted_count, 1)
        self.assertEqual(stored_alerts[0]["id"], 1)
        self.assertEqual(stored_alerts[0]["source_ip"], "203.0.113.42")
        self.assertEqual(stored_alerts[0]["event_count"], 3)
        self.assertTrue(stored_alerts[0]["created_at"])

    def test_duplicate_alert_is_not_inserted(self) -> None:
        create_alerts_table(self.connection)
        first_insert = insert_alert(self.connection, BRUTE_FORCE_ALERT)

        duplicate_insert = insert_alert(self.connection, BRUTE_FORCE_ALERT)

        self.assertTrue(first_insert)
        self.assertFalse(duplicate_insert)
        self.assertEqual(len(get_all_alerts(self.connection)), 1)

    def test_additional_alert_fields_are_stored(self) -> None:
        create_alerts_table(self.connection)

        insert_alert(self.connection, PASSWORD_SPRAYING_ALERT)
        stored_alert = get_all_alerts(self.connection)[0]

        self.assertEqual(stored_alert["distinct_username_count"], 3)
        self.assertIsNone(stored_alert["username"])

    def test_second_batch_does_not_add_duplicate_alerts(self) -> None:
        create_alerts_table(self.connection)

        first_count = insert_alerts(
            self.connection, [BRUTE_FORCE_ALERT, PASSWORD_SPRAYING_ALERT]
        )
        second_count = insert_alerts(
            self.connection, [BRUTE_FORCE_ALERT, PASSWORD_SPRAYING_ALERT]
        )

        self.assertEqual(first_count, 2)
        self.assertEqual(second_count, 0)
        self.assertEqual(len(get_all_alerts(self.connection)), 2)

    def test_existing_alerts_table_is_upgraded(self) -> None:
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

        create_alerts_table(self.connection)

        columns = {
            row[1]
            for row in self.connection.execute("PRAGMA table_info(alerts)").fetchall()
        }
        self.assertIn("distinct_username_count", columns)
        self.assertIn("username", columns)


if __name__ == "__main__":
    unittest.main()
