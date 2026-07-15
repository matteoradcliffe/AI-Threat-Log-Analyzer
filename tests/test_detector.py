"""Unit tests for SSH brute-force detection."""

import sys
import tempfile
import unittest
from pathlib import Path


SRC_DIRECTORY = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(SRC_DIRECTORY))

from database import (  # noqa: E402
    create_auth_events_table,
    insert_auth_events,
    open_database,
)
from detector import detect_ssh_brute_force  # noqa: E402
from parser import AuthEvent  # noqa: E402


def make_event(number: int, ip_address: str, event_type: str) -> AuthEvent:
    """Build a distinct authentication event for a detector test."""
    return {
        "timestamp": f"Jul 11 09:15:{number:02d}",
        "username": "testuser",
        "ip_address": ip_address,
        "event_type": event_type,
        "raw_message": f"fake authentication message {number} from {ip_address}",
    }


class BruteForceDetectorTests(unittest.TestCase):
    """Verify SQL-based failed-login counting behavior."""

    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        database_path = Path(self.temporary_directory.name) / "detector.db"
        self.connection = open_database(database_path)
        create_auth_events_table(self.connection)

    def tearDown(self) -> None:
        self.connection.close()
        self.temporary_directory.cleanup()

    def test_three_failed_logins_create_alert(self) -> None:
        events = [
            make_event(number, "203.0.113.42", "failed_password")
            for number in range(1, 4)
        ]
        insert_auth_events(self.connection, events)

        alerts = detect_ssh_brute_force(self.connection)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["source_ip"], "203.0.113.42")
        self.assertEqual(alerts[0]["event_count"], 3)

    def test_fewer_than_three_failed_logins_do_not_create_alert(self) -> None:
        events = [
            make_event(number, "203.0.113.42", "failed_password")
            for number in range(1, 3)
        ]
        insert_auth_events(self.connection, events)

        self.assertEqual(detect_ssh_brute_force(self.connection), [])

    def test_successful_logins_are_not_counted(self) -> None:
        events = [
            make_event(1, "203.0.113.42", "failed_password"),
            make_event(2, "203.0.113.42", "failed_password"),
            make_event(3, "203.0.113.42", "accepted_password"),
        ]
        insert_auth_events(self.connection, events)

        self.assertEqual(detect_ssh_brute_force(self.connection), [])

    def test_failed_attempts_from_ips_are_counted_separately(self) -> None:
        events = [
            make_event(number, "203.0.113.42", "failed_password")
            for number in range(1, 4)
        ]
        events.extend(
            make_event(number, "198.51.100.77", "failed_password")
            for number in range(4, 7)
        )
        insert_auth_events(self.connection, events)

        alerts = detect_ssh_brute_force(self.connection)

        self.assertEqual(len(alerts), 2)
        self.assertEqual(
            {alert["source_ip"] for alert in alerts},
            {"203.0.113.42", "198.51.100.77"},
        )

    def test_custom_threshold(self) -> None:
        events = [
            make_event(number, "203.0.113.42", "failed_password")
            for number in range(1, 5)
        ]
        insert_auth_events(self.connection, events)

        below_threshold = detect_ssh_brute_force(self.connection, threshold=5)
        at_threshold = detect_ssh_brute_force(self.connection, threshold=4)

        self.assertEqual(below_threshold, [])
        self.assertEqual(len(at_threshold), 1)
        self.assertEqual(at_threshold[0]["event_count"], 4)


if __name__ == "__main__":
    unittest.main()
