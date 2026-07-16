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
from detector import (  # noqa: E402
    detect_invalid_user_enumeration,
    detect_password_spraying,
    detect_ssh_brute_force,
    detect_successful_login_after_failures,
)
from parser import AuthEvent  # noqa: E402


def make_event(
    number: int,
    ip_address: str,
    event_type: str,
    username: str = "testuser",
    invalid_user: bool = False,
) -> AuthEvent:
    """Build a distinct authentication event for a detector test."""
    result = "Accepted" if event_type == "accepted_password" else "Failed"
    invalid_text = "invalid user " if invalid_user else ""
    return {
        "timestamp": f"Jul 11 09:15:{number:02d}",
        "username": username,
        "ip_address": ip_address,
        "event_type": event_type,
        "raw_message": (
            f"Jul 11 09:15:{number:02d} test sshd[{number}]: {result} password "
            f"for {invalid_text}{username} from {ip_address} port 22 ssh2"
        ),
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

    def test_password_spraying_targets_distinct_usernames(self) -> None:
        events = [
            make_event(number, "192.0.2.10", "failed_password", username)
            for number, username in enumerate(["alice", "bob", "carol"], start=1)
        ]
        insert_auth_events(self.connection, events)

        alerts = detect_password_spraying(self.connection)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["event_count"], 3)
        self.assertEqual(alerts[0]["distinct_username_count"], 3)

    def test_password_spraying_ignores_repeated_single_username(self) -> None:
        events = [
            make_event(number, "192.0.2.10", "failed_password", "alice")
            for number in range(1, 5)
        ]
        insert_auth_events(self.connection, events)

        self.assertEqual(detect_password_spraying(self.connection), [])

    def test_password_spraying_custom_threshold(self) -> None:
        events = [
            make_event(1, "192.0.2.10", "failed_password", "alice"),
            make_event(2, "192.0.2.10", "failed_password", "bob"),
        ]
        insert_auth_events(self.connection, events)

        self.assertEqual(detect_password_spraying(self.connection), [])
        self.assertEqual(
            len(detect_password_spraying(self.connection, username_threshold=2)),
            1,
        )

    def test_success_after_enough_failures_creates_alert(self) -> None:
        events = [
            make_event(number, "203.0.113.20", "failed_password")
            for number in range(1, 4)
        ]
        events.append(
            make_event(4, "203.0.113.20", "accepted_password", "alice")
        )
        insert_auth_events(self.connection, events)

        alerts = detect_successful_login_after_failures(self.connection)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["event_count"], 3)
        self.assertEqual(alerts[0]["username"], "alice")

    def test_success_before_failures_does_not_create_alert(self) -> None:
        events = [
            make_event(1, "203.0.113.20", "accepted_password", "alice")
        ]
        events.extend(
            make_event(number, "203.0.113.20", "failed_password")
            for number in range(2, 5)
        )
        insert_auth_events(self.connection, events)

        self.assertEqual(
            detect_successful_login_after_failures(self.connection), []
        )

    def test_success_and_failures_from_different_ips_are_not_combined(self) -> None:
        events = [
            make_event(number, "203.0.113.20", "failed_password")
            for number in range(1, 4)
        ]
        events.append(
            make_event(4, "203.0.113.21", "accepted_password", "alice")
        )
        insert_auth_events(self.connection, events)

        self.assertEqual(
            detect_successful_login_after_failures(self.connection), []
        )

    def test_success_after_failures_custom_threshold(self) -> None:
        events = [
            make_event(1, "203.0.113.20", "failed_password"),
            make_event(2, "203.0.113.20", "failed_password"),
            make_event(3, "203.0.113.20", "accepted_password", "alice"),
        ]
        insert_auth_events(self.connection, events)

        self.assertEqual(
            detect_successful_login_after_failures(self.connection), []
        )
        self.assertEqual(
            len(
                detect_successful_login_after_failures(
                    self.connection, failure_threshold=2
                )
            ),
            1,
        )

    def test_invalid_user_enumeration_targets_distinct_invalid_users(self) -> None:
        events = [
            make_event(
                number,
                "198.51.100.30",
                "failed_password",
                username,
                invalid_user=True,
            )
            for number, username in enumerate(["admin", "guest", "support"], start=1)
        ]
        insert_auth_events(self.connection, events)

        alerts = detect_invalid_user_enumeration(self.connection)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["distinct_username_count"], 3)

    def test_invalid_user_enumeration_ignores_valid_user_failures(self) -> None:
        events = [
            make_event(number, "198.51.100.30", "failed_password", username)
            for number, username in enumerate(["alice", "bob", "carol"], start=1)
        ]
        insert_auth_events(self.connection, events)

        self.assertEqual(detect_invalid_user_enumeration(self.connection), [])

    def test_invalid_user_enumeration_ignores_repeated_username(self) -> None:
        events = [
            make_event(
                number,
                "198.51.100.30",
                "failed_password",
                "admin",
                invalid_user=True,
            )
            for number in range(1, 5)
        ]
        insert_auth_events(self.connection, events)

        self.assertEqual(detect_invalid_user_enumeration(self.connection), [])

    def test_invalid_user_enumeration_custom_threshold(self) -> None:
        events = [
            make_event(
                number,
                "198.51.100.30",
                "failed_password",
                username,
                invalid_user=True,
            )
            for number, username in enumerate(["admin", "guest"], start=1)
        ]
        insert_auth_events(self.connection, events)

        self.assertEqual(detect_invalid_user_enumeration(self.connection), [])
        self.assertEqual(
            len(
                detect_invalid_user_enumeration(
                    self.connection, username_threshold=2
                )
            ),
            1,
        )


if __name__ == "__main__":
    unittest.main()
