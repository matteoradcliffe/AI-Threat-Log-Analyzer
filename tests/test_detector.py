"""Tests for sliding-window SSH authentication detections."""

import sys
import tempfile
import unittest
from datetime import datetime, timedelta
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
    minute: int,
    ip_address: str = "203.0.113.42",
    username: str = "alice",
    event_type: str = "failed_password",
    invalid: bool = False,
    day: int = 11,
) -> AuthEvent:
    """Build an event with independently controlled timestamp and insertion ID."""
    event_time = datetime(2026, 7, day, 9, 0) + timedelta(minutes=minute)
    return {
        "timestamp": event_time.strftime("%b %d %H:%M:%S"),
        "event_timestamp": event_time.isoformat(timespec="seconds"),
        "username": username,
        "ip_address": ip_address,
        "event_type": event_type,
        "is_invalid_user": invalid,
        "raw_message": f"structured event {number}",
    }


class DetectorTestCase(unittest.TestCase):
    """Provide a fresh normalized event database for each detector test."""

    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.connection = open_database(
            Path(self.temporary_directory.name) / "detector.db"
        )
        create_auth_events_table(self.connection)

    def tearDown(self) -> None:
        self.connection.close()
        self.temporary_directory.cleanup()

    def store(self, events: list[AuthEvent]) -> None:
        """Insert test events into the current database."""
        insert_auth_events(self.connection, events)


class BruteForceDetectorTests(DetectorTestCase):
    def test_triggers_inside_window(self) -> None:
        self.store([make_event(i, minute) for i, minute in enumerate([0, 2, 4])])
        alerts = detect_ssh_brute_force(self.connection)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["window_start"], "2026-07-11T09:00:00")
        self.assertEqual(alerts[0]["window_end"], "2026-07-11T09:04:00")

    def test_does_not_trigger_outside_window(self) -> None:
        self.store([make_event(i, minute) for i, minute in enumerate([0, 60, 120])])
        self.assertEqual(detect_ssh_brute_force(self.connection), [])

    def test_finds_later_cluster(self) -> None:
        self.store(
            [make_event(i, minute) for i, minute in enumerate([0, 60, 120, 121, 122])]
        )
        alerts = detect_ssh_brute_force(self.connection)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["window_start"], "2026-07-11T11:00:00")

    def test_custom_threshold(self) -> None:
        self.store([make_event(i, i) for i in range(4)])
        self.assertEqual(
            detect_ssh_brute_force(self.connection, threshold=5), []
        )
        self.assertEqual(
            len(detect_ssh_brute_force(self.connection, threshold=4)), 1
        )

    def test_custom_window(self) -> None:
        self.store([make_event(i, minute) for i, minute in enumerate([0, 5, 10])])
        self.assertEqual(detect_ssh_brute_force(self.connection), [])
        self.assertEqual(
            len(detect_ssh_brute_force(self.connection, window_minutes=10)), 1
        )

    def test_ips_are_evaluated_separately(self) -> None:
        events = [make_event(i, i) for i in range(3)]
        events += [make_event(i + 3, i, ip_address="198.51.100.2") for i in range(2)]
        self.store(events)
        alerts = detect_ssh_brute_force(self.connection)
        self.assertEqual([alert["source_ip"] for alert in alerts], ["203.0.113.42"])


class PasswordSprayingDetectorTests(DetectorTestCase):
    def test_distinct_users_inside_window_trigger(self) -> None:
        self.store(
            [
                make_event(1, 0, username="alice"),
                make_event(2, 4, username="bob"),
                make_event(3, 9, username="carol"),
            ]
        )
        alerts = detect_password_spraying(self.connection)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["distinct_username_count"], 3)

    def test_users_spread_too_far_apart_do_not_combine(self) -> None:
        self.store(
            [
                make_event(1, 0, username="alice"),
                make_event(2, 20, username="bob"),
                make_event(3, 40, username="carol"),
            ]
        )
        self.assertEqual(detect_password_spraying(self.connection), [])

    def test_repeated_username_does_not_count_as_distinct(self) -> None:
        self.store([make_event(i, i, username="alice") for i in range(5)])
        self.assertEqual(detect_password_spraying(self.connection), [])

    def test_custom_threshold_and_window(self) -> None:
        self.store(
            [
                make_event(1, 0, username="alice"),
                make_event(2, 12, username="bob"),
            ]
        )
        self.assertEqual(detect_password_spraying(self.connection), [])
        self.assertEqual(
            len(
                detect_password_spraying(
                    self.connection, username_threshold=2, window_minutes=15
                )
            ),
            1,
        )


class SuccessfulLoginDetectorTests(DetectorTestCase):
    def test_success_after_failures_inside_window_triggers(self) -> None:
        events = [make_event(i, i) for i in range(3)]
        events.append(make_event(4, 4, event_type="accepted_password"))
        self.store(events)
        alerts = detect_successful_login_after_failures(self.connection)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(
            alerts[0]["successful_login_timestamp"], "2026-07-11T09:04:00"
        )

    def test_success_outside_window_does_not_trigger(self) -> None:
        events = [make_event(i, i) for i in range(3)]
        events.append(make_event(4, 20, event_type="accepted_password"))
        self.store(events)
        self.assertEqual(detect_successful_login_after_failures(self.connection), [])

    def test_success_before_failures_does_not_trigger(self) -> None:
        events = [make_event(1, 0, event_type="accepted_password")]
        events += [make_event(i + 2, i + 1) for i in range(3)]
        self.store(events)
        self.assertEqual(detect_successful_login_after_failures(self.connection), [])

    def test_events_must_belong_to_same_ip(self) -> None:
        events = [make_event(i, i) for i in range(3)]
        events.append(
            make_event(
                4, 4, ip_address="198.51.100.2", event_type="accepted_password"
            )
        )
        self.store(events)
        self.assertEqual(detect_successful_login_after_failures(self.connection), [])

    def test_timestamp_order_overrides_insertion_order(self) -> None:
        success = make_event(1, 4, event_type="accepted_password")
        failures = [make_event(i + 2, i) for i in range(3)]
        self.store([success, *failures])
        self.assertEqual(
            len(detect_successful_login_after_failures(self.connection)), 1
        )

    def test_row_id_breaks_equal_timestamp_ties(self) -> None:
        failures = [make_event(i, 0) for i in range(3)]
        success = make_event(4, 0, event_type="accepted_password")
        self.store([*failures, success])
        self.assertEqual(
            len(detect_successful_login_after_failures(self.connection)), 1
        )


class InvalidUserEnumerationTests(DetectorTestCase):
    def test_invalid_users_inside_window_trigger(self) -> None:
        self.store(
            [
                make_event(1, 0, username="guest", invalid=True),
                make_event(2, 4, username="support", invalid=True),
                make_event(3, 9, username="admin", invalid=True),
            ]
        )
        self.assertEqual(
            len(detect_invalid_user_enumeration(self.connection)), 1
        )

    def test_uses_structured_flag_not_raw_message(self) -> None:
        events = [
            make_event(i, i, username=f"fake{i}", invalid=True) for i in range(3)
        ]
        self.assertTrue(all("invalid user" not in event["raw_message"] for event in events))
        self.store(events)
        self.assertEqual(
            len(detect_invalid_user_enumeration(self.connection)), 1
        )

    def test_raw_text_without_structured_flag_does_not_trigger(self) -> None:
        events = [make_event(i, i, username=f"fake{i}") for i in range(3)]
        for event in events:
            event["raw_message"] += " invalid user"
        self.store(events)
        self.assertEqual(detect_invalid_user_enumeration(self.connection), [])

    def test_invalid_users_spread_too_far_apart_do_not_trigger(self) -> None:
        self.store(
            [
                make_event(1, 0, username="guest", invalid=True),
                make_event(2, 20, username="support", invalid=True),
                make_event(3, 40, username="admin", invalid=True),
            ]
        )
        self.assertEqual(detect_invalid_user_enumeration(self.connection), [])

    def test_custom_threshold_and_window(self) -> None:
        self.store(
            [
                make_event(1, 0, username="guest", invalid=True),
                make_event(2, 12, username="support", invalid=True),
            ]
        )
        self.assertEqual(
            len(
                detect_invalid_user_enumeration(
                    self.connection, username_threshold=2, window_minutes=15
                )
            ),
            1,
        )


if __name__ == "__main__":
    unittest.main()
