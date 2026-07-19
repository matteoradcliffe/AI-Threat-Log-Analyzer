"""Unit tests for normalized SSH authentication log parsing."""

import sys
import unittest
from pathlib import Path


SRC_DIRECTORY = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(SRC_DIRECTORY))

from parser import parse_auth_log_line  # noqa: E402


def auth_line(timestamp: str = "Jul 11 09:15:01", invalid: bool = False) -> str:
    """Build a supported test log line."""
    user_text = "invalid user alice" if invalid else "alice"
    return (
        f"{timestamp} webserver sshd[1201]: Failed password for {user_text} "
        "from 203.0.113.42 port 51124 ssh2"
    )


class ParseAuthLogLineTests(unittest.TestCase):
    """Verify timestamp normalization and structured parser fields."""

    def test_standard_timestamp(self) -> None:
        event = parse_auth_log_line(auth_line(), default_year=2026)
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event["timestamp"], "Jul 11 09:15:01")
        self.assertEqual(event["event_timestamp"], "2026-07-11T09:15:01")

    def test_single_digit_day(self) -> None:
        event = parse_auth_log_line(auth_line("Jul 2 09:15:01"))
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event["event_timestamp"], "2026-07-02T09:15:01")

    def test_configurable_year(self) -> None:
        event = parse_auth_log_line(auth_line(), default_year=2024)
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event["event_timestamp"], "2024-07-11T09:15:01")

    def test_malformed_timestamp(self) -> None:
        self.assertIsNone(parse_auth_log_line(auth_line("Feb 30 09:15:01")))

    def test_invalid_user_field(self) -> None:
        event = parse_auth_log_line(auth_line(invalid=True))
        self.assertIsNotNone(event)
        assert event is not None
        self.assertTrue(event["is_invalid_user"])
        self.assertEqual(event["username"], "alice")

    def test_regular_user_is_not_invalid(self) -> None:
        event = parse_auth_log_line(auth_line())
        self.assertIsNotNone(event)
        assert event is not None
        self.assertFalse(event["is_invalid_user"])

    def test_successful_login_and_evidence(self) -> None:
        line = (
            "Jul 11 09:20:12 webserver sshd[1210]: Accepted password for bob "
            "from 192.0.2.25 port 55331 ssh2"
        )
        event = parse_auth_log_line(line)
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event["event_type"], "accepted_password")
        self.assertEqual(event["raw_message"], line)

    def test_unsupported_line(self) -> None:
        line = "Jul 11 09:22:00 webserver sudo: bob opened a root session"
        self.assertIsNone(parse_auth_log_line(line))


if __name__ == "__main__":
    unittest.main()
