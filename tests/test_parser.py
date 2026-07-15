"""Unit tests for the SSH authentication log parser."""

import sys
import unittest
from pathlib import Path


# Allow unittest discovery from the repository root without packaging src yet.
SRC_DIRECTORY = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(SRC_DIRECTORY))

from parser import parse_auth_log_line  # noqa: E402


class ParseAuthLogLineTests(unittest.TestCase):
    """Verify supported and unsupported authentication log messages."""

    def test_failed_login(self) -> None:
        line = (
            "Jul 11 09:15:01 webserver sshd[1201]: Failed password for alice "
            "from 203.0.113.42 port 51124 ssh2"
        )

        event = parse_auth_log_line(line)

        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event["event_type"], "failed_password")
        self.assertEqual(event["username"], "alice")
        self.assertEqual(event["ip_address"], "203.0.113.42")

    def test_invalid_user_login(self) -> None:
        line = (
            "Jul 11 09:18:44 webserver sshd[1205]: Failed password for invalid "
            "user administrator from 198.51.100.77 port 40211 ssh2"
        )

        event = parse_auth_log_line(line)

        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event["username"], "administrator")
        self.assertEqual(event["event_type"], "failed_password")

    def test_successful_login(self) -> None:
        line = (
            "Jul 11 09:20:12 webserver sshd[1210]: Accepted password for bob "
            "from 192.0.2.25 port 55331 ssh2"
        )

        event = parse_auth_log_line(line)

        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event["event_type"], "accepted_password")
        self.assertEqual(event["timestamp"], "Jul 11 09:20:12")
        self.assertEqual(event["raw_message"], line)

    def test_unsupported_line(self) -> None:
        line = "Jul 11 09:22:00 webserver sudo: bob opened a root session"

        self.assertIsNone(parse_auth_log_line(line))


if __name__ == "__main__":
    unittest.main()
