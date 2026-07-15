"""Parse security events from Linux SSH authentication log lines."""

import ipaddress
import re
from typing import TypedDict


class AuthEvent(TypedDict):
    """The structured fields extracted from one supported SSH log entry."""

    timestamp: str
    username: str
    ip_address: str
    event_type: str
    raw_message: str


# Example message portion:
# sshd[1234]: Failed password for invalid user admin from 192.0.2.10 port 22 ssh2
SSH_AUTH_PATTERN = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"\S+\s+sshd\[\d+\]:\s+"
    r"(?P<result>Failed|Accepted) password for "
    r"(?:(?:invalid user)\s+)?(?P<username>\S+)\s+"
    r"from\s+(?P<ip_address>\S+)\s+port\s+\d+\s+ssh2\s*$"
)


def parse_auth_log_line(line: str) -> AuthEvent | None:
    """Convert one auth.log line into an event, or return None if unsupported.

    Only OpenSSH ``Failed password`` and ``Accepted password`` messages are
    supported in this milestone. The original line is retained for auditing.
    """
    raw_message = line.rstrip("\r\n")
    match = SSH_AUTH_PATTERN.fullmatch(raw_message)
    if match is None:
        return None

    ip_address = match.group("ip_address")
    try:
        # Reject text that matches the log shape but is not a valid IPv4/IPv6 address.
        ipaddress.ip_address(ip_address)
    except ValueError:
        return None

    result = match.group("result")
    event_type = "failed_password" if result == "Failed" else "accepted_password"

    return {
        "timestamp": match.group("timestamp"),
        "username": match.group("username"),
        "ip_address": ip_address,
        "event_type": event_type,
        "raw_message": raw_message,
    }
