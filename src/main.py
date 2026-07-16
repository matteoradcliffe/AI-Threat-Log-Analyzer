"""Parse the sample SSH log and store its events in SQLite."""

import sys
from contextlib import closing
from pathlib import Path

from database import (
    StoredAlert,
    create_alerts_table,
    create_auth_events_table,
    get_all_alerts,
    insert_alerts,
    insert_auth_events,
    open_database,
)
from detector import (
    detect_invalid_user_enumeration,
    detect_password_spraying,
    detect_ssh_brute_force,
    detect_successful_login_after_failures,
)
from parser import AuthEvent, parse_auth_log_line


SAMPLE_LOG_PATH = Path(__file__).resolve().parent.parent / "data" / "sample_auth.log"


def parse_sample_log(log_path: Path = SAMPLE_LOG_PATH) -> list[AuthEvent]:
    """Parse supported events and report the line number of rejected input."""
    events: list[AuthEvent] = []

    # Strict UTF-8 decoding ensures file problems are reported rather than hidden.
    with log_path.open("r", encoding="utf-8", errors="strict") as log_file:
        for line_number, line in enumerate(log_file, start=1):
            event = parse_auth_log_line(line)
            if event is None:
                print(
                    f"Warning: unsupported or malformed log entry on line {line_number}.",
                    file=sys.stderr,
                )
                continue
            events.append(event)

    return events


def print_stored_alert(alert: StoredAlert) -> None:
    """Print one stored security alert in a readable format."""
    print(f"Alert ID:       {alert['id']}")
    print(f"Type:           {alert['alert_type']}")
    print(f"Title:          {alert['title']}")
    print(f"Severity:       {alert['severity']}")
    print(f"Source IP:      {alert['source_ip']}")
    print(f"Related events: {alert['event_count']}")
    if alert.get("distinct_username_count") is not None:
        print(f"Distinct users: {alert['distinct_username_count']}")
    if alert.get("username"):
        print(f"Username:       {alert['username']}")
    print(f"Description:    {alert['description']}")
    print(f"Recommendation: {alert['recommendation']}")
    print(f"Created at:     {alert['created_at']} UTC")
    print("-" * 72)


def main() -> None:
    """Parse events, run detection, store alerts, and display results."""
    parsed_events = parse_sample_log()

    with closing(open_database()) as connection:
        create_auth_events_table(connection)
        create_alerts_table(connection)
        newly_stored_count = insert_auth_events(connection, parsed_events)
        alerts_by_type = {
            "ssh_brute_force": detect_ssh_brute_force(connection),
            "password_spraying": detect_password_spraying(connection),
            "successful_login_after_failures": (
                detect_successful_login_after_failures(connection)
            ),
            "invalid_user_enumeration": detect_invalid_user_enumeration(connection),
        }
        detected_alerts = [
            alert for alerts in alerts_by_type.values() for alert in alerts
        ]
        newly_stored_alert_count = insert_alerts(connection, detected_alerts)
        stored_alerts = get_all_alerts(connection)

    print(f"Parsed events: {len(parsed_events)}")
    print(f"New events inserted: {newly_stored_count}")
    print(f"Alerts detected: {len(detected_alerts)}")
    print(f"New alerts inserted: {newly_stored_alert_count}")
    print("Detected by type:")
    for alert_type, alerts in alerts_by_type.items():
        print(f"  {alert_type}: {len(alerts)}")
    print()

    if not stored_alerts:
        print("No stored alerts.")
    else:
        print("Stored alerts:")
        for alert in stored_alerts:
            print_stored_alert(alert)


if __name__ == "__main__":
    main()
