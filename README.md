# AI Threat Log Analyzer

An AI-assisted security investigation tool that analyzes Linux log files, detects suspicious activity, stores security events in SQL, and generates plain-English threat summaries.

## Overview

The goal of this project is to combine cybersecurity, software engineering, artificial intelligence, and backend development into a practical defensive security tool. The application ingests Linux log files, extracts relevant security events, stores structured data in a SQL database, identifies potentially malicious behavior through detection rules, and uses AI to summarize findings for analysts.

This project is designed to strengthen skills in Linux, Python, SQL, backend development, and defensive cybersecurity while exploring how AI can improve security analysis.

## Features (Planned)

* Parse Linux authentication and system log files
* Store structured security events in a SQL database
* Detect suspicious behavior using rule-based analysis
* Generate AI-assisted threat summaries
* Provide a REST API for querying logs and alerts
* Build a command-line interface for security investigations
* Expand to a web dashboard in future versions
* Docker support for simplified deployment

## Technologies

### Programming Languages

* Python
* SQL
* Bash

### Frameworks & Libraries

* Flask
* SQLite (PostgreSQL planned)
* Pandas
* Requests

### Security

* Linux
* SSH Logs
* Authentication Logs
* Log Analysis
* Detection Engineering

### AI

* Large Language Models
* Natural Language Threat Summaries

### Development Tools

* Git
* GitHub
* Docker (planned)

## Project Structure

```text
ai-threat-analyzer/
├── src/
├── data/
├── docs/
├── tests/
├── README.md
└── requirements.txt
```

## Learning Goals

This project focuses on developing practical experience with:

* Linux system administration
* SQL database design
* Cybersecurity log analysis
* Detection engineering
* Backend API development
* AI-assisted security workflows
* Secure software development
* Version control using Git

## Roadmap

### Phase 1

* Build the project structure
* Parse Linux log files
* Store logs in SQLite

### Phase 2

* Create detection rules
* Generate security alerts

### Phase 3

* Add AI-generated threat explanations

### Phase 4

* Build a Flask REST API

### Phase 5

* Develop a command-line interface

### Phase 6

* Add a web dashboard and Docker support

## Milestone 5: Time-windowed SSH detection

Authentication events keep the original syslog timestamp as evidence and also
store an ISO 8601 `event_timestamp`. Because the supported Linux log format does
not include a year, the parser uses an explicit, configurable year. The bundled
sample data defaults to `2026`; it does not depend on the computer's current year.

The four rules use these default sliding windows:

* SSH brute force: 3 failures within 5 minutes
* Password spraying: 3 distinct usernames within 10 minutes
* Successful login after failures: 3 failures followed by a success within 15 minutes
* Invalid-user enumeration: 3 distinct invalid usernames within 10 minutes

Each rule accepts a custom threshold and `window_minutes`. Events are ordered by
`event_timestamp`, with SQLite row ID used only when timestamps are equal. The
window moves through all normalized history, so later clusters are detected
without combining unrelated events spread across time.

Existing databases are migrated in place. Old rows are preserved, and their
structured invalid-user flag is populated during migration. A legacy row whose
year is unknown keeps a null `event_timestamp` and is skipped by time-based
rules. Reprocessing its source entry safely fills the timestamp without creating
a duplicate.

Alerts store `window_start` and `window_end`; successful-login alerts also store
`successful_login_timestamp`. Duplicate identity uses the rule type, source IP,
and exact window boundaries. The same data does not duplicate an alert, while a
later window from the same IP can create a separate alert.

### Run

From the repository root:

```powershell
python src/main.py
python -m unittest discover -s tests -v
```

### Remaining limitations

* Only the current OpenSSH password-login line format is supported.
* Legacy rows cannot be time-windowed until reprocessed with a known year.
* Timestamps are naive server-local times because the source has no timezone.
* Overlapping rules can produce multiple legitimate alerts for the same activity.
* Matches are deterministic non-overlapping clusters per rule and source IP.

## Status

🚧 Currently under development.
