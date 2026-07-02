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

## Status

🚧 Currently under development.
