"""
Suspicious Login Detection
CNC211 - Assignment 2

Detects accounts with 3 or more consecutive FAILED login attempts whose
first and last attempt in that run are at most 5 minutes apart.
A SUCCESS resets the run; a new FAILED streak starts counting from zero.
"""

import csv
import sys
from collections import defaultdict
from datetime import datetime, timedelta

TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"
FAILED_THRESHOLD = 3
TIME_WINDOW = timedelta(minutes=5)


def load_events(path):
    """Read the log file and group (timestamp, status) events by username."""
    events_by_user = defaultdict(list)
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            username = row["username"].strip()
            timestamp = datetime.strptime(row["timestamp"].strip(), TIMESTAMP_FORMAT)
            status = row["status"].strip().upper()
            events_by_user[username].append((timestamp, status))
    return events_by_user


def find_suspicious_runs(events):
    """
    Given a single user's list of (timestamp, status) events (any order),
    return every consecutive FAILED run that meets the alert condition:
    length >= FAILED_THRESHOLD and (last - first) <= TIME_WINDOW.
    """
    ordered = sorted(events, key=lambda e: e[0])

    alerts = []
    run = []

    def check_and_flush():
        if len(run) >= FAILED_THRESHOLD and (run[-1] - run[0]) <= TIME_WINDOW:
            alerts.append((len(run), run[0], run[-1]))
        run.clear()

    for timestamp, status in ordered:
        if status == "FAILED":
            run.append(timestamp)
        else:  # SUCCESS ends the current run
            check_and_flush()
    check_and_flush()  # flush a run that reaches the end of the log

    return alerts


def detect_suspicious_logins(path):
    events_by_user = load_events(path)
    report = {}
    for username, events in events_by_user.items():
        alerts = find_suspicious_runs(events)
        if alerts:
            report[username] = alerts
    return report


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "login.txt"
    report = detect_suspicious_logins(path)

    if not report:
        print("No suspicious login activity detected.")
        return

    print("Suspicious login activity detected:\n")
    for username in sorted(report):
        for count, start, end in report[username]:
            print(
                f"- {username}: {count} failed attempts between "
                f"{start} and {end}"
            )


if __name__ == "__main__":
    main()
