import csv
import sys
from collections import defaultdict
from datetime import datetime, timedelta

TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"
FAILED_THRESHOLD = 3
TIME_WINDOW = timedelta(minutes=5)
REQUIRED_COLUMNS = {"timestamp", "username", "status"}


def load_events(path):
    events_by_user = defaultdict(list)

    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames or not REQUIRED_COLUMNS.issubset(reader.fieldnames):
            raise ValueError("CSV must contain timestamp, username, and status columns")

        for line_number, row in enumerate(reader, start=2):
            try:
                username = (row.get("username") or "").strip()
                timestamp_text = (row.get("timestamp") or "").strip()
                status = (row.get("status") or "").strip().upper()
                if not username:
                    raise ValueError("username is empty")
                if status not in {"FAILED", "SUCCESS"}:
                    raise ValueError("status must be FAILED or SUCCESS")
                timestamp = datetime.strptime(timestamp_text, TIMESTAMP_FORMAT)
            except (ValueError, TypeError) as error:
                raise ValueError(f"Invalid CSV data on line {line_number}: {error}") from error
            events_by_user[username].append((timestamp, status))

    return dict(events_by_user)


def find_suspicious_runs(events):
    ordered = sorted(events, key=lambda event: event[0])
    alerts = []
    run = []

    for event in ordered:
        timestamp, status = event
        if status == "FAILED":
            run.append(event)
        else:
            _find_windows(run, alerts)
            run = []

    _find_windows(run, alerts)
    return alerts


def _find_windows(ordered, alerts):
    left = 0
    for right in range(len(ordered)):
        while ordered[right][0] - ordered[left][0] > TIME_WINDOW:
            left += 1

        failed_count = right - left + 1
        is_window_end = (
            right == len(ordered) - 1
            or ordered[right + 1][0] - ordered[left][0] > TIME_WINDOW
        )

        if failed_count >= FAILED_THRESHOLD and is_window_end:
            alerts.append((failed_count, ordered[left][0], ordered[right][0]))


def load_logs(path):
    return load_events(path)


def detect_a(events_by_user):
    report = {}
    for username, events in events_by_user.items():
        alerts = find_suspicious_runs(events)
        if alerts:
            report[username] = alerts
    return report


def detect_suspicious_logins(path):
    events_by_user = load_events(path)
    return detect_a(events_by_user)


def main():
    if len(sys.argv) > 2:
        print("Usage: python detect_a.py [login.txt]", file=sys.stderr)
        return 2

    path = sys.argv[1] if len(sys.argv) > 1 else "login.txt"

    try:
        report = detect_suspicious_logins(path)
    except (OSError, ValueError, csv.Error) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    if not report:
        print("No suspicious login activity detected.")
        return 0

    print("Suspicious login activity detected (requires further review):\n")
    for username in sorted(report):
        for count, start, end in report[username]:
            print(f"- Username: {username} | FAILED: {count} | Period: {start} to {end}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
