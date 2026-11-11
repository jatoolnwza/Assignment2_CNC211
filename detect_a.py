import sys
from datetime import timedelta

from load_logs import load_logs as read_logs

FAILED_THRESHOLD = 3
TIME_WINDOW = timedelta(minutes=5)


def load_events(path):
    user_logs = read_logs(path)
    return {
        username: [(record["timestamp"], record["status"]) for record in records]
        for username, records in user_logs.items()
    }


def find_suspicious_runs(events):
    alerts = []
    run = []

    for event in events:
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
    except (OSError, ValueError) as error:
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
