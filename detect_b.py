"""Algorithm B: brute-force comparison for suspicious login detection."""
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


def load_logs(path):
    return load_events(path)


def detect_b(events_by_user):
    """Check every (start, end) pair of FAILED events directly with a
    nested loop, instead of maintaining a two-pointer window like Algorithm A."""
    report = {}
    for username, events in events_by_user.items():
        ordered = sorted(events, key=lambda event: event[0])
        n = len(ordered)
        alerts = []

        for start in range(n):
            if ordered[start][1] != "FAILED":
                continue

            for end in range(start, n):
                if ordered[end][1] != "FAILED":
                    break
                if ordered[end][0] - ordered[start][0] > TIME_WINDOW:
                    break

                count = end - start + 1
                is_leftmost = (
                    start == 0
                    or ordered[start - 1][1] != "FAILED"
                    or ordered[end][0] - ordered[start - 1][0] > TIME_WINDOW
                )
                is_rightmost = (
                    end == n - 1
                    or ordered[end + 1][1] != "FAILED"
                    or ordered[end + 1][0] - ordered[start][0] > TIME_WINDOW
                )

                if count >= FAILED_THRESHOLD and is_leftmost and is_rightmost:
                    alerts.append((count, ordered[start][0], ordered[end][0]))

        if alerts:
            report[username] = alerts
    return report


def detect_suspicious_logins(path):
    events_by_user = load_events(path)
    return detect_b(events_by_user)


def main():
    if len(sys.argv) > 2:
        print("Usage: python detect_b.py [login.txt]", file=sys.stderr)
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
