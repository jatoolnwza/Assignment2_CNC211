import csv
import sys
from collections import defaultdict
from datetime import datetime, timedelta

TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"
FAILED_THRESHOLD = 3
TIME_WINDOW = timedelta(minutes=5)


def load_events(path):
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
    ordered = sorted(events,key=lambda e:e[0])
    alerts = []
    left = 0
    for right in range(len(ordered)):
        timestamp,status = ordered[right]

        if status == "SUCCESS":
            left = right+1
            continue

        while left <= right and (ordered[right][0]-ordered[left][0]) > TIME_WINDOW:
            left += 1

        failed_count = right-left+1

        if failed_count >= FAILED_THRESHOLD:
            alerts.append((failed_count,ordered[left][0],ordered[right][0]))
            left = right+1
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
