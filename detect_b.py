"""Algorithm B: brute-force comparison for suspicious login detection."""
from datetime import timedelta

FAILED_THRESHOLD = 3
TIME_WINDOW = timedelta(minutes=5)


def detect_b(events_by_user):
    """Check every possible start position in each consecutive FAILED run."""
    report = {}
    for username, events in events_by_user.items():
        ordered = sorted(events, key=lambda event: event[0])
        runs = []
        current = []
        for event in ordered:
            if event[1] == "FAILED":
                current.append(event)
            else:
                if current:
                    runs.append(current)
                    current = []
        if current:
            runs.append(current)

        alerts = []
        for run in runs:
            for start in range(len(run)):
                end = start
                while end + 1 < len(run) and run[end + 1][0] - run[start][0] <= TIME_WINDOW:
                    end += 1
                count = end - start + 1
                can_extend_left = (
                    start > 0 and run[end][0] - run[start - 1][0] <= TIME_WINDOW
                )
                if count >= FAILED_THRESHOLD and not can_extend_left:
                    alerts.append((count, run[start][0], run[end][0]))
        if alerts:
            report[username] = alerts
    return report
