"""Algorithm B: brute-force comparison for suspicious login detection."""
from datetime import timedelta

FAILED_THRESHOLD = 3
TIME_WINDOW = timedelta(minutes=5)


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
