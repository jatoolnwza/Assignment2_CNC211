"""
detect_b.py - Algorithm B (Brute Force) for Suspicious Login Detection
CNC211 - Assignment 2 (person 3's part)

This is the comparison algorithm against Algorithm A (sliding-window,
two-pointer on pre-sorted data). It deliberately uses a brute-force
strategy so the two can be benchmarked against each other:

    - For every FAILED event, treat it as a possible run start and scan
      forward counting consecutive FAILED events within the 5-minute
      window. This re-scans overlapping sub-ranges for every FAILED
      index in a run (not just the true start), so the work done is
      O(n^2) in the worst case (e.g. a long stretch of FAILED events),
      even though only genuine run starts are reported as alerts.

Input contract (matches load_logs()'s expected output):
    events_by_user: dict[str, list[tuple[datetime, str]]]
        Maps a username to its list of (timestamp, status) events.
        status is either "FAILED" or "SUCCESS". Events for a user do
        NOT need to be pre-sorted; this module sorts them itself.

Output contract (matches detect_a()'s expected output, so results can
be diffed directly for testing/benchmarking):
    dict[str, list[tuple[int, datetime, datetime]]]
        Maps a username to a list of (failed_count, start_time, end_time)
        alerts, one per maximal consecutive-FAILED run that has
        failed_count >= FAILED_THRESHOLD and (end_time - start_time) <=
        TIME_WINDOW. Only usernames with at least one alert are included.
"""

from datetime import timedelta

FAILED_THRESHOLD = 3
TIME_WINDOW = timedelta(minutes=5)


def detect_b(events_by_user):
    """Brute-force O(n^2) detection of suspicious consecutive FAILED runs."""
    report = {}

    for username, events in events_by_user.items():
        ordered = sorted(events, key=lambda e: e[0])
        n = len(ordered)
        alerts = []

        for i in range(n):
            start_time, start_status = ordered[i]
            if start_status != "FAILED":
                continue

            # Brute force: re-scan forward from every FAILED index, even
            # ones in the middle of a run, instead of jumping straight
            # to run boundaries like the sliding-window algorithm does.
            count = 0
            last_time = start_time
            j = i
            while j < n and ordered[j][1] == "FAILED":
                if ordered[j][0] - start_time > TIME_WINDOW:
                    break
                count += 1
                last_time = ordered[j][0]
                j += 1

            is_run_start = i == 0 or ordered[i - 1][1] != "FAILED"
            if is_run_start and count >= FAILED_THRESHOLD:
                alerts.append((count, start_time, last_time))

        if alerts:
            report[username] = alerts

    return report
