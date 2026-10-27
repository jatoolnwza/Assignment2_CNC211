from datetime import timedelta

FAILED_THRESHOLD = 3
TIME_WINDOW = timedelta(minutes=5)


def detect_b(events_by_user):
    report = {}

    for username, events in events_by_user.items():
        ordered = sorted(events, key=lambda e: e[0])
        n = len(ordered)
        alerts = []

        for i in range(n):
            start_time, start_status = ordered[i]
            if start_status != "FAILED":
                continue

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
