from datetime import datetime

def load_logs(filepath="login.txt"):
    user_logs = {}
    time_format = "%Y-%m-%d %H:%M:%S"

    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()

    if not lines:
        return {}

    start_index = 0
    header = [p.strip().lower() for p in lines[0].split(",")]
    if "timestamp" in header and "username" in header:
        start_index = 1

    for idx, line in enumerate(lines[start_index:], start=start_index + 1):
        line = line.strip()
        if not line:
            continue

        parts = [p.strip() for p in line.split(",")]
        if len(parts) != 4:
            raise ValueError(f"Error at line {idx}: invalid column count")

        timestamp_str, username, ip_address, status = parts
        status = status.upper()

        if not username:
            raise ValueError(f"Error at line {idx}: empty username")

        try:
            dt = datetime.strptime(timestamp_str, time_format)
        except ValueError:
            raise ValueError(f"Error at line {idx}: invalid timestamp format")

        if status not in ("SUCCESS", "FAILED"):
            raise ValueError(f"Error at line {idx}: invalid status {status}")

        if username not in user_logs:
            user_logs[username] = []

        user_logs[username].append({
            "timestamp": dt,
            "timestamp_str": timestamp_str,
            "username": username,
            "ip_address": ip_address,
            "status": status
        })

    for user in user_logs:
        user_logs[user].sort(key=lambda x: x["timestamp"])

    return user_logs


if __name__ == "__main__":
    logs = load_logs("login.txt")
    for user, records in logs.items():
        print(user, len(records))
