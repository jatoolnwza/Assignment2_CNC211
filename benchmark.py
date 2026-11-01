import random
import time
import tracemalloc
from datetime import datetime, timedelta

from detect_a import detect_a, load_logs
from detect_b import detect_b

def generate_large_log(filename, num_rows):

    usernames = [f"user_{i}" for i in range(50)]
    statuses = ["FAILED", "FAILED", "FAILED", "SUCCESS"]
    base_time = datetime(2026, 10, 1, 8, 0, 0)

    with open(filename, "w", encoding="utf-8") as f:
        f.write("timestamp,username,ip_address,status\n")
        curr_time = base_time
        for _ in range(num_rows):
            curr_time += timedelta(seconds=random.randint(1, 10))
            user = random.choice(usernames)
            ip = f"192.168.1.{random.randint(1, 254)}"
            status = random.choice(statuses)
            f.write(
                f"{curr_time.strftime('%Y-%m-%d %H:%M:%S')},{user},{ip},{status}\n"
            )


def measure_performance(func, events_data):
    
    tracemalloc.start()
    start_time = time.perf_counter()

    _ = func(events_data)

    end_time = time.perf_counter()
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    exec_time = end_time - start_time
    peak_memory_mb = peak / (1024 * 1024)
    return exec_time, peak_memory_mb


def run_benchmark():
    test_sizes = [1000, 5000, 10000, 20000]
    print("\n=== START BENCHMARK ===")
    print(
        f"{'Rows':<8} | {'Algo A Time (s)':<15} | {'Algo A RAM (MB)':<15} | {'Algo B Time (s)':<15} | {'Algo B RAM (MB)':<15}"
    )
    print("-" * 80)

    for size in test_sizes:
        filename = f"test_log_{size}.csv"
        generate_large_log(filename, size)

        events_data = load_logs(filename)

        time_a, ram_a = measure_performance(detect_a, events_data)
        time_b, ram_b = measure_performance(detect_b, events_data)

        print(
            f"{size:<8} | {time_a:<15.4f} | {ram_a:<15.2f} | {time_b:<15.4f} | {ram_b:<15.2f}"
        )

    print("=== FINISH BENCHMARK ===\n")


if __name__ == "__main__":
    run_benchmark()