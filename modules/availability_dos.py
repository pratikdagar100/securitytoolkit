import requests
import time
import statistics

REQUEST_COUNT = 10
TIMEOUT = 3

def availability_check():
    url = input("Enter website URL: ").strip()
    if not url.startswith("http"):
        url = "http://" + url

    response_times = []
    failures = 0

    print("\nRunning availability analysis...\n")

    for _ in range(REQUEST_COUNT):
        try:
            start = time.time()
            requests.get(url, timeout=TIMEOUT)
            response_times.append(time.time() - start)
        except requests.RequestException:
            failures += 1

    if response_times:
        avg_time = statistics.mean(response_times)
        max_time = max(response_times)
        min_time = min(response_times)
    else:
        avg_time = float("inf")
        max_time = min_time = 0

    failure_rate = failures / REQUEST_COUNT

    print("Results:")
    print("Average Response Time:", round(avg_time, 2), "seconds")
    print("Max Response Time:", round(max_time, 2))
    print("Min Response Time:", round(min_time, 2))
    print("Failure Rate:", round(failure_rate * 100, 2), "%")

    if failure_rate > 0.4:
        print("Status: HIGH RISK - Possible availability issue")
    elif avg_time > 2:
        print("Status: SLOW - Server may be overloaded")
    else:
        print("Status: STABLE")
