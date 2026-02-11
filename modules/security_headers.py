import requests

HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Referrer-Policy"
]

def header_check():
    url = input("Enter website URL: ").strip()
    if not url.startswith("http"):
        url = "http://" + url

    try:
        response = requests.get(url, timeout=5)
    except:
        print("Failed to connect.")
        return

    print("\nSecurity Headers Report:\n")

    score = 0

    for header in HEADERS:
        if header in response.headers:
            print(header + ": PRESENT")
            score += 1
        else:
            print(header + ": MISSING")

    print("\nHeader Score:", score, "/", len(HEADERS))
