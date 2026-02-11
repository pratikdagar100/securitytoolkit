import requests
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

PAYLOADS = ["'", "' OR '1'='1"]
ERROR_PATTERNS = ["sql syntax", "mysql", "syntax error", "unclosed quotation"]

def sql_check():
    url = input("Enter URL with parameters (example: http://site.com?id=1): ").strip()

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        print("No parameters found.")
        return

    vulnerable = False

    for param in params:
        for payload in PAYLOADS:
            test_params = params.copy()
            test_params[param] = payload
            new_query = urlencode(test_params, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))

            try:
                response = requests.get(test_url, timeout=5)
                for pattern in ERROR_PATTERNS:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        print("Possible SQL exposure detected in parameter:", param)
                        vulnerable = True
                        break
            except:
                pass

    if not vulnerable:
        print("No SQL error exposure detected.")
