import ssl
import socket
from urllib.parse import urlparse

def ssl_check():
    url = input("Enter website URL: ").strip()
    if not url.startswith("http"):
        url = "https://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname

    print("\nRunning SSL/HTTPS check...\n")

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                print("HTTPS: Enabled")
                print("Certificate Issuer:", cert['issuer'])
    except:
        print("HTTPS not properly configured or certificate invalid.")
