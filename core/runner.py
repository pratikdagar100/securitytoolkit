from security_toolkit.modules.availability_dos import availability_check
from security_toolkit.modules.security_headers import header_check
from security_toolkit.modules.ssl_https import ssl_check
from security_toolkit.modules.sql_exposure import sql_check

def run_toolkit():
    print("\nStudent / Small Startup Security Toolkit\n")
    print("1. Availability & DoS Check")
    print("2. Security Headers Check")
    print("3. HTTPS & SSL Check")
    print("4. SQL Exposure Check")
    print("5. Full Scan")
    print("0. Exit")

    choice = input("\nEnter your choice: ").strip()

    if choice == "1":
        availability_check()
    elif choice == "2":
        header_check()
    elif choice == "3":
        ssl_check()
    elif choice == "4":
        sql_check()
    elif choice == "5":
        availability_check()
        header_check()
        ssl_check()
        sql_check()
    else:
        print("Exiting.")
