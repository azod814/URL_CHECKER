import requests
import sys
import re
from termcolor import colored
import pyfiglet
import time

# API Keys (Replace with your own)
GOOGLE_SAFE_BROWSING_API_KEY = "YOUR_GOOGLE_SAFE_BROWSING_API_KEY"

def print_banner():
    banner = r"""
                                          _____                    _____                    _____
                                         /\    \                  /\    \                  /\    \
                                        /::\____\                /::\    \                /::\____\
                                       /:::/    /               /::::\    \              /:::/    /
                                      /:::/    /               /::::::\    \            /:::/    /
                                     /:::/    /               /:::/\:::\    \          /:::/    /
                                    /:::/    /               /:::/__\:::\    \        /:::/    /
                                   /:::/    /               /::::\   \:::\    \      /:::/    /
                                  /:::/    /      _____    /::::::\   \:::\    \    /:::/    /
                                 /:::/____/      /\    \  /:::/\:::\   \:::\____\  /:::/    /
                                |:::|    /      /::\____\/:::/  \:::\   \:::|    |/:::/____/
                                |:::|____\     /:::/    /\::/   |::::\  /:::|____|\:::\    \
                                 \:::\    \   /:::/    /  \/____|:::::\/:::/    /  \:::\    \
                                  \:::\    \ /:::/    /         |:::::::::/    /    \:::\    \
                                   \:::\    /:::/    /          |::|\::::/    /      \:::\    \
                                    \:::\__/:::/    /           |::| \::/____/        \:::\    \
                                     \::::::::/    /            |::|  ~|               \:::\    \
                                      \::::::/    /             |::|   |                \:::\    \
                                       \::::/    /              \::|   |                 \:::\____\
                                        \::/____/                \:|   |                  \::/    /
                                         ~~                       \|___|                   \/____/
"""
    print(colored(banner, "cyan"))

def check_url_safety(url):
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"
    payload = {
        "client": {
            "clientId": "urlchecker",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        response = requests.post(api_url, json=payload)
        return response.json()
    except:
        return {"error": "API request failed"}

def check_email_safety(email):
    domain = email.split("@")[-1]
    url = f"http://{domain}"
    return check_url_safety(url)

def print_loading():
    for _ in range(3):
        sys.stdout.write(colored("\r[*] Checking" + "." * (_ + 1), "yellow"))
        sys.stdout.flush()
        time.sleep(0.5)
    print()

def main():
    print_banner()

    if len(sys.argv) != 2:
        print(colored("\n[!] Usage: python url_email_checker.py <url/email>", "red"))
        print(colored("    Example: python url_email_checker.py example.com", "yellow"))
        print(colored("             python url_email_checker.py test@example.com", "yellow"))
        sys.exit(1)

    target = sys.argv[1]
    target_type = "email" if "@" in target else "url"

    print(colored(f"\n[*] Target: {target} ({target_type})", "yellow"))
    print_loading()

    if target_type == "url":
        result = check_url_safety(target)
        if "error" in result:
            print(colored("\n[!] Error: Could not check URL.", "red"))
        elif "matches" in result and result["matches"]:
            print(colored("\n[!] ❌ UNSAFE URL!", "red"))
            for match in result["matches"]:
                print(colored(f"    - Threat: {match['threatType']}", "red"))
        else:
            print(colored("\n[✅] SAFE URL! No threats detected.", "green"))

    elif target_type == "email":
        if not re.match(r"[^@]+@[^@]+\.[^@]+", target):
            print(colored("\n[!] Invalid email format.", "red"))
            sys.exit(1)
        result = check_email_safety(target)
        if "error" in result:
            print(colored("\n[!] Error: Could not check email domain.", "red"))
        elif "matches" in result and result["matches"]:
            print(colored("\n[!] ❌ UNSAFE EMAIL DOMAIN!", "red"))
            for match in result["matches"]:
                print(colored(f"    - Threat: {match['threatType']}", "red"))
        else:
            print(colored("\n[✅] SAFE EMAIL DOMAIN! No threats detected.", "green"))

    print()

if __name__ == "__main__":
    main()
