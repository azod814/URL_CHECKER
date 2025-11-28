#!/usr/bin/env python3
import requests
import sys
import re
from termcolor import colored
import pyfiglet
import time
import os

GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "YOUR_GOOGLE_SAFE_BROWSING_API_KEY")

def print_banner():
    banner = pyfiglet.figlet_format("URL / Email Checker", font="standard")
    print(colored(banner, "cyan"))

def check_url_safety(url):
    if GOOGLE_SAFE_BROWSING_API_KEY in (None, "", "YOUR_GOOGLE_SAFE_BROWSING_API_KEY"):
        return {"error": "Missing Google Safe Browsing API key. Set the environment variable or edit the script."}
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"
    payload = {
        "client": {"clientId": "urlchecker", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        resp = requests.post(api_url, json=payload, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.RequestException as e:
        return {"error": f"API request failed: {e}"}
    except ValueError:
        return {"error": "Invalid response from API (not JSON)."}

def print_loading():
    for i in range(3):
        sys.stdout.write(colored("\r[*] Checking" + "." * (i + 1), "yellow"))
        sys.stdout.flush()
        time.sleep(0.4)
    print()

def handle_target(target):
    target_type = "email" if "@" in target else "url"
    print(colored(f"\n[*] Target: {target} ({target_type})", "yellow"))
    print_loading()

    if target_type == "url":
        if not target.startswith(("http://", "https://")):
            target = "http://" + target
        result = check_url_safety(target)
        if "error" in result:
            print(colored(f"\n[!] Error: {result['error']}", "red"))
        elif "matches" in result and result["matches"]:
            print(colored("\n[!] ❌ UNSAFE URL!", "red"))
            for match in result["matches"]:
                print(colored(f"    - Threat: {match.get('threatType')}", "red"))
        else:
            print(colored("\n[✅] SAFE URL! No threats detected.", "green"))

    else:  # email
        if not re.match(r"[^@]+@[^@]+\.[^@]+", target):
            print(colored("\n[!] Invalid email format.", "red"))
            return
        domain = target.split("@")[-1]
        result = check_url_safety("http://" + domain)
        if "error" in result:
            print(colored(f"\n[!] Error: {result['error']}", "red"))
        elif "matches" in result and result["matches"]:
            print(colored("\n[!] ❌ UNSAFE EMAIL DOMAIN!", "red"))
            for match in result["matches"]:
                print(colored(f"    - Threat: {match.get('threatType')}", "red"))
        else:
            print(colored("\n[✅] SAFE EMAIL DOMAIN! No threats detected.", "green"))

def main():
    print_banner()

    if len(sys.argv) == 2:
        handle_target(sys.argv[1])
        input(colored("\nPress Enter to exit...", "cyan"))
        return

    print(colored("Interactive mode — type URL or email to check. Type 'exit' or Ctrl+C to quit.", "yellow"))
    while True:
        try:
            target = input(colored("\nEnter URL or email> ", "cyan")).strip()
        except (KeyboardInterrupt, EOFError):
            print("\nBye.")
            break
        if not target:
            continue
        if target.lower() in ("exit", "quit"):
            print("Exiting.")
            break
        handle_target(target)

if __name__ == "__main__":
    main()
