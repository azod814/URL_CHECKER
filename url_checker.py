import tkinter as tk
from tkinter import simpledialog
import requests
import os
import sys
import re
from termcolor import colored
import pyfiglet
import time

# पहले से मौजूद कोड और फ़ंक्शन्स...

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

def handle_target(target):
    target_type = "email" if "@" in target else "url"
    print(colored(f"\n[*] Target: {target} ({target_type})", "yellow"))
    
    if target_type == "url":
        if not target.startswith(("http://", "https://")):
            target = "http://" + target
        result = check_url_safety(target)
        if "error" in result:
            print(colored(f"\n[!] Error: {result['error']}", "red"))
        elif "matches" in result and result["matches"]:
            print(colored("\n[!] ❌ UNSAFE URL!", "red"))
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
        else:
            print(colored("\n[✅] SAFE EMAIL DOMAIN! No threats detected.", "green"))

def open_url_checker():
    url = simpledialog.askstring("URL Checker", "Enter URL to check:")
    if url:
        handle_target(url)

def open_email_checker():
    email = simpledialog.askstring("Email Checker", "Enter Email to check:")
    if email:
        handle_target(email)

def create_gui():
    root = tk.Tk()
    root.title("URL और Email Checker")

    url_button = tk.Button(root, text="Check URL", command=open_url_checker)
    url_button.pack(pady=10)

    email_button = tk.Button(root, text="Check Email", command=open_email_checker)
    email_button.pack(pady=10)

    root.mainloop()

if __name__ == "__main__":
    print_banner()
    create_gui()
