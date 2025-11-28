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
        return {"error": "Missing Google Safe Browsing API key. Set the environment variable GOOGLE_SAFE_BROWSING_API_KEY or edit the script."}
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
        sys.stdout.write(colored("\r[*] Checking" + "." * (i + 1
