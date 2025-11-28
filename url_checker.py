#!/usr/bin/env python3
"""
URL & Email Checker — Full GUI version
Features:
 - Professional-ish larger GUI (Tkinter + ttk)
 - Semi-transparent "glass-like" main window (alpha)
 - Separate persistent windows for URL check and Email check (both can stay open)
 - Uses Google Safe Browsing API if GOOGLE_SAFE_BROWSING_API_KEY env var is set
 - Falls back to a basic HTTP HEAD check + format/domain heuristics if API key missing
 - Runs network checks in background threads so GUI stays responsive

Dependencies:
 pip install requests pyfiglet termcolor
(you only need these if you want console banner or API access; GUI uses standard tkinter)
"""

import os
import re
import threading
import requests
import urllib.parse
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from tkinter.scrolledtext import ScrolledText
import pyfiglet
from termcolor import colored

GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()

# ---------- Utilities ----------

def print_banner():
    try:
        banner = pyfiglet.figlet_format("URL / Email Checker", font="standard")
        print(colored(banner, "cyan"))
    except Exception:
        # silent fallback if pyfiglet/termcolor missing
        print("URL / Email Checker")

def normalize_url(user_input: str) -> str:
    # Ensure scheme present; prefer https when possible
    u = user_input.strip()
    if not re.match(r"^https?://", u, re.I):
        u = "https://" + u
    parsed = urllib.parse.urlparse(u)
    if not parsed.netloc:
        # maybe user typed something weird; return original
        return user_input
    # Rebuild to standard form
    return urllib.parse.urlunparse((parsed.scheme or "https", parsed.netloc, parsed.path or "/", "", "", ""))

def is_valid_email(email: str) -> bool:
    return bool(re.match(r"^[^@]+@[^@]+\.[^@]+$", email.strip()))

# ---------- Threat checking ----------

def check_url_safety_api(url: str, timeout=10):
    """Call Google Safe Browsing API if key present. Returns dict or {'error': msg}."""
    if not GOOGLE_SAFE_BROWSING_API_KEY:
        return {"error": "Missing Google Safe Browsing API key (env var GOOGLE_SAFE_BROWSING_API_KEY)."}
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
        resp = requests.post(api_url, json=payload, timeout=timeout)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.RequestException as e:
        return {"error": f"API request failed: {e}"}
    except ValueError:
        return {"error": "Invalid JSON response from API."}

def quick_http_check(url: str, timeout=8):
    """Simple fallback: attempt HEAD then GET to see response and status codes."""
    try:
        # HEAD first
        resp = requests.head(url, allow_redirects=True, timeout=timeout)
        code = resp.status_code
        final = resp.url
        return {"status_code": code, "final_url": final, "ok": resp.ok}
    except requests.exceptions.RequestException:
        try:
            resp = requests.get(url, allow_redirects=True, timeout=timeout)
            return {"status_code": resp.status_code, "final_url": resp.url, "ok": resp.ok}
        except requests.exceptions.RequestException as e:
            return {"error": f"Network error: {e}"}

def analyze_url(url: str):
    """High-level wrapper that returns a human-readable string result about URL safety."""
    url_norm = normalize_url(url)
    out_lines = []
    out_lines.append(f"Checked URL: {url_norm}")
    # Try API first if key exists
    if GOOGLE_SAFE_BROWSING_API_KEY:
        out_lines.append("Using Google Safe Browsing API...")
        api_res = check_url_safety_api(url_norm)
        if "error" in api_res:
            out_lines.append(f"API error: {api_res['error']}")
            out_lines.append("Falling back to HTTP checks...")
            quick = quick_http_check(url_norm)
            if "error" in quick:
                out_lines.append(quick["error"])
            else:
                out_lines.append(f"HTTP status: {quick.get('status_code')}, final URL: {quick.get('final_url')}")
        else:
            # If matches key present -> threats
            if api_res and api_res.get("matches"):
                out_lines.append("❌ UNSAFE: Threats detected by Google Safe Browsing:")
                for m in api_res["matches"]:
                    out_lines.append(f" - Threat Type: {m.get('threatType')}, Platform: {m.get('platformType')}")
            else:
                out_lines.append("✅ SAFE: No matches in Google Safe Browsing.")
    else:
        out_lines.append("No Google API key configured. Performing quick HTTP checks and heuristics.")
        quick = quick_http_check(url_norm)
        if "error" in quick:
            out_lines.append(quick["error"])
        else:
            out_lines.append(f"HTTP status: {quick.get('status_code')}, final URL: {quick.get('final_url')}")
            if quick.get("status_code") and 400 <= quick["status_code"] < 600:
                out_lines.append("⚠️ Warning: Server returned error status code.")
            else:
                out_lines.append("No immediate HTTP errors detected.")
        # Basic heuristics (phishy patterns)
        parsed = urllib.parse.urlparse(url_norm)
        host = parsed.netloc.lower()
        if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", host):
            out_lines.append("⚠️ Heuristic: URL uses raw IP address (may be suspicious).")
        if len(host.split(".")) > 3:
            out_lines.append("⚠️ Heuristic: Long subdomain depth (could be phishing trick).")
    return "\n".join(out_lines)

def analyze_email(email: str):
    """Analyze email: basic validation, domain check via URL check on domain."""
    out_lines = []
    email_s = email.strip()
    out_lines.append(f"Checked Email: {email_s}")
    if not is_valid_email(email_s):
        out_lines.append("❌ Invalid email format.")
        return "\n".join(out_lines)
    domain = email_s.split("@")[-1]
    out_lines.append(f"Domain: {domain}")
    # Use the same URL analyzer on the domain (http://domain)
    domain_url = "https://" + domain
    out_lines.append("Checking domain using URL checks...")
    domain_result = analyze_url(domain_url)
    out_lines.append(domain_result)
    return "\n".join(out_lines)

# ---------- GUI ----------

class CheckerWindow:
    def __init__(self, master, title="Checker", width=700, height=420):
        self.win = tk.Toplevel(master)
        self.win.title(title)
        self.win.geometry(f"{width}x{height}")
        # keep window resizable
        self.win.minsize(560, 320)
        # Slightly transparent to mimic glass
        try:
            self.win.attributes("-alpha", 0.95)
        except Exception:
            pass

        # style frame to look like a card
        frame = ttk.Frame(self.win, padding=(12, 12, 12, 12), relief="flat")
        frame.pack(expand=True, fill="both")

        # Input row
        row = ttk.Frame(frame)
        row.pack(fill="x", pady=(0, 8))
        self.entry = ttk.Entry(row, font=("Segoe UI", 12))
        self.entry.pack(side="left", expand=True, fill="x", padx=(0, 8))
        self.check_btn = ttk.Button(row, text="Check", command=self.start_check)
        self.check_btn.pack(side="right")

        # Result area
        self.result_text = ScrolledText(frame, wrap="word", font=("Consolas", 11), state="disabled", height=14)
        self.result_text.pack(expand=True, fill="both")

        # Small status bar
        self.status = ttk.Label(frame, text="Ready", anchor="w")
        self.status.pack(fill="x", pady=(8, 0))

    def set_status(self, txt):
        self.status.config(text=txt)

    def append_result(self, text, clear=False):
        self.result_text.config(state="normal")
        if clear:
            self.result_text.delete("1.0", "end")
        self.result_text.insert("end", text + "\n")
        self.result_text.see("end")
        self.result_text.config(state="disabled")

    def start_check(self):
        query = self.entry.get().strip()
        if not query:
            messagebox.showinfo("Info", "Please enter a URL/email to check.")
            return
        # disable UI while checking
        self.check_btn.config(state="disabled")
        self.set_status("Checking...")
        self.append_result(f"--- Starting check for: {query} ---", clear=True)
        # Run check in background
        t = threading.Thread(target=self._run_check, args=(query,), daemon=True)
        t.start()

    def _run_check(self, query):
        try:
            if "@" in query and is_valid_email(query):
                res = analyze_email(query)
            elif "@" in query and not is_valid_email(query):
                res = "Invalid email format."
            else:
                res = analyze_url(query)
        except Exception as e:
            res = f"Unexpected error during check: {e}"
        # update UI in main thread
        self.win.after(0, self._finish_check, res)

    def _finish_check(self, res):
        self.append_result(res)
        self.set_status("Done")
        self.check_btn.config(state="normal")

class MainApp:
    def __init__(self, root):
        self.root = root
        root.title("URL & Email Toolkit")
        # size and center
        w, h = 520, 300
        x = (root.winfo_screenwidth() - w) // 2
        y = (root.winfo_screenheight() - h) // 3
        root.geometry(f"{w}x{h}+{x}+{y}")
        root.minsize(480, 260)

        # glass-like: background + alpha (best-effort)
        try:
            root.attributes("-alpha", 0.96)
        except Exception:
            pass
        root.configure(bg="#F2F7FB")  # soft light background

        # top frame with nice heading
        top = ttk.Frame(root, padding=(18, 12))
        top.pack(fill="x")
        title_lbl = ttk.Label(top, text="URL & Email Security Toolkit", font=("Segoe UI", 16, "bold"))
        title_lbl.pack(anchor="center")

        subtitle = ttk.Label(top, text="Quick checks + Google Safe Browsing (if API key configured)", font=("Segoe UI", 9))
        subtitle.pack(anchor="center", pady=(4, 0))

        # center options area
        center = ttk.Frame(root, padding=(18, 12))
        center.pack(expand=True, fill="both")

        # Buttons to open persistent checker windows
        btn_frame = ttk.Frame(center)
        btn_frame.pack(pady=(12, 6))

        url_btn = ttk.Button(btn_frame, text="Open URL Checker Window", command=self.open_url_window, width=28)
        url_btn.grid(row=0, column=0, padx=8, pady=6)

        email_btn = ttk.Button(btn_frame, text="Open Email Checker Window", command=self.open_email_window, width=28)
        email_btn.grid(row=0, column=1, padx=8, pady=6)

        # Quick input and single-click check area (for fast use)
        quick_frame = ttk.LabelFrame(center, text="Quick Check", padding=(10, 10))
        quick_frame.pack(fill="x", padx=6, pady=(12, 0))

        self.quick_entry = ttk.Entry(quick_frame, font=("Segoe UI", 11))
        self.quick_entry.pack(side="left", expand=True, fill="x", padx=(0, 8))
        quick_btn = ttk.Button(quick_frame, text="Check Fast", command=self.quick_check)
        quick_btn.pack(side="right")

        # status / tips area
        footer = ttk.Frame(root, padding=(12, 6))
        footer.pack(fill="x")
        tip = "Tip: Set env var GOOGLE_SAFE_BROWSING_API_KEY for best results."
        footer_lbl = ttk.Label(footer, text=tip, font=("Segoe UI", 9))
        footer_lbl.pack(anchor="w")

        # keep references to windows so user can open multiple or reopen
        self.open_windows = []

    def open_url_window(self):
        w = CheckerWindow(self.root, title="URL Checker", width=820, height=460)
        w.entry.insert(0, "example.com")
        self.open_windows.append(w)

    def open_email_window(self):
        w = CheckerWindow(self.root, title="Email Checker", width=820, height=460)
        w.entry.insert(0, "user@example.com")
        self.open_windows.append(w)

    def quick_check(self):
        q = self.quick_entry.get().strip()
        if not q:
            messagebox.showinfo("Info", "Enter URL or email to quick-check.")
            return
        # spawn temporary window to show result quickly
        temp = CheckerWindow(self.root, title="Quick Result", width=700, height=360)
        temp.entry.insert(0, q)
        # auto-start check
        temp.start_check()
        self.open_windows.append(temp)

# ---------- Main entry ----------

def main():
    print_banner()
    root = tk.Tk()
    # ttk theme
    try:
        style = ttk.Style(root)
        style.theme_use("clam")
        # style tweaks
        style.configure("TButton", padding=6)
        style.configure("TLabel", padding=4)
    except Exception:
        pass

    app = MainApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
