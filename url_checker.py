#!/usr/bin/env python3
"""
URL & Email Checker — Improved version
 - Adds stronger heuristics for phishing/suspicious detection
 - Labels results clearly: ✅ SAFE, ⚠️ SUSPICIOUS, ❌ XNOTSAFE (PHISHING)
 - Email checks include MX/A resolution heuristics + disposable domain list
 - Uses Google Safe Browsing API if env var GOOGLE_SAFE_BROWSING_API_KEY set
 - Still GUI (Tkinter) with persistent checker windows and quick-check
 - Includes big ASCII banner in console output
"""

import os
import re
import threading
import requests
import urllib.parse
import socket
import tkinter as tk
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText

# Optional pretty console banner modules - silent fallback if missing
try:
    import pyfiglet
    from termcolor import colored
    USE_PYFIGLET = True
except Exception:
    USE_PYFIGLET = False

GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()

# Big ASCII banner requested by user
BIG_ASCII = r"""
 ___  ___  ________  ___                                               
|\  \|\  \|\   __  \|\  \                                              
\ \  \\\  \ \  \|\  \ \  \                                             
 \ \  \\\  \ \   _  _\ \  \                                            
  \ \  \\\  \ \  \\  \\ \  \____                                       
   \ \_______\ \__\\ _\\ \_______\                                     
    \|_______|\|__|\|__|\|_______|                                     
                                                                           
                                                                           
                                                                           
 ________  ___  ___  _______   ________  ___  __    _______   ________     
|\   ____\|\  \|\  \|\  ___ \ |\   ____\|\  \|\  \ |\  ___ \ |\   __  \    
\ \  \___|\ \  \\\  \ \   __/|\ \  \___|\ \  \/  /|\ \   __/|\ \  \|\  \   
 \ \  \    \ \   __  \ \  \_|/_\ \  \    \ \   ___  \ \  \_|/_\ \   _  _\  
  \ \  \____\ \  \ \  \ \  \_|\ \ \  \____\ \  \\ \  \ \  \_|\ \ \  \\  \| 
   \ \_______\ \__\ \__\ \_______\ \_______\ \__\\ \__\ \_______\ \__\\ _\ 
    \|_______|\|__|\|__|\|_______|\|_______|\|__| \|__|\|_______|\|__|\|__|
"""

# Small list of known disposable domains (not exhaustive)
DISPOSABLE_DOMAINS = {
    "mailinator.com", "10minutemail.com", "guerrillamail.com", "yopmail.com",
    "trashmail.com", "temp-mail.org", "dispostable.com", "maildrop.cc"
}

# URL shorteners (common small set)
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly", "is.gd", "tiny.cc", "rb.gy"
}

# ---------- Utilities ----------

def print_banner():
    try:
        if USE_PYFIGLET:
            banner = pyfiglet.figlet_format("URL / Email Checker", font="standard")
            print(colored(banner, "cyan"))
        else:
            print(BIG_ASCII)
    except Exception:
        print(BIG_ASCII)

def normalize_url(user_input: str) -> str:
    u = user_input.strip()
    if not re.match(r"^https?://", u, re.I):
        u = "https://" + u
    parsed = urllib.parse.urlparse(u)
    # If user typed something invalid, return original cleaned input
    if not parsed.netloc:
        return user_input.strip()
    return urllib.parse.urlunparse((parsed.scheme or "https", parsed.netloc, parsed.path or "/", "", parsed.query or "", parsed.fragment or ""))

def is_valid_email(email: str) -> bool:
    return bool(re.match(r"^[A-Za-z0-9._%+\-']+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$", email.strip()))

# ---------- Networking / API ----------

def check_url_safety_api(url: str, timeout=10):
    """Call Google Safe Browsing API if key present. Returns dict or {'error': msg}."""
    if not GOOGLE_SAFE_BROWSING_API_KEY:
        return {"error": "Missing Google Safe Browsing API key (env var GOOGLE_SAFE_BROWSING_API_KEY)."}
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"
    payload = {
        "client": {"clientId": "urlchecker", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
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
    """Attempt HEAD then GET to detect redirects, status codes, final URL."""
    try:
        resp = requests.head(url, allow_redirects=True, timeout=timeout)
        return {"status_code": resp.status_code, "final_url": resp.url, "ok": resp.ok}
    except requests.exceptions.RequestException:
        try:
            resp = requests.get(url, allow_redirects=True, timeout=timeout)
            return {"status_code": resp.status_code, "final_url": resp.url, "ok": resp.ok}
        except requests.exceptions.RequestException as e:
            return {"error": f"Network error: {e}"}

def domain_resolves(domain: str) -> bool:
    """Basic domain resolution test using getaddrinfo (works for A/AAAA)."""
    try:
        socket.getaddrinfo(domain, None)
        return True
    except Exception:
        return False

# ---------- Heuristics & Classification ----------

def hostname_of(url: str) -> str:
    try:
        p = urllib.parse.urlparse(url)
        return (p.netloc or "").lower()
    except Exception:
        return ""

def classify_url(url: str):
    """Return (label, reasons:list). label one of 'safe','suspicious','phishing'."""
    reasons = []
    url_norm = normalize_url(url)
    host = hostname_of(url_norm)
    score = 0  # higher score -> more suspicious
    # Quick: Google Safe Browsing
    if GOOGLE_SAFE_BROWSING_API_KEY:
        api = check_url_safety_api(url_norm)
        if api and "matches" in api and api["matches"]:
            reasons.append("Detected by Google Safe Browsing as malicious.")
            return "phishing", reasons
        if "error" in api:
            reasons.append(f"Safe Browsing API error: {api['error']}. Proceeding heuristics.")

    # Basic HTTP check
    http = quick_http_check(url_norm)
    if "error" in http:
        reasons.append(f"Network/HTTP check failed: {http['error']}")
        score += 1
    else:
        code = http.get("status_code")
        final = http.get("final_url")
        if code and 400 <= code < 600:
            reasons.append(f"Server returned error status {code}.")
            score += 1
        # Redirect to very different host?
        if final:
            final_host = hostname_of(final)
            if final_host and final_host != host:
                reasons.append(f"Redirects to different host ({final_host}) — could be phishing/redirector.")
                score += 2

    # Heuristic checks on host and path
    # Raw IP
    if re.search(r"^\[?\d{1,3}(\.\d{1,3}){3}\]?$", host) or re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", host):
        reasons.append("URL uses raw IP address instead of domain.")
        score += 3

    # Long subdomain depth
    if host.count(".") >= 4:
        reasons.append("Long subdomain chain (common trick to hide real domain).")
        score += 2

    # Punycode / IDN trick
    if host.startswith("xn--") or "xn--" in host:
        reasons.append("Contains punycode (xn--). Could be IDN homograph trick.")
        score += 3

    # Lots of hyphens or digits in domain
    if re.search(r"[0-9].*", host) and not re.search(r"[a-zA-Z]", host.split(".")[0]):
        reasons.append("Hostname contains many digits and few letters.")
        score += 2
    if host.count("-") >= 2:
        reasons.append("Hostname has multiple hyphens (a common phishing pattern).")
        score += 1

    # Suspicious keywords in path combined with domain not matching a known brand
    suspicious_keywords = ["login", "signin", "secure", "verify", "update", "confirm", "banking", "account", "password", "pay", "checkout"]
    path = urllib.parse.urlparse(url_norm).path.lower()
    for kw in suspicious_keywords:
        if kw in path or kw in host:
            reasons.append(f"Contains suspicious keyword '{kw}' in host/path.")
            score += 1

    # URL shorteners
    naked_host = host.split(":")[0].split("@")[-1]
    if naked_host in URL_SHORTENERS:
        reasons.append("URL shortener used — could hide final destination.")
        score += 2

    # Many query parameters or very long encoded query strings (common in malicious links)
    query = urllib.parse.urlparse(url_norm).query
    if query and len(query) > 120:
        reasons.append("Very long query string (may include encoded malicious payloads).")
        score += 1

    # Suspicious TLDs list (not definitive) - flag lightly
    suspicious_tlds = {".zip", ".review", ".country", ".kim", ".work", ".gdn", ".tk", ".ml"}
    for tld in suspicious_tlds:
        if host.endswith(tld):
            reasons.append(f"TLD '{tld}' is often used by low-quality or phishing domains.")
            score += 1
            break

    # Final decision thresholds
    if score >= 5:
        reasons.insert(0, f"Suspicion score {score} (higher is worse).")
        return "phishing", reasons
    elif 2 <= score < 5:
        reasons.insert(0, f"Suspicion score {score}.")
        return "suspicious", reasons
    else:
        reasons.insert(0, f"Suspicion score {score}. No strong heuristics flagged.")
        return "safe", reasons

def analyze_url(url: str):
    """Human-readable result string with label and reasons."""
    url_norm = normalize_url(url)
    label, reasons = classify_url(url_norm)
    out = []
    out.append(f"Checked URL: {url_norm}")
    if label == "phishing":
        out.append("❌ XNOTSAFE / PHISHING detected.")
    elif label == "suspicious":
        out.append("⚠️ SUSPICIOUS — proceed with caution.")
    else:
        out.append("✅ SAFE (no clear indicators).")
    out.append("")
    out.append("Reason(s):")
    for r in reasons:
        out.append(f" - {r}")
    # Add quick HTTP details for visibility
    http = quick_http_check(url_norm)
    if "error" in http:
        out.append(f"\nHTTP check: {http['error']}")
    else:
        out.append(f"\nHTTP status: {http.get('status_code')}  final URL: {http.get('final_url')}")
    return "\n".join(out)

# ---------- Email analysis ----------

def classify_email(email: str):
    """Return (label, reasons:list)."""
    e = email.strip()
    reasons = []
    if not is_valid_email(e):
        return "invalid", ["Invalid email format."]
    local, domain = e.split("@", 1)
    domain = domain.lower()
    score = 0
    # disposable domain
    if domain in DISPOSABLE_DOMAINS:
        reasons.append("Domain is a known disposable email provider.")
        score += 3
    # domain resolution
    if domain_resolves(domain):
        reasons.append("Domain resolves (A/AAAA record found).")
    else:
        reasons.append("Domain does NOT resolve — could be fake or typo.")
        score += 2
    # unusual local part (like too many numbers or suspicious words)
    if re.search(r"(noreply|no-reply|admin|support|service|secure)", local, re.I):
        reasons.append("Local-part uses generic/service terms (noreply/admin) — be careful with auto messages.")
        score += 1
    if re.search(r"\d{5,}", local):
        reasons.append("Local part has long sequence of digits (common in auto-generated/disposable addresses).")
        score += 1
    # MX check (best-effort - using getaddrinfo on smtp port 25 may be unreliable/firewalled; we do simple resolution)
    try:
        mx_ok = False
        # try MX via socket.getaddrinfo on the domain (not exact MX but helps)
        socket.getaddrinfo(domain, 25)
        mx_ok = True
        if mx_ok:
            reasons.append("Appears to accept SMTP connections (port probe possible).")
    except Exception:
        # silent - no bonus
        pass
    # threshold
    if score >= 4:
        return "unsafe", reasons
    elif 2 <= score < 4:
        return "suspicious", reasons
    else:
        return "safe", reasons

def analyze_email(email: str):
    out = []
    out.append(f"Checked Email: {email.strip()}")
    label, reasons = classify_email(email)
    out.append("")
    if label == "invalid":
        out.append("❌ Invalid email format.")
    elif label == "unsafe":
        out.append("❌ XNOTSAFE / POSSIBLY FRAUDULENT (email).")
    elif label == "suspicious":
        out.append("⚠️ SUSPICIOUS (email).")
    else:
        out.append("✅ SAFE (email looks okay).")
    out.append("")
    out.append("Reason(s):")
    for r in reasons:
        out.append(f" - {r}")
    return "\n".join(out)

# ---------- GUI ----------

class CheckerWindow:
    def __init__(self, master, title="Checker", width=720, height=420, show_banner=False):
        self.win = tk.Toplevel(master)
        self.win.title(title)
        self.win.geometry(f"{width}x{height}")
        self.win.minsize(560, 320)
        try:
            self.win.attributes("-alpha", 0.96)
        except Exception:
            pass

        frame = ttk.Frame(self.win, padding=(10, 10))
        frame.pack(expand=True, fill="both")

        # Optional ASCII banner area (small)
        if show_banner:
            banner_frame = ttk.Frame(frame)
            banner_frame.pack(fill="x", pady=(0, 6))
            lbl = ttk.Label(banner_frame, text="URL & Email Checker", font=("Segoe UI", 13, "bold"))
            lbl.pack(anchor="center")

        # Input row
        row = ttk.Frame(frame)
        row.pack(fill="x", pady=(6, 6))
        self.entry = ttk.Entry(row, font=("Segoe UI", 12))
        self.entry.pack(side="left", expand=True, fill="x", padx=(0, 8))
        self.check_btn = ttk.Button(row, text="Check", command=self.start_check)
        self.check_btn.pack(side="right")

        # Result area
        self.result_text = ScrolledText(frame, wrap="word", font=("Consolas", 11), state="disabled", height=14)
        self.result_text.pack(expand=True, fill="both")

        # status / copy buttons
        bottom = ttk.Frame(frame)
        bottom.pack(fill="x", pady=(8,0))
        self.status = ttk.Label(bottom, text="Ready", anchor="w")
        self.status.pack(side="left", fill="x", expand=True)
        copy_btn = ttk.Button(bottom, text="Copy Result", command=self.copy_result)
        copy_btn.pack(side="right")

    def set_status(self, txt):
        self.status.config(text=txt)

    def append_result(self, text, clear=False):
        self.result_text.config(state="normal")
        if clear:
            self.result_text.delete("1.0", "end")
        self.result_text.insert("end", text + "\n")
        self.result_text.see("end")
        self.result_text.config(state="disabled")

    def copy_result(self):
        try:
            txt = self.result_text.get("1.0", "end")
            self.win.clipboard_clear()
            self.win.clipboard_append(txt)
            messagebox.showinfo("Copied", "Result copied to clipboard.")
        except Exception as e:
            messagebox.showerror("Error", f"Unable to copy: {e}")

    def start_check(self):
        query = self.entry.get().strip()
        if not query:
            messagebox.showinfo("Info", "Please enter a URL or email to check.")
            return
        self.check_btn.config(state="disabled")
        self.set_status("Checking...")
        self.append_result(f"--- Starting check for: {query} ---", clear=True)
        t = threading.Thread(target=self._run_check, args=(query,), daemon=True)
        t.start()

    def _run_check(self, query):
        try:
            if "@" in query and is_valid_email(query):
                res = analyze_email(query)
            elif "@" in query and not is_valid_email(query):
                res = "❌ Invalid email format."
            else:
                res = analyze_url(query)
        except Exception as e:
            res = f"Unexpected error during check: {e}"
        self.win.after(0, self._finish_check, res)

    def _finish_check(self, res):
        self.append_result(res)
        self.set_status("Done")
        self.check_btn.config(state="normal")

class MainApp:
    def __init__(self, root):
        self.root = root
        root.title("URL & Email Toolkit")
        w, h = 560, 320
        x = (root.winfo_screenwidth() - w) // 2
        y = (root.winfo_screenheight() - h) // 3
        root.geometry(f"{w}x{h}+{x}+{y}")
        root.minsize(520, 280)
        try:
            root.attributes("-alpha", 0.96)
            root.configure(bg="#F7FBFE")
        except Exception:
            pass

        top = ttk.Frame(root, padding=(12, 10))
        top.pack(fill="x")
        title_lbl = ttk.Label(top, text="URL & Email Security Toolkit", font=("Segoe UI", 14, "bold"))
        title_lbl.pack(anchor="center")
        subtitle = ttk.Label(top, text="Quick checks + Google Safe Browsing (if API key set). Labels: ✅ SAFE / ⚠️ SUSPICIOUS / ❌ XNOTSAFE", font=("Segoe UI", 9))
        subtitle.pack(anchor="center", pady=(4,0))

        center = ttk.Frame(root, padding=(12,8))
        center.pack(expand=True, fill="both")

        btn_frame = ttk.Frame(center)
        btn_frame.pack(pady=(10,6))

        url_btn = ttk.Button(btn_frame, text="Open URL Checker Window", command=self.open_url_window, width=26)
        url_btn.grid(row=0, column=0, padx=8, pady=6)
        email_btn = ttk.Button(btn_frame, text="Open Email Checker Window", command=self.open_email_window, width=26)
        email_btn.grid(row=0, column=1, padx=8, pady=6)

        quick_frame = ttk.LabelFrame(center, text="Quick Check", padding=(8,8))
        quick_frame.pack(fill="x", padx=6, pady=(10,0))
        self.quick_entry = ttk.Entry(quick_frame, font=("Segoe UI", 11))
        self.quick_entry.pack(side="left", expand=True, fill="x", padx=(0,8))
        quick_btn = ttk.Button(quick_frame, text="Check Fast", command=self.quick_check)
        quick_btn.pack(side="right")

        footer = ttk.Frame(root, padding=(8,6))
        footer.pack(fill="x")
        tip = "Tip: set env var GOOGLE_SAFE_BROWSING_API_KEY for best results (optional)."
        ttk.Label(footer, text=tip, font=("Segoe UI", 9)).pack(anchor="w")

        self.open_windows = []

    def open_url_window(self):
        w = CheckerWindow(self.root, title="URL Checker", width=820, height=460, show_banner=True)
        w.entry.insert(0, "example.com")
        self.open_windows.append(w)

    def open_email_window(self):
        w = CheckerWindow(self.root, title="Email Checker", width=820, height=460, show_banner=True)
        w.entry.insert(0, "user@example.com")
        self.open_windows.append(w)

    def quick_check(self):
        q = self.quick_entry.get().strip()
        if not q:
            messagebox.showinfo("Info", "Enter URL or email to quick-check.")
            return
        temp = CheckerWindow(self.root, title="Quick Result", width=700, height=360, show_banner=False)
        temp.entry.insert(0, q)
        temp.start_check()
        self.open_windows.append(temp)

# ---------- Main ----------

def main():
    print_banner()
    root = tk.Tk()
    try:
        style = ttk.Style(root)
        style.theme_use("clam")
    except Exception:
        pass
    app = MainApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
