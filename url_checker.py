#!/usr/bin/env python3
"""
URL & Email Checker — GUI updated (green/pro look + emoji verdict banner)

What changed visually:
 - Green professional-ish background and card panels
 - Colored action buttons (primary green) that work cross-platform
 - Big emoji + bold verdict banner (SAFE / SUSPICIOUS / XNOTSAFE) for clarity
 - Result details remain in a ScrolledText below the banner
 - Functionality (Safe Browsing + heuristics + email checks) preserved
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

# Optional console banner libs — silent fallback
try:
    import pyfiglet
    from termcolor import colored
    USE_PYFIGLET = True
except Exception:
    USE_PYFIGLET = False

GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()

BIG_ASCII = r"""
 ___  ___  ________  ___                                               
|\  \|\  \|\   __  \|\  \                                              
\ \  \\\  \ \  \|\  \ \  \                                             
 \ \  \\\  \ \   _  _\ \  \                                            
  \ \  \\\  \ \  \\  \\ \  \____                                       
   \ \_______\ \__\\ _\\ \_______\                                     
    \|_______|\|__|\|__|\|_______|                                     
"""

DISPOSABLE_DOMAINS = {
    "mailinator.com", "10minutemail.com", "guerrillamail.com", "yopmail.com",
    "trashmail.com", "temp-mail.org", "dispostable.com", "maildrop.cc"
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly", "is.gd", "tiny.cc", "rb.gy"
}

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
    if not parsed.netloc:
        return user_input.strip()
    return urllib.parse.urlunparse((parsed.scheme or "https", parsed.netloc, parsed.path or "/", "", parsed.query or "", parsed.fragment or ""))

def is_valid_email(email: str) -> bool:
    return bool(re.match(r"^[A-Za-z0-9._%+\-']+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$", email.strip()))

def check_url_safety_api(url: str, timeout=10):
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
    try:
        socket.getaddrinfo(domain, None)
        return True
    except Exception:
        return False

def hostname_of(url: str) -> str:
    try:
        p = urllib.parse.urlparse(url)
        return (p.netloc or "").lower()
    except Exception:
        return ""

def classify_url(url: str):
    reasons = []
    url_norm = normalize_url(url)
    host = hostname_of(url_norm)
    score = 0
    if GOOGLE_SAFE_BROWSING_API_KEY:
        api = check_url_safety_api(url_norm)
        if api and "matches" in api and api["matches"]:
            reasons.append("Detected by Google Safe Browsing as malicious.")
            return "phishing", reasons
        if "error" in api:
            reasons.append(f"Safe Browsing API error: {api['error']}. Proceeding heuristics.")
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
        if final:
            final_host = hostname_of(final)
            if final_host and final_host != host:
                reasons.append(f"Redirects to different host ({final_host}) — could be phishing/redirector.")
                score += 2
    if re.search(r"^\[?\d{1,3}(\.\d{1,3}){3}\]?$", host) or re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", host):
        reasons.append("URL uses raw IP address instead of domain.")
        score += 3
    if host.count(".") >= 4:
        reasons.append("Long subdomain chain (common trick to hide real domain).")
        score += 2
    if host.startswith("xn--") or "xn--" in host:
        reasons.append("Contains punycode (xn--). Could be IDN homograph trick.")
        score += 3
    if re.search(r"[0-9].*", host) and not re.search(r"[a-zA-Z]", host.split(".")[0]):
        reasons.append("Hostname contains many digits and few letters.")
        score += 2
    if host.count("-") >= 2:
        reasons.append("Hostname has multiple hyphens (a common phishing pattern).")
        score += 1
    suspicious_keywords = ["login", "signin", "secure", "verify", "update", "confirm", "banking", "account", "password", "pay", "checkout"]
    path = urllib.parse.urlparse(url_norm).path.lower()
    for kw in suspicious_keywords:
        if kw in path or kw in host:
            reasons.append(f"Contains suspicious keyword '{kw}' in host/path.")
            score += 1
    naked_host = host.split(":")[0].split("@")[-1]
    if naked_host in URL_SHORTENERS:
        reasons.append("URL shortener used — could hide final destination.")
        score += 2
    query = urllib.parse.urlparse(url_norm).query
    if query and len(query) > 120:
        reasons.append("Very long query string (may include encoded malicious payloads).")
        score += 1
    suspicious_tlds = {".zip", ".review", ".country", ".kim", ".work", ".gdn", ".tk", ".ml"}
    for tld in suspicious_tlds:
        if host.endswith(tld):
            reasons.append(f"TLD '{tld}' is often used by low-quality or phishing domains.")
            score += 1
            break
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
    http = quick_http_check(url_norm)
    if "error" in http:
        out.append(f"\nHTTP check: {http['error']}")
    else:
        out.append(f"\nHTTP status: {http.get('status_code')}  final URL: {http.get('final_url')}")
    return "\n".join(out)

def classify_email(email: str):
    e = email.strip()
    reasons = []
    if not is_valid_email(e):
        return "invalid", ["Invalid email format."]
    local, domain = e.split("@", 1)
    domain = domain.lower()
    score = 0
    if domain in DISPOSABLE_DOMAINS:
        reasons.append("Domain is a known disposable email provider.")
        score += 3
    if domain_resolves(domain):
        reasons.append("Domain resolves (A/AAAA record found).")
    else:
        reasons.append("Domain does NOT resolve — could be fake or typo.")
        score += 2
    if re.search(r"(noreply|no-reply|admin|support|service|secure)", local, re.I):
        reasons.append("Local-part uses generic/service terms (noreply/admin) — be careful with auto messages.")
        score += 1
    if re.search(r"\d{5,}", local):
        reasons.append("Local part has long sequence of digits (common in auto-generated/disposable addresses).")
        score += 1
    try:
        socket.getaddrinfo(domain, 25)
        reasons.append("Appears to accept SMTP connections (port probe possible).")
    except Exception:
        pass
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

# ---------- GUI Helpers (visuals) ----------

def make_primary_btn(master, text, cmd):
    # Use tk.Button for background color that works across platforms
    return tk.Button(master, text=text, command=cmd,
                     bg="#1E9A48", fg="white", activebackground="#14783a",
                     activeforeground="white", bd=0, padx=10, pady=6,
                     font=("Segoe UI", 10, "bold"))

def make_secondary_btn(master, text, cmd):
    return tk.Button(master, text=text, command=cmd,
                     bg="#2E7D8A", fg="white", activebackground="#1B585F",
                     activeforeground="white", bd=0, padx=8, pady=5,
                     font=("Segoe UI", 9, "bold"))

def verdict_style(label_widget, verdict):
    # verdict: 'safe','suspicious','phishing','invalid'
    if verdict == "safe":
        label_widget.config(text="✅ SAFE", fg="#074f1d", bg="#dff7e6")
    elif verdict == "suspicious":
        label_widget.config(text="⚠️ SUSPICIOUS", fg="#6a4a00", bg="#fff7e0")
    elif verdict == "phishing":
        label_widget.config(text="❌ XNOTSAFE", fg="#7a0a08", bg="#ffe6e6")
    elif verdict == "invalid":
        label_widget.config(text="❌ INVALID", fg="#7a0a08", bg="#ffe6e6")
    else:
        label_widget.config(text="ℹ️ RESULT", fg="black", bg="#f0f0f0")
    # bold large font
    label_widget.config(font=("Segoe UI", 16, "bold"), padx=12, pady=8)

class CheckerWindow:
    def __init__(self, master, title="Checker", width=760, height=460, show_banner=False):
        self.win = tk.Toplevel(master)
        self.win.title(title)
        self.win.geometry(f"{width}x{height}")
        self.win.minsize(560, 360)
        try:
            self.win.attributes("-alpha", 0.99)
        except Exception:
            pass

        # Card-style main frame
        outer = tk.Frame(self.win, bg="#eaf6ee")
        outer.pack(expand=True, fill="both")
        frame = tk.Frame(outer, bg="white", bd=0, padx=14, pady=12, relief="flat")
        frame.place(relx=0.02, rely=0.03, relwidth=0.96, relheight=0.94)

        if show_banner:
            title_lbl = tk.Label(frame, text=title, font=("Segoe UI", 14, "bold"), bg="white")
            title_lbl.pack(anchor="n")

        input_row = tk.Frame(frame, bg="white")
        input_row.pack(fill="x", pady=(10, 8))
        self.entry = tk.Entry(input_row, font=("Segoe UI", 12), bd=1, relief="solid")
        self.entry.pack(side="left", expand=True, fill="x", padx=(0, 10))
        self.check_btn = make_primary_btn(input_row, "Check", self.start_check)
        self.check_btn.pack(side="right")

        # Verdict banner
        self.verdict_lbl = tk.Label(frame, text=" ", bg="#f0f0f0", anchor="center")
        self.verdict_lbl.pack(fill="x", pady=(6, 6))

        # Result area
        self.result_text = ScrolledText(frame, wrap="word", font=("Consolas", 11), state="disabled", height=14, bd=1, relief="solid")
        self.result_text.pack(expand=True, fill="both", pady=(4, 4))

        bottom = tk.Frame(frame, bg="white")
        bottom.pack(fill="x", pady=(6,0))
        self.status = tk.Label(bottom, text="Ready", anchor="w", bg="white", font=("Segoe UI", 9))
        self.status.pack(side="left", fill="x", expand=True)
        copy_btn = make_secondary_btn(bottom, "Copy Result", self.copy_result)
        copy_btn.pack(side="right", padx=(8,0))

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
                label, _ = classify_email(query)
            elif "@" in query and not is_valid_email(query):
                res = "❌ Invalid email format."
                label = "invalid"
            else:
                res = analyze_url(query)
                label, _ = classify_url(query)
        except Exception as e:
            res = f"Unexpected error during check: {e}"
            label = "invalid"
        self.win.after(0, self._finish_check, res, label)

    def _finish_check(self, res, label):
        # Update verdict banner (map classify labels to visual label)
        if label == "safe":
            verdict_style(self.verdict_lbl, "safe")
        elif label == "suspicious":
            verdict_style(self.verdict_lbl, "suspicious")
        elif label == "phishing":
            verdict_style(self.verdict_lbl, "phishing")
        elif label == "invalid" or label == "unsafe":
            verdict_style(self.verdict_lbl, "invalid")
        else:
            verdict_style(self.verdict_lbl, None)
        self.append_result(res)
        self.set_status("Done")
        self.check_btn.config(state="normal")

class MainApp:
    def __init__(self, root):
        self.root = root
        root.title("URL & Email Toolkit")
        w, h = 600, 360
        x = (root.winfo_screenwidth() - w) // 2
        y = (root.winfo_screenheight() - h) // 3
        root.geometry(f"{w}x{h}+{x}+{y}")
        root.minsize(520, 300)
        try:
            root.attributes("-alpha", 0.99)
        except Exception:
            pass
        # background
        root.configure(bg="#eaf6ee")

        # top card
        top_card = tk.Frame(root, bg="white", bd=0, padx=12, pady=10)
        top_card.place(relx=0.03, rely=0.04, relwidth=0.94, relheight=0.92)

        title_lbl = tk.Label(top_card, text="URL & Email Security Toolkit", font=("Segoe UI", 15, "bold"), bg="white")
        title_lbl.pack(anchor="n")
        subtitle = tk.Label(top_card, text="Quick checks + Google Safe Browsing (optional). Results: ✅ SAFE / ⚠️ SUSPICIOUS / ❌ XNOTSAFE", font=("Segoe UI", 9), bg="white")
        subtitle.pack(anchor="n", pady=(4,8))

        center = tk.Frame(top_card, bg="white")
        center.pack(expand=True, fill="both")

        btn_frame = tk.Frame(center, bg="white")
        btn_frame.pack(pady=(10,8))

        url_btn = make_primary_btn(btn_frame, "Open URL Checker Window", self.open_url_window)
        url_btn.grid(row=0, column=0, padx=8, pady=6)
        email_btn = make_primary_btn(btn_frame, "Open Email Checker Window", self.open_email_window)
        email_btn.grid(row=0, column=1, padx=8, pady=6)

        quick_frame = tk.Frame(center, bg="white", bd=1, relief="solid", padx=8, pady=8)
        quick_frame.pack(fill="x", padx=12, pady=(10,6))
        tk.Label(quick_frame, text="Quick Check", bg="white", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        row = tk.Frame(quick_frame, bg="white")
        row.pack(fill="x", pady=(6,0))
        self.quick_entry = tk.Entry(row, font=("Segoe UI", 11), bd=1, relief="solid")
        self.quick_entry.pack(side="left", expand=True, fill="x", padx=(0,8))
        quick_btn = make_secondary_btn(row, "Check Fast", self.quick_check)
        quick_btn.pack(side="right")

        footer = tk.Frame(top_card, bg="white")
        footer.pack(fill="x", pady=(6,0))
        tip = "Tip: set env var GOOGLE_SAFE_BROWSING_API_KEY for best results (optional)."
        tk.Label(footer, text=tip, font=("Segoe UI", 9), bg="white").pack(anchor="w")

        self.open_windows = []

    def open_url_window(self):
        w = CheckerWindow(self.root, title="URL Checker", width=820, height=480, show_banner=True)
        w.entry.insert(0, "example.com")
        self.open_windows.append(w)

    def open_email_window(self):
        w = CheckerWindow(self.root, title="Email Checker", width=820, height=480, show_banner=True)
        w.entry.insert(0, "user@example.com")
        self.open_windows.append(w)

    def quick_check(self):
        q = self.quick_entry.get().strip()
        if not q:
            messagebox.showinfo("Info", "Enter URL or email to quick-check.")
            return
        temp = CheckerWindow(self.root, title="Quick Result", width=700, height=380, show_banner=False)
        temp.entry.insert(0, q)
        temp.start_check()
        self.open_windows.append(temp)

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
