#!/usr/bin/env python3
"""
URL & Email Checker — Updated strict email & hostname validation + GUI (green/pro look)
- Stricter email validation (rejects malformed addresses like 'user@!mail.com' or missing '@')
- Hostname validation per-label rules
- DNS resolution impact on scoring
- GUI shows big emoji + bold verdicts (SAFE/SUSPICIOUS/XNOTSAFE/INVALID)
"""

import os
import re
import threading
import requests
import urllib.parse
import socket
import tkinter as tk
from tkinter import messagebox
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

# Disposable and shortener lists
DISPOSABLE_DOMAINS = {
    "mailinator.com", "10minutemail.com", "guerrillamail.com", "yopmail.com",
    "trashmail.com", "temp-mail.org", "dispostable.com", "maildrop.cc"
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly", "is.gd", "tiny.cc", "rb.gy"
}

# ---------- Utilities / Validation ----------

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

def is_valid_hostname(hostname: str) -> bool:
    """
    Validate hostname labels:
     - 1..63 chars per label, overall <=253
     - labels only [A-Za-z0-9-], not start/end with hyphen
     - allow punycode xn--
    """
    if not hostname:
        return False
    # remove port if present and userinfo if present
    host = hostname.split(":")[0].split("@")[-1].strip().lower()
    if len(host) > 253:
        return False
    # allow single-label (like localhost) but still validate characters
    labels = host.split(".")
    for label in labels:
        if not label:
            return False
        if len(label) < 1 or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        # allow punycode prefix 'xn--'
        if label.startswith("xn--"):
            # basic length check done above; accept punycode label
            continue
        if not re.match(r"^[A-Za-z0-9-]+$", label):
            return False
    return True

def is_valid_email(email: str) -> bool:
    """
    Strict but pragmatic email syntax check:
    - Must have single @
    - Local part: letters, digits and allowed punctuation ._%+-' (no spaces or weird chars)
    - Domain part validated by is_valid_hostname
    """
    e = email.strip()
    # Quick basic pattern
    if "@" not in e:
        return False
    parts = e.split("@")
    if len(parts) != 2:
        return False
    local, domain = parts[0], parts[1]
    if not local or not domain:
        return False
    # local part rules: allow these chars, but not start/end with dot, not consecutive dots
    if local.startswith(".") or local.endswith(".") or ".." in local:
        return False
    if not re.match(r"^[A-Za-z0-9._%+\-']+$", local):
        return False
    # domain must be valid hostname (reject illegal chars like '!')
    if not is_valid_hostname(domain):
        return False
    # domain must contain at least one dot (e.g., example.com). Accept 'localhost' only if explicitly wanted (we'll require dot)
    if "." not in domain:
        return False
    return True

# ---------- Networking / API ----------

def check_url_safety_api(url: str, timeout=10):
    """Google Safe Browsing call if API key present."""
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
    """
    HTTP check with clearer DNS vs network error classification.
    Returns either {'status_code', 'final_url', 'ok'} or {'error':'dns'/'network', 'message':...}
    """
    try:
        resp = requests.head(url, allow_redirects=True, timeout=timeout)
        return {"status_code": resp.status_code, "final_url": resp.url, "ok": resp.ok}
    except requests.exceptions.RequestException as e_head:
        msg = str(e_head)
        # DNS error patterns (urllib3 / requests)
        if "Name or service not known" in msg or "Failed to resolve" in msg or "NameResolutionError" in msg or "getaddrinfo failed" in msg:
            return {"error": "dns", "message": msg}
        # fallback to GET
        try:
            resp = requests.get(url, allow_redirects=True, timeout=timeout)
            return {"status_code": resp.status_code, "final_url": resp.url, "ok": resp.ok}
        except requests.exceptions.RequestException as e_get:
            msg2 = str(e_get)
            if "Name or service not known" in msg2 or "Failed to resolve" in msg2 or "NameResolutionError" in msg2 or "getaddrinfo failed" in msg2:
                return {"error": "dns", "message": msg2}
            return {"error": "network", "message": msg2}

def domain_resolves(domain: str) -> bool:
    """Basic check: does domain resolve to A/AAAA?"""
    try:
        # remove port/userinfo
        d = domain.split(":")[0].split("@")[-1]
        socket.getaddrinfo(d, None)
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
    """Classify URL with early invalid-hostname detection and DNS handling."""
    reasons = []
    url_norm = normalize_url(url)
    host = hostname_of(url_norm)

    # Early hostname syntax validation
    if not is_valid_hostname(host):
        reasons.append("Invalid hostname syntax (illegal characters or invalid labels).")
        return "phishing", reasons

    score = 0
    # Google Safe Browsing
    if GOOGLE_SAFE_BROWSING_API_KEY:
        api = check_url_safety_api(url_norm)
        if api and "matches" in api and api["matches"]:
            reasons.append("Detected by Google Safe Browsing as malicious.")
            return "phishing", reasons
        if "error" in api:
            reasons.append(f"Safe Browsing API error: {api['error']}. Proceeding heuristics.")

    # HTTP/DNS check
    http = quick_http_check(url_norm)
    if "error" in http:
        if http["error"] == "dns":
            reasons.append(f"DNS resolution failure: {http.get('message')}")
            score += 3
        else:
            reasons.append(f"Network error: {http.get('message')}")
            score += 1
    else:
        code = http.get("status_code")
        final = http.get("final_url")
        if code and 400 <= code < 600:
            reasons.append(f"Server returned HTTP error status {code}.")
            score += 1
        if final:
            final_host = hostname_of(final)
            if final_host and final_host != host:
                reasons.append(f"Redirects to different host ({final_host}) — possible redirector.")
                score += 2

    # other heuristics
    if re.search(r"^\[?\d{1,3}(\.\d{1,3}){3}\]?$", host) or re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", host):
        reasons.append("Raw IP address used in URL.")
        score += 3
    if host.count(".") >= 4:
        reasons.append("Long subdomain chain (possible obfuscation).")
        score += 2
    if host.startswith("xn--") or "xn--" in host:
        reasons.append("Punycode (xn--) present — IDN homograph risk.")
        score += 3
    if re.search(r"[0-9].*", host) and not re.search(r"[a-zA-Z]", host.split(".")[0]):
        reasons.append("Hostname heavy on digits, few letters.")
        score += 2
    if host.count("-") >= 2:
        reasons.append("Multiple hyphens in hostname.")
        score += 1
    path = urllib.parse.urlparse(url_norm).path.lower()
    suspicious_keywords = ["login", "signin", "secure", "verify", "update", "confirm", "banking", "account", "password", "pay", "checkout"]
    for kw in suspicious_keywords:
        if kw in path or kw in host:
            reasons.append(f"Contains suspicious keyword '{kw}'.")
            score += 1

    if score >= 5:
        reasons.insert(0, f"Suspicion score {score} (higher is worse).")
        return "phishing", reasons
    elif 2 <= score < 5:
        reasons.insert(0, f"Suspicion score {score}.")
        return "suspicious", reasons
    else:
        reasons.insert(0, f"Suspicion score {score}.")
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
        out.append(f"\nHTTP check: {http.get('error')} - {http.get('message')}")
    else:
        out.append(f"\nHTTP status: {http.get('status_code')}  final URL: {http.get('final_url')}")
    return "\n".join(out)

# ---------- Email classification ----------

def classify_email(email: str):
    """
    Strictly classify email:
     - invalid: syntax or illegal domain -> immediate invalid
     - unsafe: disposable domain or clearly suspicious
     - suspicious: domain doesn't resolve, long numeric local, generic local parts
     - safe: passes checks
    """
    e = email.strip()
    reasons = []
    if not is_valid_email(e):
        return "invalid", ["Invalid email format or illegal domain characters."]
    local, domain = e.split("@", 1)
    domain = domain.lower()
    score = 0

    # disposable
    if domain in DISPOSABLE_DOMAINS:
        reasons.append("Domain is a known disposable email provider.")
        score += 3

    # domain resolution
    if domain_resolves(domain):
        reasons.append("Domain resolves (A/AAAA record present).")
    else:
        reasons.append("Domain does NOT resolve publicly.")
        score += 2

    # local-part heuristics
    if re.search(r"(noreply|no-reply|admin|support|service|secure|postmaster)", local, re.I):
        reasons.append("Local-part uses generic/service terms (noreply/admin).")
        score += 1
    if re.search(r"\d{5,}", local):
        reasons.append("Local-part contains long sequence of digits (often auto-generated/disposable).")
        score += 1
    # odd characters already filtered in is_valid_email

    # MX check: lightweight probe (try resolving MX via getaddrinfo on smtp port)
    try:
        socket.getaddrinfo(domain, 25)
        reasons.append("Appears to accept SMTP connections (basic reachability).")
    except Exception:
        # no extra penalty here; domain_resolves already handles missing DNS
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
        out.append("❌ INVALID email format.")
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

# ---------- GUI (visuals) ----------

def make_primary_btn(master, text, cmd):
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
    if verdict == "safe":
        label_widget.config(text="✅ SAFE", fg="#074f1d", bg="#dff7e6")
    elif verdict == "suspicious":
        label_widget.config(text="⚠️ SUSPICIOUS", fg="#6a4a00", bg="#fff7e0")
    elif verdict == "phishing" or verdict == "unsafe":
        label_widget.config(text="❌ XNOTSAFE", fg="#7a0a08", bg="#ffe6e6")
    elif verdict == "invalid":
        label_widget.config(text="❌ INVALID", fg="#7a0a08", bg="#ffe6e6")
    else:
        label_widget.config(text="ℹ️ RESULT", fg="black", bg="#f0f0f0")
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

        self.verdict_lbl = tk.Label(frame, text=" ", bg="#f0f0f0", anchor="center")
        self.verdict_lbl.pack(fill="x", pady=(6, 6))

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
            if "@" in query:
                # Always run strict email validation first if '@' present
                if is_valid_email(query):
                    res = analyze_email(query)
                    label, _ = classify_email(query)
                else:
                    res = "❌ Invalid email format or illegal characters in domain."
                    label = "invalid"
            else:
                res = analyze_url(query)
                label, _ = classify_url(query)
        except Exception as e:
            res = f"Unexpected error during check: {e}"
            label = "invalid"
        self.win.after(0, self._finish_check, res, label)

    def _finish_check(self, res, label):
        if label == "safe":
            verdict_style(self.verdict_lbl, "safe")
        elif label == "suspicious":
            verdict_style(self.verdict_lbl, "suspicious")
        elif label in ("phishing", "unsafe"):
            verdict_style(self.verdict_lbl, "phishing")
        elif label == "invalid":
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
        root.configure(bg="#eaf6ee")

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
    app = MainApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
