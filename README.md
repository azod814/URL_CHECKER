# URL & Email Security Toolkit — Quick README

| Section | Details |
|--------|---------|
| **Project Name** | URL & Email Security Toolkit |
| **Description** | Tkinter GUI tool to check if a URL or Email is SAFE, SUSPICIOUS, or XNOTSAFE (PHISHING) using heuristics, HTTP checks, and optional Google Safe Browsing API. |
| **Features** | • GUI windows: URL Checker + Email Checker<br>• Quick Check popup<br>• Results: ✅ SAFE / ⚠️ SUSPICIOUS / ❌ XNOTSAFE<br>• Google Safe Browsing support<br>• Detects punycode, raw IP, redirects, shorteners, long queries<br>• Email checks: disposable domain + DNS resolution |
| **Required Modules** | `requests` |
| **Optional Modules** | `pyfiglet`, `termcolor` (for console banner) |
| **Built-in Modules Used** | `tkinter`, `threading`, `socket`, `urllib`, `re`, `os` |
| **Install Dependencies** | ```bash\npip install requests\npip install pyfiglet termcolor   # optional\n``` |
| **Clone Repository** | ```bash\ngit clone https://github.com/<your-username>/url-email-security-toolkit.git\ncd url-email-security-toolkit\n``` |
| **Create Virtual Environment** | **Linux/macOS:**<br>```bash\npython3 -m venv venv\nsource venv/bin/activate\n```<br>**Windows (PowerShell):**<br>```powershell\npython -m venv venv\n.\venv\Scripts\Activate.ps1\n``` |
| **Optional: Google Safe Browsing API Key** | **Linux/macOS:**<br>```bash\nexport GOOGLE_SAFE_BROWSING_API_KEY="YOUR_KEY"\n```<br>**Windows CMD:**<br>```cmd\nset GOOGLE_SAFE_BROWSING_API_KEY=YOUR_KEY\n```<br>**Windows PowerShell:**<br>```powershell\n$env:GOOGLE_SAFE_BROWSING_API_KEY="YOUR_KEY"\n``` |
| **Run Application** | ```bash\npython url_email_checker.py\n``` |
| **Suggested Files** | • url_email_checker.py<br>• requirements.txt<br>• README.md<br>• .gitignore |
| **requirements.txt Example** | ```text\nrequests>=2.28\npyfiglet>=0.8.1\ntermcolor>=1.1.0\n``` |
| **Result Meanings** | • **SAFE** — no strong indicators<br>• **SUSPICIOUS** — some heuristics triggered<br>• **XNOTSAFE** — highly unsafe or flagged by Google |
| **Troubleshooting** | • Install Tkinter if missing: `sudo apt install python3-tk`<br>• Requests error = missing module or no internet<br>• Google API error = invalid/missing API key |
| **Future Enhancements** | MX lookup, typosquatting detection, CSV export logs, dark mode |
| **Update Project** | ```bash\ngit add .\ngit commit -m "update"\ngit push origin main\n``` |
| **License** | MIT (recommended) |
