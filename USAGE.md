# How to Use the Security Toolkit (Simple Guide)

This is a friendly, step-by-step guide for everyday users. No security expertise needed.

> ⚠️ **Only scan things you own or are allowed to test.** Your own website, your own
> computer, or a system you have written permission to check. That's it.

---

## 1. Install it (one time)

You need **Python 3.8 or newer**. Then open a terminal (Command Prompt / PowerShell
on Windows, Terminal on Mac/Linux) and run:

```bash
pip install git+https://github.com/pratikdagar100/securitytoolkit.git
```

For the full set of features, also run:

```bash
pip install "dnspython psutil pefile reportlab"
```

That's it. Now the command `security-toolkit` works anywhere.

---

## 2. The easiest way: the menu

Just type this and press Enter:

```bash
security-toolkit
```

You'll see a menu with a short explanation next to every option:

```
  #  Option                          What it does
 1.  Case Management                 Create/list cases and mark which targets you may test
 2.  Reconnaissance / OSINT          Passively look up public info (DNS, IP, WHOIS, certificate)
 3.  Network Assessment              Find open ports and running services on a host/network
 4.  Website Security Assessment     Check a site's headers, HTTPS, cookies, CORS, TLS certificate
 5.  SQL Injection Exposure Check    Safely test URL parameters for signs of SQL injection
 6.  XSS Exposure Check              Safely test URL parameters for reflected cross-site scripting
 7.  API Security Assessment         Check an API's methods, auth, headers and rate limiting
 8.  Availability / DoS Symptom      Measure response time/failures to spot slowness (not an attack)
 9.  Log & SOC Analysis              Scan a log file for brute-force logins and scanning attempts
10.  Host Security Assessment        Inspect THIS computer: processes, listening ports, users
11.  Malware / File Triage           Safely examine a file (hashes, strings) without running it
12.  Evidence Management             List the evidence collected and stored for a case
13.  Generate Report                 Build a JSON/CSV/HTML/PDF report for a case
14.  External Tools Status           Show which optional tools (Nmap, Amass, ...) are installed
15.  Configuration                   Show where your workspace and settings live
 0.  Exit                            Quit the toolkit
```

Type a number, press Enter, and answer the questions it asks (like "what website?").
The toolkit does the rest and shows you the results. To leave, type `0`.

**Tip:** A good order to try is `1` (make a case) → `2` (look things up) →
`4` (check a website) → `13` (make a report).

**That's all most people need.** The sections below are for doing it by typing commands.

---

## 3. Understand 3 simple words

The toolkit is careful about what it's allowed to do. You pick a "mode":

| Mode | What it means | When to use |
|------|---------------|-------------|
| **PASSIVE** | Just look things up. Never pokes the target. | Safe default. Always allowed. |
| **ASSESSMENT** | Runs real checks (headers, ports, etc.). | Your own site/network. |
| **AUTHORIZED_LAB** | Deeper testing on practice/lab machines. | Only test labs you set up. |

If you don't say a mode, it uses **PASSIVE** (the safest one).

---

## 4. A complete example (copy–paste)

Let's check a website you own, step by step.

```bash
# Step 1: Start a "case" (a folder to hold your results)
security-toolkit case create --name "My website checkup"

# It prints a case number like CASE-2026-001. Use that below.

# Step 2: Tell it the target IS allowed
security-toolkit case target --case CASE-2026-001 --target yoursite.com --authorized

# Step 3: Look up basic info (safe, passive)
security-toolkit recon --case CASE-2026-001 --target yoursite.com

# Step 4: Check the website's security (needs the "assessment" mode)
security-toolkit web --case CASE-2026-001 --target https://yoursite.com --profile-auth ASSESSMENT

# Step 5: Make a nice report you can open in your browser
security-toolkit report --case CASE-2026-001 --format html
```

The last command tells you where the report file was saved. Double-click it to open it.

---

## 5. Other handy commands

**Check your own computer:**
```bash
security-toolkit host
```

**Analyze a log file for hacking attempts (like failed logins):**
```bash
security-toolkit logs --target path/to/your/logfile.log
```

**Check if a downloaded file is suspicious (does NOT run the file):**
```bash
security-toolkit file --target path/to/file.exe
```

**See which extra tools you have installed (like Nmap):**
```bash
security-toolkit tools
```

---

## 6. Reading the results

Every result is shown as a clear block, for example:

```
Finding: Missing Content-Security-Policy
Severity: MEDIUM
Confidence: HIGH
Evidence: The response had no Content-Security-Policy header.
Recommendation: Add a Content-Security-Policy to your site.
```

- **Severity** = how serious it is: INFO → LOW → MEDIUM → HIGH → CRITICAL.
- **Confidence** = how sure the tool is. LOW confidence means "double-check this yourself."
- **Recommendation** = what to do about it.

At the end you get a **Risk Score** (0 = great, 100 = lots of problems).

---

## 7. Common questions

**Where are my results saved?**
In a folder called `.security_toolkit` inside your home directory. Reports live inside
each case folder.

**It said "authorization denied" — did I break something?**
No. That's the safety net. It means you tried a real check without marking the target
as allowed. Add `--authorized` and use `--profile-auth ASSESSMENT`, like in Step 4 above.

**Do I need Nmap, VirusTotal, etc.?**
No. They're optional. The toolkit works without them and just uses them if they're there.

**Is this legal to run?**
Only on systems you own or have permission to test. Scanning other people's systems
without permission can be illegal. When in doubt, don't.

---

## Need more detail?

See the full [README](readme.md) for advanced options and the complete command list.
