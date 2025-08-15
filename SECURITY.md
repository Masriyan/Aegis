# Security Policy

Thank you for helping keep **AEGIS — Automated Enrichment & Global Intelligence Scanner** and its users safe.

> **Use this project ethically.** AEGIS is intended for educational and authorized security testing only.

---

## 📦 Supported Versions

We actively maintain the latest minor release and accept security reports for the versions below.

| Version | Status          |
|--------:|-----------------|
| `main`  | ✅ Supported    |
| `>= 1.0` (latest release series) | ✅ Supported |
| `< 1.0` | ❌ End-of-life  |

> Please reproduce issues against `main` when possible.

---

## 🔔 How to Report a Vulnerability

Please **do not** open public GitHub issues for security vulnerabilities.

- Use GitHub’s **“Report a vulnerability”** (Security Advisories) on this repo; or  
- Email the maintainers at **riyan@security-life.org**.

**Include** a clear description, impact, steps to reproduce (PoC), affected version/commit, and suggested remediation if any.

### Optional: PGP
If you prefer encryption, share your public key or request ours in your first email. Alternatively, attach your own public key and we will reply encrypted.

---

## ⏱️ Disclosure & Response Timeline

We follow **coordinated disclosure**:

- **Acknowledgement:** within **48 hours**  
- **Initial triage:** within **5 business days** (CVSS estimate and scope confirmation)  
- **Fix target:** as quickly as feasible; our general goal is **90 days** from triage. Critical issues may be expedited (7–14 days).  
- **Credit:** We are happy to acknowledge reporters in release notes unless you prefer to remain anonymous.

If a deadline needs extension (e.g., complex dependency chains), we’ll keep you informed.

---

## 🎯 Scope

Reports are **in scope** when they affect code in this repository or the default configuration of AEGIS, including:

- Web UI routes and rendering logic
- OSINT/scan modules (incorrect trust boundaries, command or template injection, SSRF in fetchers, unsafe file writes)
- Local storage & exports (SQLite, JSON/CSV/PDF) handling
- Authentication/authorization (if introduced in the future)
- Supply chain concerns specific to this project (e.g., unsafe update paths, pinned dependency tampering)

### Out of Scope (examples)

- Vulnerabilities in **third‑party services** (VirusTotal, OTX, Shodan, GreyNoise, AbuseIPDB, urlscan.io, crt.sh, Wayback Machine, etc.)  
- **Denial of Service** via excessive volume or repeated heavy scans  
- **Social engineering**, phishing, physical security, or policy issues  
- **Best practice** requests without security impact (e.g., preference for different headers)  
- **Clickjacking** on static pages with no sensitive action  
- **Rate limiting** and generic CAPTCHAs  
- Findings that require privileged local access beyond the app’s normal permissions

If you’re unsure whether something is in scope, contact us privately and we’ll clarify.

---

## 🧪 Rules of Engagement (Good Faith Testing)

To protect users and the ecosystem, please:

1. Do **not** perform destructive testing (no data corruption, no DDoS).  
2. Do **not** exfiltrate more data than necessary to demonstrate impact.  
3. Avoid privacy violations and access to third‑party data.  
4. Use test targets you **own or are authorized** to test.  
5. Follow applicable laws and terms of service.

---

## 🛡️ Safe Harbor

We will **not** pursue legal action or report you for good‑faith, authorized research that adheres to this policy. If legal action is initiated by a third party against you and you have complied with this policy, we will take steps to make it known that your actions were conducted in compliance with this policy.

This safe harbor does **not** cover actions that are illegal, dangerous, or that exceed the scope/methods outlined above.

---

## 🧮 Severity & Triage

We typically assess severity using **CVSS v3.1**. Please feel free to propose a base score or vector as part of your report; we’ll confirm during triage.

Priority is based on a combination of severity, exploitability, and user impact.

---

## 🔗 Third‑Party Dependencies

Security issues found in dependencies should be reported to the **upstream maintainers** first. If a dependency issue impacts AEGIS directly, feel free to notify us as well so we can track, patch, or mitigate.

We strive to keep dependencies current and may ship emergency pins or temporary workarounds when upstream fixes are pending.

---

## 🧾 Report Template

You may use this template when submitting:

```
Title: <short clear title>
Component: <module/route/dependency>
Version/Commit: <tag or commit hash>
Severity (CVSS): <optional vector and score>

Summary:
- <one or two sentences>

Steps to Reproduce:
1) …
2) …
3) …

Impact:
- <what can an attacker achieve?>

Proof of Concept:
- <PoC code or request sequence>

Suggested Remediation:
- <optional fix ideas>

Reporter:
- <name or “Anonymous”>
Contact:
- <email or preferred method>
Disclosure:
- <public after fix? keep private? desire credit?>
```

---

## 🙏 Thanks

We appreciate responsible security research. Your efforts help keep the community safe.
