# Security Policy

## 🛡️ Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |

---

## 🔐 Reporting a Vulnerability

We take security seriously. If you discover a vulnerability in AEGIS, please report it responsibly.

### How to Report

**DO NOT** open a public GitHub issue for security vulnerabilities.

Instead, please use one of these methods:

1. **GitHub Security Advisories** (Preferred)
   - Go to [Security Advisories](https://github.com/Masriyan/Aegis/security/advisories)
   - Click "Report a vulnerability"

2. **Email**
   - Send details to the repository maintainer via GitHub profile

### What to Include

```
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)
- Your contact information (optional)
```

---

## ⏱️ Response Timeline

| Action | Timeframe |
|--------|-----------|
| Initial acknowledgment | 48 hours |
| Preliminary assessment | 7 days |
| Fix development | 14-30 days (severity dependent) |
| Public disclosure | After fix is released |

---

## 🎯 Scope

### In Scope
- Remote code execution
- SQL injection
- Cross-site scripting (XSS)
- Authentication bypass
- Sensitive data exposure
- SSRF vulnerabilities

### Out of Scope
- Denial of Service (DoS)
- Social engineering
- Physical attacks
- Issues in dependencies (report to upstream)
- Issues requiring user-installed malware

---

## 🏆 Recognition

We appreciate responsible disclosure. Contributors who report valid vulnerabilities will be:

- Credited in release notes (unless anonymity is requested)
- Added to our Security Hall of Fame
- Considered for bug bounty rewards (when applicable)

---

## 🔒 Security Best Practices for Users

### When Running AEGIS

1. **API Keys** - Never commit `.env` files or expose API keys
2. **Network** - Run on localhost or behind authentication
3. **Updates** - Keep AEGIS and dependencies updated
4. **Authorization** - Only scan targets you own or have permission to test

### Environment Setup

```bash
# Create .env from template
cp .env.example .env

# Set restrictive permissions
chmod 600 .env

# Never use in production without authentication
# Consider running behind a reverse proxy with auth
```

---

## 📋 Security Checklist for Contributors

- [ ] No hardcoded credentials or secrets
- [ ] Input validation on user-supplied data
- [ ] Proper error handling (no stack traces in production)
- [ ] Dependencies reviewed for known vulnerabilities
- [ ] No arbitrary code execution from user input

---

## 🔗 Related Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/archive/2023/2023_top25_list.html)
- [GitHub Security Best Practices](https://docs.github.com/en/code-security)

---

<p align="center">
  <strong>Thank you for helping keep AEGIS secure! 🛡️</strong>
</p>
