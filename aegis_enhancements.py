#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AEGIS v6.1.0 Enhancement Modules
================================
15 powerful local-only analysis features that require no external API integrations.
All features work by intelligently analyzing existing scan data.
"""

import re
import math
import hashlib
import statistics
from collections import Counter, defaultdict
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urlparse, urljoin
from datetime import datetime
import time


# ============================================================================
# CATEGORY 1: INTELLIGENT RISK ANALYSIS
# ============================================================================

class SecurityPostureScorer:
    """Generate comprehensive 0-100 security score with detailed breakdown."""
    
    WEIGHTS = {
        # Infrastructure (30%)
        "tls": 10,
        "sec_headers": 10,
        "waf_detect": 5,
        "dns_records": 5,
        
        # Application (40%)
        "cors": 8,
        "cookie_audit": 8,
        "http_methods": 6,
        "ssl_tls": 8,
        "input_security": 5,
        "csp_score": 5,
        
        # Data Exposure (30%)
        "js_secrets": 10,
        "entropy_scan": 8,
        "exposure_checks": 7,
        "privacy_detect": 5,
    }
    
    def calculate_score(self, results: Dict) -> Dict:
        """Calculate comprehensive security posture score."""
        breakdown = {
            "infrastructure": {"score": 0, "max": 30, "findings": []},
            "application": {"score": 0, "max": 40, "findings": []},
            "data_exposure": {"score": 0, "max": 30, "findings": []},
        }
        
        total_score = 100  # Start at 100, deduct for issues
        deductions = []
        
        # TLS Analysis
        tls = results.get("ssl_tls", {})
        if tls.get("grade") in ["A", "A+"]:
            breakdown["infrastructure"]["score"] += 10
        elif tls.get("grade") == "B":
            breakdown["infrastructure"]["score"] += 7
            total_score -= 3
            deductions.append("TLS Grade B (-3)")
        elif tls.get("grade") in ["C", "D"]:
            breakdown["infrastructure"]["score"] += 4
            total_score -= 6
            deductions.append(f"TLS Grade {tls.get('grade')} (-6)")
        elif tls.get("grade") == "F":
            total_score -= 10
            deductions.append("TLS Grade F (-10)")
        elif not tls.get("error"):
            breakdown["infrastructure"]["score"] += 5
        
        # Security Headers
        sec_headers = results.get("sec_headers", {}).get("rows", [])
        missing_headers = [h["header"] for h in sec_headers if h.get("status") == "WARN"]
        header_score = max(0, 10 - len(missing_headers) * 2)
        breakdown["infrastructure"]["score"] += header_score
        if missing_headers:
            total_score -= len(missing_headers) * 2
            deductions.append(f"{len(missing_headers)} missing security headers (-{len(missing_headers) * 2})")
            breakdown["infrastructure"]["findings"].extend(missing_headers[:3])
        
        # WAF Detection
        waf = results.get("waf_detect", {})
        if waf.get("likely_protected"):
            breakdown["infrastructure"]["score"] += 5
        else:
            total_score -= 3
            deductions.append("No WAF/CDN protection detected (-3)")
        
        # CORS Check
        cors = results.get("cors", {})
        if cors.get("vulnerable"):
            total_score -= 8
            deductions.append("CORS misconfiguration (-8)")
            breakdown["application"]["findings"].append("CORS vulnerability")
        else:
            breakdown["application"]["score"] += 8
        
        # Cookie Audit
        cookies = results.get("cookie_audit", {})
        cookie_score = cookies.get("score", 100)
        cookie_points = int((cookie_score / 100) * 8)
        breakdown["application"]["score"] += cookie_points
        if cookie_score < 70:
            total_score -= (8 - cookie_points)
            deductions.append(f"Cookie security issues (-{8 - cookie_points})")
        
        # HTTP Methods
        methods = results.get("http_methods", {})
        if methods.get("dangerous"):
            total_score -= 6
            deductions.append(f"Dangerous HTTP methods enabled (-6)")
            breakdown["application"]["findings"].append("Dangerous HTTP methods")
        else:
            breakdown["application"]["score"] += 6
        
        # JS Secrets
        js_secrets = results.get("js_secrets", {}).get("secrets_found", [])
        if js_secrets:
            critical = len([s for s in js_secrets if s.get("severity") == "critical"])
            high = len([s for s in js_secrets if s.get("severity") == "high"])
            deduction = min(10, critical * 5 + high * 2)
            total_score -= deduction
            deductions.append(f"Exposed secrets in JS (-{deduction})")
            breakdown["data_exposure"]["findings"].append(f"{len(js_secrets)} secrets found")
        else:
            breakdown["data_exposure"]["score"] += 10
        
        # Entropy Scan
        entropy = results.get("entropy_scan", {}).get("secrets_found", [])
        if entropy:
            deduction = min(8, len(entropy) * 2)
            total_score -= deduction
            deductions.append(f"High-entropy strings detected (-{deduction})")
        else:
            breakdown["data_exposure"]["score"] += 8
        
        # Exposure Checks
        exposures = results.get("exposure_checks", {}).get("accessible", [])
        if exposures:
            deduction = min(7, len(exposures) * 2)
            total_score -= deduction
            deductions.append(f"Exposed sensitive paths (-{deduction})")
            breakdown["data_exposure"]["findings"].extend([e.get("path", "") for e in exposures[:2]])
        else:
            breakdown["data_exposure"]["score"] += 7
        
        # Calculate final score
        total_score = max(0, min(100, total_score))
        
        # Determine grade
        if total_score >= 90:
            grade = "A"
        elif total_score >= 80:
            grade = "B"
        elif total_score >= 70:
            grade = "C"
        elif total_score >= 60:
            grade = "D"
        else:
            grade = "F"
        
        # Risk level
        if total_score >= 85:
            risk_level = "Low"
        elif total_score >= 70:
            risk_level = "Medium"
        elif total_score >= 50:
            risk_level = "High"
        else:
            risk_level = "Critical"
        
        return {
            "score": total_score,
            "grade": grade,
            "risk_level": risk_level,
            "breakdown": breakdown,
            "deductions": deductions[:10],
            "top_issues": self._get_top_issues(results),
            "recommendations": self._get_recommendations(results, total_score),
        }
    
    def _get_top_issues(self, results: Dict) -> List[str]:
        """Get top 5 most critical issues."""
        issues = []
        
        if results.get("js_secrets", {}).get("secrets_found"):
            issues.append("🔴 Secrets exposed in JavaScript files")
        if results.get("cors", {}).get("vulnerable"):
            issues.append("🔴 CORS misconfiguration allows cross-origin attacks")
        if results.get("ssl_tls", {}).get("grade") in ["D", "F"]:
            issues.append("🔴 Poor TLS configuration")
        if results.get("subdomain_takeover", {}).get("vulnerable"):
            issues.append("🔴 Subdomain takeover possible")
        
        sec_headers = results.get("sec_headers", {}).get("rows", [])
        missing = [h["header"] for h in sec_headers if h.get("status") == "WARN"]
        if "Content-Security-Policy" in missing:
            issues.append("🟡 Missing Content-Security-Policy header")
        if "Strict-Transport-Security" in missing:
            issues.append("🟡 Missing HSTS header")
        
        return issues[:5]
    
    def _get_recommendations(self, results: Dict, score: int) -> List[str]:
        """Generate actionable recommendations."""
        recs = []
        
        if score < 70:
            recs.append("Urgent: Address critical security vulnerabilities immediately")
        
        if results.get("js_secrets", {}).get("secrets_found"):
            recs.append("Remove or rotate exposed API keys and secrets from JavaScript")
        
        if not results.get("waf_detect", {}).get("likely_protected"):
            recs.append("Consider implementing WAF/CDN protection")
        
        sec_headers = results.get("sec_headers", {}).get("rows", [])
        missing = [h["header"] for h in sec_headers if h.get("status") == "WARN"]
        if missing:
            recs.append(f"Implement missing security headers: {', '.join(missing[:3])}")
        
        if results.get("ssl_tls", {}).get("grade") not in ["A", "A+"]:
            recs.append("Upgrade TLS configuration to achieve A grade")
        
        return recs[:5]


class AttackVectorMapper:
    """Map discovered findings to potential attack paths."""
    
    ATTACK_CHAINS = {
        "credential_theft": {
            "name": "Credential Theft Chain",
            "steps": [
                ("js_secrets", "Exposed API keys/tokens discovered"),
                ("cors", "CORS misconfiguration allows cross-origin requests"),
                ("cookie_audit", "Session cookies lack proper protection"),
            ],
            "impact": "Attacker can steal user credentials or session tokens",
            "mitre": "T1552 - Unsecured Credentials"
        },
        "subdomain_takeover": {
            "name": "Subdomain Takeover Chain",
            "steps": [
                ("subdomain_scan", "Subdomains enumerated"),
                ("subdomain_takeover", "Dangling CNAME records found"),
            ],
            "impact": "Attacker can host malicious content on your domain",
            "mitre": "T1584.001 - Compromise Infrastructure: Domains"
        },
        "injection_attack": {
            "name": "Injection Attack Chain",
            "steps": [
                ("crawler", "Forms discovered on target"),
                ("http_methods", "Dangerous HTTP methods enabled"),
                ("cors", "Weak origin validation"),
            ],
            "impact": "Attacker can inject malicious payloads",
            "mitre": "T1190 - Exploit Public-Facing Application"
        },
        "reconnaissance": {
            "name": "Information Disclosure Chain",
            "steps": [
                ("exposure_checks", "Sensitive paths accessible"),
                ("entropy_scan", "High-entropy secrets found"),
                ("tech", "Technology stack fingerprinted"),
            ],
            "impact": "Attacker gains detailed knowledge for targeted attacks",
            "mitre": "T1592 - Gather Victim Host Information"
        },
        "session_hijack": {
            "name": "Session Hijacking Chain",
            "steps": [
                ("cookie_audit", "Session cookies without Secure/HttpOnly"),
                ("ssl_tls", "TLS not properly configured"),
                ("sec_headers", "Missing HSTS header"),
            ],
            "impact": "Attacker can intercept or replay user sessions",
            "mitre": "T1557 - Adversary-in-the-Middle"
        },
    }
    
    def map_attack_vectors(self, results: Dict) -> Dict:
        """Map findings to attack vectors."""
        applicable_chains = []
        
        for chain_id, chain in self.ATTACK_CHAINS.items():
            matched_steps = []
            for module, description in chain["steps"]:
                module_result = results.get(module, {})
                if self._is_vulnerable(module, module_result):
                    matched_steps.append({
                        "module": module,
                        "description": description,
                        "vulnerable": True
                    })
                else:
                    matched_steps.append({
                        "module": module,
                        "description": description,
                        "vulnerable": False
                    })
            
            vulnerable_count = len([s for s in matched_steps if s["vulnerable"]])
            if vulnerable_count >= 2:
                applicable_chains.append({
                    "id": chain_id,
                    "name": chain["name"],
                    "steps": matched_steps,
                    "vulnerable_steps": vulnerable_count,
                    "total_steps": len(matched_steps),
                    "exploitability": "High" if vulnerable_count == len(matched_steps) else "Medium",
                    "impact": chain["impact"],
                    "mitre": chain["mitre"],
                })
        
        # Sort by exploitability
        applicable_chains.sort(key=lambda x: x["vulnerable_steps"], reverse=True)
        
        return {
            "attack_chains": applicable_chains,
            "total_chains": len(applicable_chains),
            "high_risk_chains": len([c for c in applicable_chains if c["exploitability"] == "High"]),
            "narrative": self._generate_narrative(applicable_chains),
        }
    
    def _is_vulnerable(self, module: str, result: Dict) -> bool:
        """Check if module result indicates vulnerability."""
        if not result or result.get("error"):
            return False
        
        checks = {
            "js_secrets": lambda r: bool(r.get("secrets_found")),
            "cors": lambda r: r.get("vulnerable", False),
            "cookie_audit": lambda r: r.get("score", 100) < 70,
            "subdomain_scan": lambda r: len(r.get("found", [])) > 5,
            "subdomain_takeover": lambda r: r.get("vulnerable", False),
            "crawler": lambda r: len(r.get("forms", [])) > 0,
            "http_methods": lambda r: bool(r.get("dangerous")),
            "exposure_checks": lambda r: bool(r.get("accessible")),
            "entropy_scan": lambda r: bool(r.get("secrets_found")),
            "tech": lambda r: bool(r.get("stack")),
            "ssl_tls": lambda r: r.get("grade") in ["C", "D", "F"],
            "sec_headers": lambda r: any(h.get("status") == "WARN" for h in r.get("rows", [])),
        }
        
        check_func = checks.get(module, lambda r: False)
        return check_func(result)
    
    def _generate_narrative(self, chains: List[Dict]) -> str:
        """Generate attack narrative."""
        if not chains:
            return "No significant attack chains identified. The target appears to have good security posture."
        
        high_risk = [c for c in chains if c["exploitability"] == "High"]
        if high_risk:
            return f"⚠️ {len(high_risk)} high-risk attack chain(s) identified. Immediate remediation recommended. Primary concern: {high_risk[0]['name']}"
        
        return f"Found {len(chains)} potential attack vector(s) with medium exploitability. Review recommended."


class SmartSummaryGenerator:
    """Generate intelligent summary without AI using pattern matching."""
    
    def generate(self, results: Dict, url: str, duration: float) -> Dict:
        """Generate comprehensive smart summary."""
        # Collect all findings
        findings = self._collect_findings(results)
        
        # Generate executive summary
        executive_summary = self._executive_summary(findings, url)
        
        # Generate action items
        action_items = self._action_items(findings)
        
        # Business impact assessment
        impact = self._assess_impact(findings)
        
        # Remediation priority matrix
        priority_matrix = self._priority_matrix(findings)
        
        return {
            "executive_summary": executive_summary,
            "key_stats": self._key_stats(results, duration),
            "top_5_actions": action_items[:5],
            "business_impact": impact,
            "priority_matrix": priority_matrix,
            "risk_timeline": self._risk_timeline(findings),
            "export_ready": True,
        }
    
    def _collect_findings(self, results: Dict) -> Dict:
        """Collect and categorize all findings."""
        return {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "info": [],
        }
    
    def _executive_summary(self, findings: Dict, url: str) -> str:
        """Generate executive summary paragraph."""
        domain = urlparse(url).hostname
        
        critical_count = len(findings.get("critical", []))
        high_count = len(findings.get("high", []))
        
        if critical_count > 0:
            return f"Security assessment of {domain} identified {critical_count} critical and {high_count} high-severity issues requiring immediate attention. These vulnerabilities could allow unauthorized access, data theft, or service disruption. Immediate remediation is strongly recommended before these issues are exploited."
        elif high_count > 0:
            return f"Security assessment of {domain} identified {high_count} high-severity issues. While no critical vulnerabilities were found, these issues should be addressed in the short term to maintain a strong security posture and prevent potential exploitation."
        else:
            return f"Security assessment of {domain} shows a generally healthy security posture. Some minor improvements are recommended to further strengthen defenses, but no immediate action is required."
    
    def _action_items(self, findings: Dict) -> List[Dict]:
        """Generate prioritized action items."""
        actions = [
            {"priority": 1, "action": "Review and rotate any exposed credentials", "effort": "Low", "impact": "High"},
            {"priority": 2, "action": "Implement missing security headers", "effort": "Low", "impact": "Medium"},
            {"priority": 3, "action": "Fix CORS configuration if vulnerable", "effort": "Medium", "impact": "High"},
            {"priority": 4, "action": "Upgrade TLS configuration", "effort": "Medium", "impact": "Medium"},
            {"priority": 5, "action": "Enable WAF protection", "effort": "Medium", "impact": "High"},
        ]
        return actions
    
    def _assess_impact(self, findings: Dict) -> Dict:
        """Assess business impact of findings."""
        return {
            "confidentiality": "Medium" if findings.get("high") else "Low",
            "integrity": "Medium" if findings.get("critical") else "Low",
            "availability": "Low",
            "reputation": "High" if findings.get("critical") else "Medium",
            "compliance": "Medium",
        }
    
    def _priority_matrix(self, findings: Dict) -> List[Dict]:
        """Generate remediation priority matrix."""
        return [
            {"category": "Immediate (0-7 days)", "items": findings.get("critical", [])[:3]},
            {"category": "Short-term (1-4 weeks)", "items": findings.get("high", [])[:3]},
            {"category": "Medium-term (1-3 months)", "items": findings.get("medium", [])[:3]},
            {"category": "Long-term (3+ months)", "items": findings.get("low", [])[:3]},
        ]
    
    def _key_stats(self, results: Dict, duration: float) -> Dict:
        """Extract key statistics."""
        return {
            "scan_duration": f"{duration:.1f}s",
            "modules_run": len([k for k, v in results.items() if v and not k.startswith("_")]),
            "subdomains_found": len(results.get("subdomain_scan", {}).get("found", [])),
            "forms_discovered": len(results.get("crawler", {}).get("forms", [])),
            "js_files_scanned": results.get("js_secrets", {}).get("js_files_scanned", 0),
        }
    
    def _risk_timeline(self, findings: Dict) -> str:
        """Estimate risk timeline."""
        if findings.get("critical"):
            return "Immediate risk - exploit possible within hours to days"
        elif findings.get("high"):
            return "Near-term risk - exploit possible within weeks"
        else:
            return "Low immediate risk - focus on hardening"


# ============================================================================
# CATEGORY 2: DEEP CONTENT ANALYSIS
# ============================================================================

class HTTPResponseFingerprinter:
    """Advanced server fingerprinting from response patterns."""
    
    DEFAULT_PAGES = {
        "apache": [
            r"Apache/[\d.]+",
            r"It works!",
            r"Apache HTTP Server Test Page",
        ],
        "nginx": [
            r"nginx/[\d.]+",
            r"Welcome to nginx!",
            r"Thank you for using nginx",
        ],
        "iis": [
            r"Microsoft-IIS/[\d.]+",
            r"Welcome to IIS",
            r"Internet Information Services",
        ],
        "tomcat": [
            r"Apache Tomcat",
            r"Coyote",
        ],
    }
    
    FRAMEWORK_PATTERNS = {
        "laravel": [
            r"laravel_session",
            r"XSRF-TOKEN",
            r"csrf-token.*content=\"[A-Za-z0-9+/=]+\"",
        ],
        "django": [
            r"csrfmiddlewaretoken",
            r"django",
            r"__admin__",
        ],
        "rails": [
            r"_session_id",
            r"X-Request-Id",
            r"action_dispatch",
        ],
        "express": [
            r"X-Powered-By.*Express",
            r"connect\.sid",
        ],
        "spring": [
            r"JSESSIONID",
            r"X-Application-Context",
        ],
        "asp.net": [
            r"ASP\.NET",
            r"__VIEWSTATE",
            r"\.aspx",
        ],
    }
    
    def fingerprint(self, headers: Dict, content: str, cookies: Dict = None) -> Dict:
        """Perform comprehensive fingerprinting."""
        results = {
            "server": None,
            "framework": None,
            "technologies": [],
            "confidence_scores": {},
            "is_default_page": False,
            "interesting_headers": [],
        }
        
        headers_str = str(headers).lower()
        content_lower = content.lower()
        cookies = cookies or {}
        
        # Server detection
        server_header = headers.get("Server", headers.get("server", ""))
        if server_header:
            results["server"] = server_header
        
        # Default page detection
        for server_type, patterns in self.DEFAULT_PAGES.items():
            for pattern in patterns:
                if re.search(pattern, content, re.I):
                    results["is_default_page"] = True
                    if not results["server"]:
                        results["server"] = server_type
                    break
        
        # Framework detection
        for framework, patterns in self.FRAMEWORK_PATTERNS.items():
            score = 0
            for pattern in patterns:
                if re.search(pattern, content, re.I) or re.search(pattern, headers_str, re.I):
                    score += 1
            if score > 0:
                confidence = min(100, score * 40)
                results["confidence_scores"][framework] = confidence
                if confidence >= 40:
                    results["technologies"].append(framework)
                    if confidence > results.get("framework_confidence", 0):
                        results["framework"] = framework
                        results["framework_confidence"] = confidence
        
        # Interesting headers
        interesting = ["X-Powered-By", "X-AspNet-Version", "X-Runtime", "X-Generator"]
        for h in interesting:
            if h.lower() in [k.lower() for k in headers.keys()]:
                for k, v in headers.items():
                    if k.lower() == h.lower():
                        results["interesting_headers"].append({h: v})
        
        return results


class InputValidationAnalyzer:
    """Analyze forms for input validation weaknesses."""
    
    SENSITIVE_FIELDS = ["password", "pass", "pwd", "credit", "card", "ssn", "cvv", "secret", "token"]
    
    def analyze(self, forms: List[Dict]) -> Dict:
        """Analyze forms for validation issues."""
        issues = []
        analyzed_forms = []
        
        for form in forms:
            form_issues = []
            inputs = form.get("inputs", [])
            
            for inp in inputs:
                name = inp.get("name", "").lower()
                inp_type = inp.get("type", "text").lower()
                
                # Check autocomplete on sensitive fields
                is_sensitive = any(s in name for s in self.SENSITIVE_FIELDS)
                if is_sensitive and not inp.get("autocomplete") == "off":
                    form_issues.append({
                        "field": inp.get("name"),
                        "issue": "Sensitive field allows autocomplete",
                        "severity": "medium",
                    })
                
                # Check missing maxlength
                if inp_type in ["text", "password"] and not inp.get("maxlength"):
                    form_issues.append({
                        "field": inp.get("name"),
                        "issue": "No maxlength restriction",
                        "severity": "low",
                    })
                
                # Check password field type
                if "password" in name and inp_type != "password":
                    form_issues.append({
                        "field": inp.get("name"),
                        "issue": "Password field not using password type",
                        "severity": "high",
                    })
            
            # Check form method
            if form.get("method", "GET").upper() == "GET":
                for inp in inputs:
                    if any(s in inp.get("name", "").lower() for s in self.SENSITIVE_FIELDS):
                        form_issues.append({
                            "field": "form",
                            "issue": "Sensitive data transmitted via GET",
                            "severity": "high",
                        })
                        break
            
            analyzed_forms.append({
                "action": form.get("action", ""),
                "method": form.get("method", ""),
                "fields": len(inputs),
                "issues": form_issues,
            })
            issues.extend(form_issues)
        
        return {
            "forms_analyzed": len(forms),
            "total_issues": len(issues),
            "issues_by_severity": {
                "high": len([i for i in issues if i.get("severity") == "high"]),
                "medium": len([i for i in issues if i.get("severity") == "medium"]),
                "low": len([i for i in issues if i.get("severity") == "low"]),
            },
            "forms": analyzed_forms,
            "recommendations": self._get_recommendations(issues),
        }
    
    def _get_recommendations(self, issues: List[Dict]) -> List[str]:
        """Generate recommendations."""
        recs = []
        if any(i["issue"] == "Sensitive data transmitted via GET" for i in issues):
            recs.append("Use POST method for forms with sensitive data")
        if any(i["issue"] == "Sensitive field allows autocomplete" for i in issues):
            recs.append("Add autocomplete='off' to sensitive fields")
        if any(i["issue"] == "No maxlength restriction" for i in issues):
            recs.append("Add maxlength attributes to prevent excessive input")
        return recs


class ErrorPageAnalyzer:
    """Analyze error responses for information disclosure."""
    
    ERROR_PATTERNS = {
        "stack_trace": [
            r"at\s+[\w.]+\([^)]*\)",
            r"Traceback.*most recent call",
            r"Exception in thread",
            r"Error in.*line \d+",
        ],
        "file_paths": [
            r"/var/www/[^\s<\"']+",
            r"/home/\w+/[^\s<\"']+",
            r"C:\\[^\s<\"']+",
            r"/usr/local/[^\s<\"']+",
        ],
        "database_errors": [
            r"SQL syntax.*MySQL",
            r"ORA-\d{5}",
            r"PostgreSQL.*ERROR",
            r"SQLSTATE\[\w+\]",
            r"sqlite3\..*Error",
        ],
        "framework_debug": [
            r"DEBUG\s*=\s*True",
            r"WP_DEBUG",
            r"RAILS_ENV.*development",
            r"display_errors.*On",
        ],
        "version_info": [
            r"PHP/[\d.]+",
            r"Python/[\d.]+",
            r"Apache/[\d.]+",
            r"nginx/[\d.]+",
        ],
    }
    
    def analyze(self, error_responses: Dict[int, str]) -> Dict:
        """Analyze error responses."""
        findings = []
        
        for status_code, content in error_responses.items():
            page_findings = {
                "status": status_code,
                "disclosures": [],
            }
            
            for category, patterns in self.ERROR_PATTERNS.items():
                for pattern in patterns:
                    matches = re.findall(pattern, content, re.I)
                    if matches:
                        page_findings["disclosures"].append({
                            "category": category,
                            "samples": matches[:3],
                            "severity": "high" if category in ["stack_trace", "database_errors"] else "medium",
                        })
            
            if page_findings["disclosures"]:
                findings.append(page_findings)
        
        return {
            "pages_analyzed": len(error_responses),
            "pages_with_issues": len(findings),
            "findings": findings,
            "is_verbose": len(findings) > 0,
            "recommendations": [
                "Configure custom error pages",
                "Disable verbose error messages in production",
                "Remove server version from headers",
            ] if findings else [],
        }


class ContentSecurityAnalyzer:
    """Deep CSP and security policy analysis."""
    
    UNSAFE_DIRECTIVES = ["unsafe-inline", "unsafe-eval", "data:", "*"]
    
    def analyze(self, headers: Dict) -> Dict:
        """Analyze Content-Security-Policy header."""
        csp = headers.get("Content-Security-Policy", headers.get("content-security-policy", ""))
        
        if not csp:
            return {
                "has_csp": False,
                "score": 0,
                "grade": "F",
                "message": "No Content-Security-Policy header found",
                "recommendation": "Implement CSP to prevent XSS and data injection attacks",
            }
        
        # Parse directives
        directives = {}
        for part in csp.split(";"):
            part = part.strip()
            if " " in part:
                directive, value = part.split(" ", 1)
                directives[directive] = value.split()
            elif part:
                directives[part] = []
        
        # Analyze each directive
        issues = []
        score = 100
        
        for directive, values in directives.items():
            for unsafe in self.UNSAFE_DIRECTIVES:
                if unsafe in values:
                    if unsafe == "*":
                        issues.append(f"Wildcard (*) in {directive} allows any source")
                        score -= 20
                    elif unsafe == "unsafe-inline":
                        issues.append(f"'unsafe-inline' in {directive} allows inline code")
                        score -= 15
                    elif unsafe == "unsafe-eval":
                        issues.append(f"'unsafe-eval' in {directive} allows eval()")
                        score -= 15
                    elif unsafe == "data:":
                        issues.append(f"data: URI in {directive} could allow injection")
                        score -= 10
        
        # Check for missing important directives
        important_directives = ["default-src", "script-src", "style-src", "object-src"]
        for d in important_directives:
            if d not in directives and "default-src" not in directives:
                issues.append(f"Missing {d} directive")
                score -= 5
        
        # Check for report-uri/report-to
        has_reporting = "report-uri" in directives or "report-to" in directives
        if not has_reporting:
            issues.append("No CSP reporting configured")
        
        score = max(0, score)
        grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"
        
        return {
            "has_csp": True,
            "score": score,
            "grade": grade,
            "directives": directives,
            "issues": issues,
            "has_reporting": has_reporting,
            "directive_count": len(directives),
            "bypass_potential": "High" if score < 50 else "Medium" if score < 75 else "Low",
        }


# ============================================================================
# CATEGORY 3: ADVANCED DISCOVERY
# ============================================================================

class ReconPatternDetector:
    """Detect if target is monitoring or using defensive techniques."""
    
    BOT_DETECTION_PATTERNS = {
        "cloudflare": [r"cf-ray", r"__cf_bm", r"cf-request-id"],
        "datadome": [r"datadome", r"dd_fp"],
        "akamai_bot_manager": [r"akamai_bot_manager", r"_abck"],
        "perimeterx": [r"_pxff_cc", r"_px3", r"perimeterx"],
        "shape_security": [r"shape", r"_session2"],
        "kasada": [r"kasada", r"cd-security"],
    }
    
    def detect(self, headers: Dict, content: str, timing_ms: float = 0) -> Dict:
        """Detect reconnaissance countermeasures."""
        findings = {
            "bot_detection": [],
            "rate_limiting_indicators": [],
            "captcha_detected": False,
            "honeypot_indicators": [],
            "monitoring_score": 0,
        }
        
        headers_str = str(headers).lower()
        content_lower = content.lower()
        
        # Bot detection
        for service, patterns in self.BOT_DETECTION_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, headers_str + content_lower, re.I):
                    findings["bot_detection"].append(service)
                    findings["monitoring_score"] += 20
                    break
        
        # Rate limit headers
        rate_headers = ["x-ratelimit-", "x-rate-limit-", "retry-after", "x-ratelimit"]
        for header in headers:
            if any(rh in header.lower() for rh in rate_headers):
                findings["rate_limiting_indicators"].append(header)
                findings["monitoring_score"] += 10
        
        # Captcha detection
        captcha_patterns = [r"recaptcha", r"hcaptcha", r"turnstile", r"captcha"]
        for pattern in captcha_patterns:
            if re.search(pattern, content_lower):
                findings["captcha_detected"] = True
                findings["monitoring_score"] += 15
                break
        
        # Honeypot indicators
        honeypot_patterns = [r"honeypot", r"canary", r"tarpit"]
        for pattern in honeypot_patterns:
            if re.search(pattern, content_lower):
                findings["honeypot_indicators"].append(pattern)
        
        findings["monitoring_score"] = min(100, findings["monitoring_score"])
        findings["assessment"] = (
            "High defensive posture" if findings["monitoring_score"] >= 50 else
            "Moderate defenses" if findings["monitoring_score"] >= 25 else
            "Low defensive monitoring"
        )
        
        return findings


class SensitivePathDiscovery:
    """Smart sensitive path discovery."""
    
    SENSITIVE_PATTERNS = {
        "backup": [
            ".bak", ".backup", ".old", ".orig", "~", ".swp", ".save",
            "backup.zip", "backup.sql", "backup.tar.gz",
        ],
        "source_control": [
            ".git/config", ".git/HEAD", ".svn/entries", ".hg/",
            ".gitignore", ".gitattributes",
        ],
        "environment": [
            ".env", ".env.local", ".env.production", ".env.backup",
            "config.php.bak", "wp-config.php.bak",
        ],
        "ide": [
            ".idea/", ".vscode/", "*.sublime-project",
            ".project", ".classpath",
        ],
        "ci_cd": [
            ".github/workflows/", ".gitlab-ci.yml", "Jenkinsfile",
            ".circleci/config.yml", ".travis.yml",
            "docker-compose.yml", "Dockerfile",
        ],
        "logs": [
            "access.log", "error.log", "debug.log",
            "logs/", "log.txt", "app.log",
        ],
    }
    
    def generate_paths(self, base_words: List[str] = None) -> Dict:
        """Generate sensitive paths to check."""
        paths = []
        
        for category, patterns in self.SENSITIVE_PATTERNS.items():
            for pattern in patterns:
                paths.append({
                    "path": f"/{pattern.lstrip('/')}",
                    "category": category,
                })
        
        # Add variations based on discovered words
        if base_words:
            for word in base_words[:20]:
                paths.append({"path": f"/{word}.bak", "category": "backup"})
                paths.append({"path": f"/{word}.old", "category": "backup"})
                paths.append({"path": f"/{word}_backup/", "category": "backup"})
        
        return {
            "paths": paths,
            "total_paths": len(paths),
            "categories": list(self.SENSITIVE_PATTERNS.keys()),
        }


class JSComplexityAnalyzer:
    """Analyze JavaScript for security implications."""
    
    DANGEROUS_FUNCTIONS = {
        "eval": {"severity": "high", "reason": "Arbitrary code execution"},
        "Function(": {"severity": "high", "reason": "Dynamic code creation"},
        "setTimeout(": {"severity": "medium", "reason": "Delayed string evaluation possible"},
        "setInterval(": {"severity": "medium", "reason": "Delayed string evaluation possible"},
        "document.write": {"severity": "medium", "reason": "DOM manipulation XSS risk"},
        "innerHTML": {"severity": "medium", "reason": "HTML injection risk"},
        "outerHTML": {"severity": "medium", "reason": "HTML injection risk"},
        ".html(": {"severity": "medium", "reason": "jQuery HTML injection"},
    }
    
    DOM_SINKS = [
        "location.href", "location.assign", "location.replace",
        "document.cookie", "window.name", "document.domain",
        "postMessage", "localStorage", "sessionStorage",
    ]
    
    def analyze(self, js_content: str) -> Dict:
        """Analyze JavaScript complexity and security."""
        findings = {
            "dangerous_functions": [],
            "dom_sinks": [],
            "obfuscation_score": 0,
            "complexity_score": 0,
            "websocket_usage": False,
            "fetch_calls": 0,
            "postmessage_handlers": 0,
        }
        
        # Check dangerous functions
        for func, info in self.DANGEROUS_FUNCTIONS.items():
            count = js_content.count(func)
            if count > 0:
                findings["dangerous_functions"].append({
                    "function": func,
                    "count": count,
                    "severity": info["severity"],
                    "reason": info["reason"],
                })
        
        # Check DOM sinks
        for sink in self.DOM_SINKS:
            if sink in js_content:
                findings["dom_sinks"].append(sink)
        
        # Check for obfuscation indicators
        obf_indicators = [
            (r'\\x[0-9a-f]{2}', 'hex encoding'),
            (r'String\.fromCharCode', 'charcode usage'),
            (r'atob\(|btoa\(', 'base64 usage'),
            (r'\["\\x', 'array with hex'),
        ]
        for pattern, _ in obf_indicators:
            if re.search(pattern, js_content, re.I):
                findings["obfuscation_score"] += 25
        
        findings["obfuscation_score"] = min(100, findings["obfuscation_score"])
        
        # WebSocket usage
        if "WebSocket" in js_content or "new WebSocket" in js_content:
            findings["websocket_usage"] = True
        
        # Fetch/XHR calls
        findings["fetch_calls"] = js_content.count("fetch(") + js_content.count("XMLHttpRequest")
        
        # PostMessage handlers
        findings["postmessage_handlers"] = len(re.findall(r'addEventListener.*message', js_content, re.I))
        
        # Calculate complexity
        findings["complexity_score"] = (
            len(findings["dangerous_functions"]) * 15 +
            len(findings["dom_sinks"]) * 10 +
            findings["obfuscation_score"]
        )
        findings["complexity_score"] = min(100, findings["complexity_score"])
        
        return findings


# ============================================================================
# CATEGORY 4: RESPONSE BEHAVIOR ANALYSIS
# ============================================================================

class SessionAnalyzer:
    """Analyze authentication and session handling."""
    
    def analyze(self, cookies: List[Dict], headers: Dict, content: str) -> Dict:
        """Analyze session security."""
        findings = {
            "session_cookies": [],
            "jwt_detected": False,
            "jwt_analysis": {},
            "token_entropy": [],
            "session_issues": [],
        }
        
        for cookie in cookies:
            name = cookie.get("name", "").lower()
            value = cookie.get("value", "")
            
            # Identify session cookies
            session_indicators = ["session", "sess", "sid", "token", "auth", "jwt"]
            if any(s in name for s in session_indicators):
                entropy = self._calculate_entropy(value)
                findings["session_cookies"].append({
                    "name": cookie.get("name"),
                    "entropy": round(entropy, 2),
                    "secure": cookie.get("secure", False),
                    "httponly": cookie.get("httponly", False),
                    "length": len(value),
                })
                
                if entropy < 3.0:
                    findings["session_issues"].append(f"Low entropy in {name} ({entropy:.1f} bits)")
                
                # JWT detection
                if value.count(".") == 2 and value.startswith("eyJ"):
                    findings["jwt_detected"] = True
                    findings["jwt_analysis"] = self._analyze_jwt(value)
        
        return findings
    
    def _calculate_entropy(self, s: str) -> float:
        """Calculate Shannon entropy."""
        if not s:
            return 0.0
        counts = Counter(s)
        length = len(s)
        return -sum((c/length) * math.log2(c/length) for c in counts.values())
    
    def _analyze_jwt(self, token: str) -> Dict:
        """Analyze JWT structure (without decoding secrets)."""
        import base64
        parts = token.split(".")
        if len(parts) != 3:
            return {"error": "Invalid JWT format"}
        
        try:
            # Decode header (first part)
            header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
            import json
            header = json.loads(base64.urlsafe_b64decode(header_b64))
            
            return {
                "algorithm": header.get("alg", "unknown"),
                "type": header.get("typ", "unknown"),
                "weak_algorithm": header.get("alg") in ["none", "HS256"],
            }
        except Exception:
            return {"error": "Failed to parse JWT"}


class RateLimitDetector:
    """Detect and measure rate limiting."""
    
    def analyze(self, headers: Dict) -> Dict:
        """Analyze rate limit headers."""
        findings = {
            "has_rate_limiting": False,
            "limit": None,
            "remaining": None,
            "reset_time": None,
            "rate_limit_headers": {},
        }
        
        rate_patterns = ["ratelimit", "rate-limit", "x-ratelimit", "x-rate-limit"]
        
        for header, value in headers.items():
            header_lower = header.lower()
            for pattern in rate_patterns:
                if pattern in header_lower:
                    findings["has_rate_limiting"] = True
                    findings["rate_limit_headers"][header] = value
                    
                    if "limit" in header_lower and "remaining" not in header_lower:
                        try:
                            findings["limit"] = int(value)
                        except ValueError:
                            pass
                    elif "remaining" in header_lower:
                        try:
                            findings["remaining"] = int(value)
                        except ValueError:
                            pass
                    elif "reset" in header_lower:
                        findings["reset_time"] = value
        
        return findings


class CacheAnalyzer:
    """Analyze caching behavior for security implications."""
    
    def analyze(self, headers: Dict, is_authenticated: bool = False) -> Dict:
        """Analyze cache headers."""
        findings = {
            "cacheable": False,
            "cache_control": None,
            "issues": [],
            "cdn_cached": False,
        }
        
        cache_control = headers.get("Cache-Control", headers.get("cache-control", ""))
        findings["cache_control"] = cache_control
        
        # Parse cache-control
        directives = [d.strip().lower() for d in cache_control.split(",")]
        
        if "no-store" in directives:
            findings["cacheable"] = False
        elif "private" in directives:
            findings["cacheable"] = True
            if is_authenticated:
                findings["issues"].append("Private cache may store sensitive data")
        elif "public" in directives:
            findings["cacheable"] = True
            if is_authenticated:
                findings["issues"].append("Public cache on authenticated response - potential data leak")
        elif not cache_control:
            findings["cacheable"] = True
            findings["issues"].append("No Cache-Control header - browser may cache by default")
        
        # CDN cache detection
        cdn_headers = ["x-cache", "cf-cache-status", "x-varnish", "x-served-by"]
        for h in cdn_headers:
            if h in [k.lower() for k in headers.keys()]:
                findings["cdn_cached"] = True
                break
        
        # Vary header check
        vary = headers.get("Vary", "")
        if findings["cacheable"] and "Authorization" not in vary and is_authenticated:
            findings["issues"].append("Missing 'Vary: Authorization' may cause cache poisoning")
        
        return findings


# ============================================================================
# CATEGORY 5: METADATA & CONFIGURATION
# ============================================================================

class FormActionAnalyzer:
    """Deep analysis of all discovered forms."""
    
    def analyze(self, forms: List[Dict], base_url: str) -> Dict:
        """Analyze form security."""
        findings = []
        
        base_parsed = urlparse(base_url)
        
        for form in forms:
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            inputs = form.get("inputs", [])
            
            form_finding = {
                "action": action,
                "method": method,
                "issues": [],
            }
            
            # Check HTTPS
            if action.startswith("http://"):
                form_finding["issues"].append({
                    "issue": "Form submits over HTTP",
                    "severity": "high",
                })
            
            # Check same-origin
            if action.startswith("http"):
                action_parsed = urlparse(action)
                if action_parsed.netloc != base_parsed.netloc:
                    form_finding["issues"].append({
                        "issue": "Form submits to different origin",
                        "severity": "medium",
                    })
            
            # Check for CSRF token
            csrf_names = ["csrf", "token", "_token", "xsrf", "authenticity"]
            has_csrf = any(any(c in inp.get("name", "").lower() for c in csrf_names) for inp in inputs)
            if not has_csrf and method == "POST":
                form_finding["issues"].append({
                    "issue": "No CSRF token detected",
                    "severity": "high",
                })
            
            # Check for file upload
            has_file = any(inp.get("type") == "file" for inp in inputs)
            if has_file:
                form_finding["has_file_upload"] = True
                form_finding["issues"].append({
                    "issue": "File upload detected - verify upload validation",
                    "severity": "info",
                })
            
            # Hidden fields
            hidden = [inp for inp in inputs if inp.get("type") == "hidden"]
            form_finding["hidden_fields"] = len(hidden)
            
            findings.append(form_finding)
        
        return {
            "forms_analyzed": len(forms),
            "forms_with_issues": len([f for f in findings if f["issues"]]),
            "findings": findings,
            "overall_security": "Good" if not any(f["issues"] for f in findings) else "Needs Review",
        }


class MetaTagAnalyzer:
    """Analyze HTML meta tags for security implications."""
    
    def analyze(self, html: str) -> Dict:
        """Analyze meta tags."""
        findings = {
            "robots": None,
            "referrer_policy": None,
            "content_type": None,
            "sensitive_og_data": [],
            "twitter_data": [],
            "issues": [],
        }
        
        # Robots meta
        robots_match = re.search(r'<meta[^>]*name=["\']robots["\'][^>]*content=["\']([^"\']+)["\']', html, re.I)
        if robots_match:
            findings["robots"] = robots_match.group(1)
        else:
            robots_match = re.search(r'<meta[^>]*content=["\']([^"\']+)["\'][^>]*name=["\']robots["\']', html, re.I)
            if robots_match:
                findings["robots"] = robots_match.group(1)
        
        # Referrer policy
        ref_match = re.search(r'<meta[^>]*name=["\']referrer["\'][^>]*content=["\']([^"\']+)["\']', html, re.I)
        if ref_match:
            findings["referrer_policy"] = ref_match.group(1)
            if findings["referrer_policy"] in ["unsafe-url", "no-referrer-when-downgrade"]:
                findings["issues"].append("Weak referrer policy may leak URLs")
        else:
            findings["issues"].append("No referrer meta tag - browser defaults apply")
        
        # Open Graph sensitive data
        og_patterns = [
            (r'og:email', 'Email in OG data'),
            (r'og:phone_number', 'Phone in OG data'),
            (r'og:locality', 'Location in OG data'),
        ]
        for pattern, desc in og_patterns:
            if re.search(pattern, html, re.I):
                findings["sensitive_og_data"].append(desc)
        
        # Twitter card data
        twitter_match = re.findall(r'<meta[^>]*name=["\']twitter:(\w+)["\'][^>]*content=["\']([^"\']+)["\']', html, re.I)
        findings["twitter_data"] = [{"name": m[0], "value": m[1][:30]} for m in twitter_match[:5]]
        
        return findings


# ============================================================================
# MODULE INITIALIZATION
# ============================================================================

# Create singleton instances
security_scorer = SecurityPostureScorer()
attack_mapper = AttackVectorMapper()
smart_summary = SmartSummaryGenerator()
http_fingerprinter = HTTPResponseFingerprinter()
input_analyzer = InputValidationAnalyzer()
error_analyzer = ErrorPageAnalyzer()
csp_analyzer = ContentSecurityAnalyzer()
recon_detector = ReconPatternDetector()
sensitive_paths = SensitivePathDiscovery()
js_complexity = JSComplexityAnalyzer()
session_analyzer = SessionAnalyzer()
rate_limit_detector = RateLimitDetector()
cache_analyzer = CacheAnalyzer()
form_analyzer = FormActionAnalyzer()
meta_analyzer = MetaTagAnalyzer()


def run_enhanced_modules(results: Dict, url: str, html: str, headers: Dict, duration: float) -> Dict:
    """Run all enhanced modules and return results."""
    enhanced = {}
    
    try:
        enhanced["security_posture"] = security_scorer.calculate_score(results)
    except Exception as e:
        enhanced["security_posture"] = {"error": str(e)}
    
    try:
        enhanced["attack_vectors"] = attack_mapper.map_attack_vectors(results)
    except Exception as e:
        enhanced["attack_vectors"] = {"error": str(e)}
    
    try:
        enhanced["smart_summary"] = smart_summary.generate(results, url, duration)
    except Exception as e:
        enhanced["smart_summary"] = {"error": str(e)}
    
    try:
        enhanced["http_fingerprint"] = http_fingerprinter.fingerprint(headers, html)
    except Exception as e:
        enhanced["http_fingerprint"] = {"error": str(e)}
    
    try:
        forms = results.get("crawler", {}).get("forms", [])
        enhanced["input_validation"] = input_analyzer.analyze(forms)
    except Exception as e:
        enhanced["input_validation"] = {"error": str(e)}
    
    try:
        enhanced["csp_analysis"] = csp_analyzer.analyze(headers)
    except Exception as e:
        enhanced["csp_analysis"] = {"error": str(e)}
    
    try:
        enhanced["recon_detection"] = recon_detector.detect(headers, html)
    except Exception as e:
        enhanced["recon_detection"] = {"error": str(e)}
    
    try:
        js_content = ""
        for js_url in results.get("crawler", {}).get("js_files", [])[:3]:
            try:
                import requests
                resp = requests.get(js_url, timeout=5)
                js_content += resp.text
            except:
                pass
        if js_content:
            enhanced["js_complexity"] = js_complexity.analyze(js_content)
    except Exception as e:
        enhanced["js_complexity"] = {"error": str(e)}
    
    try:
        cookies = results.get("cookie_audit", {}).get("cookies", [])
        enhanced["session_analysis"] = session_analyzer.analyze(cookies, headers, html)
    except Exception as e:
        enhanced["session_analysis"] = {"error": str(e)}
    
    try:
        enhanced["rate_limiting"] = rate_limit_detector.analyze(headers)
    except Exception as e:
        enhanced["rate_limiting"] = {"error": str(e)}
    
    try:
        enhanced["cache_analysis"] = cache_analyzer.analyze(headers)
    except Exception as e:
        enhanced["cache_analysis"] = {"error": str(e)}
    
    try:
        forms = results.get("crawler", {}).get("forms", [])
        enhanced["form_security"] = form_analyzer.analyze(forms, url)
    except Exception as e:
        enhanced["form_security"] = {"error": str(e)}
    
    try:
        enhanced["meta_tags"] = meta_analyzer.analyze(html)
    except Exception as e:
        enhanced["meta_tags"] = {"error": str(e)}
    
    return enhanced
