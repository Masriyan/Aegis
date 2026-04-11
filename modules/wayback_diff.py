"""
Wayback Machine Diff Engine

Compares current website with archived snapshots to detect:
- JavaScript injection
- Defacement
- New tracking scripts
- Content manipulation
- Backdoor insertion
"""

import aiohttp
import asyncio
import re
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from urllib.parse import quote
import difflib

from .base import BaseModule


class WaybackDiffModule(BaseModule):
    name = "wayback_diff"
    description = "Compares current site with Wayback Machine snapshots to detect JS injection, defacement, or backdoors."
    category = "Tactical OSINT"
    dependencies = []
    rate_limit_rpm = 15

    CDX_API = "https://web.archive.org/cdx/search/cdx"
    WAYBACK_RAW = "https://web.archive.org/web/{timestamp}id_/{url}"

    async def run(self, target: str, session: aiohttp.ClientSession, shared_state: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        results = {
            "target": target,
            "snapshots_available": 0,
            "snapshots_compared": 0,
            "changes_detected": [],
            "suspicious_changes": [],
            "js_changes": [],
            "timeline": [],
        }

        # Step 1: Get available snapshots from CDX API
        snapshots = await self._get_snapshots(session, target)
        results["snapshots_available"] = len(snapshots)

        if len(snapshots) < 1:
            results["message"] = "No Wayback Machine snapshots available for comparison"
            return results

        # Step 2: Fetch current version
        current_html = await self._fetch_current(session, target)
        if not current_html:
            results["error"] = "Could not fetch current page"
            return results

        # Step 3: Fetch most recent archived version
        latest_snapshot = snapshots[0]  # Most recent
        archived_html = await self._fetch_archived(session, target, latest_snapshot["timestamp"])

        if not archived_html:
            results["message"] = "Could not fetch archived snapshot"
            return results

        results["snapshots_compared"] = 1
        results["comparison_snapshot"] = {
            "timestamp": latest_snapshot["timestamp"],
            "date": self._format_timestamp(latest_snapshot["timestamp"]),
        }

        # Step 4: Diff analysis
        changes = self._analyze_diff(current_html, archived_html)
        results["changes_detected"] = changes["all_changes"]
        results["js_changes"] = changes["js_changes"]
        results["suspicious_changes"] = changes["suspicious"]

        # Step 5: Build timeline if multiple snapshots
        if len(snapshots) >= 3:
            # Sample 3 snapshots across time
            indices = [0, len(snapshots) // 2, -1]
            for idx in indices:
                snap = snapshots[idx]
                results["timeline"].append({
                    "timestamp": snap["timestamp"],
                    "date": self._format_timestamp(snap["timestamp"]),
                    "status": snap.get("statuscode", "200"),
                })

        # Risk assessment
        suspicious_count = len(results["suspicious_changes"])
        js_count = len(results["js_changes"])

        if suspicious_count > 0:
            results["risk_assessment"] = (
                f"⚠️ {suspicious_count} suspicious change(s) detected since last archive. "
                "Possible compromise, defacement, or unauthorized modification."
            )
            results["severity"] = "high"
        elif js_count > 0:
            results["risk_assessment"] = (
                f"Found {js_count} JavaScript change(s) since {results['comparison_snapshot']['date']}. "
                "Review for unauthorized script injection."
            )
            results["severity"] = "medium"
        elif results["changes_detected"]:
            results["risk_assessment"] = (
                f"Normal content changes detected since {results['comparison_snapshot']['date']}."
            )
            results["severity"] = "info"
        else:
            results["risk_assessment"] = "No significant changes from archived version."
            results["severity"] = "info"

        return results

    async def _get_snapshots(self, session: aiohttp.ClientSession, url: str) -> List[Dict]:
        """Get list of available snapshots from CDX API."""
        try:
            params = {
                "url": url,
                "output": "json",
                "limit": 20,
                "fl": "timestamp,statuscode,digest,length",
                "filter": "statuscode:200",
                "collapse": "digest",  # Deduplicate identical snapshots
            }
            timeout = aiohttp.ClientTimeout(total=15)
            async with session.get(self.CDX_API, params=params, timeout=timeout) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    if len(data) > 1:  # First row is header
                        headers = data[0]
                        snapshots = []
                        for row in data[1:]:
                            snap = dict(zip(headers, row))
                            snapshots.append(snap)
                        # Sort by timestamp descending (most recent first)
                        snapshots.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
                        return snapshots
        except Exception:
            pass
        return []

    async def _fetch_current(self, session: aiohttp.ClientSession, url: str) -> Optional[str]:
        """Fetch current version of the page."""
        try:
            timeout = aiohttp.ClientTimeout(total=15)
            async with session.get(url, timeout=timeout) as resp:
                if resp.status == 200:
                    return await resp.text(encoding="utf-8", errors="ignore")
        except Exception:
            pass
        return None

    async def _fetch_archived(self, session: aiohttp.ClientSession, url: str, timestamp: str) -> Optional[str]:
        """Fetch an archived snapshot from Wayback Machine."""
        try:
            archive_url = self.WAYBACK_RAW.format(timestamp=timestamp, url=url)
            timeout = aiohttp.ClientTimeout(total=20)
            async with session.get(archive_url, timeout=timeout) as resp:
                if resp.status == 200:
                    text = await resp.text(encoding="utf-8", errors="ignore")
                    # Remove Wayback Machine toolbar injection
                    text = self._strip_wayback_toolbar(text)
                    return text
        except Exception:
            pass
        return None

    def _strip_wayback_toolbar(self, html: str) -> str:
        """Remove the Wayback Machine toolbar from archived HTML."""
        # Remove the comment block and toolbar div
        html = re.sub(r'<!-- BEGIN WAYBACK TOOLBAR INSERT -->.*?<!-- END WAYBACK TOOLBAR INSERT -->', '', html, flags=re.DOTALL)
        html = re.sub(r'<script src="/_static/.*?</script>', '', html, flags=re.DOTALL)
        html = re.sub(r'<link.*?web\.archive\.org.*?/>', '', html)
        return html

    def _analyze_diff(self, current: str, archived: str) -> Dict[str, List]:
        """Analyze differences between current and archived HTML."""
        all_changes = []
        js_changes = []
        suspicious = []

        # Normalize whitespace for comparison
        current_lines = current.splitlines()
        archived_lines = archived.splitlines()

        # Use difflib for structured comparison
        differ = difflib.unified_diff(
            archived_lines, current_lines,
            fromfile="archived", tofile="current",
            lineterm="", n=1
        )

        added_lines = []
        removed_lines = []

        for line in differ:
            if line.startswith("+") and not line.startswith("+++"):
                added_lines.append(line[1:])
            elif line.startswith("-") and not line.startswith("---"):
                removed_lines.append(line[1:])

        # Analyze added content
        for line in added_lines:
            line_lower = line.strip().lower()

            # Check for new script tags
            if "<script" in line_lower:
                js_change = {
                    "type": "script_added",
                    "content": line.strip()[:200],
                    "severity": "medium",
                }

                # Check for suspicious script sources
                if any(s in line_lower for s in [
                    "eval(", "document.write(", "btoa(", "atob(",
                    "String.fromCharCode", "unescape(",
                ]):
                    js_change["severity"] = "high"
                    js_change["suspicious"] = True
                    suspicious.append({
                        "type": "obfuscated_script",
                        "description": "New obfuscated JavaScript detected",
                        "content": line.strip()[:200],
                    })

                # External scripts from unknown domains
                src_match = re.search(r'src=["\']([^"\']+)', line)
                if src_match:
                    src = src_match.group(1)
                    js_change["source"] = src
                    if not any(safe in src.lower() for safe in [
                        "jquery", "bootstrap", "google", "cloudflare",
                        "cdnjs", "jsdelivr", "unpkg",
                    ]):
                        js_change["severity"] = "high"
                        suspicious.append({
                            "type": "unknown_external_script",
                            "description": f"New external script from unknown source: {src}",
                            "content": src,
                        })

                js_changes.append(js_change)

            # Check for new iframes
            if "<iframe" in line_lower:
                suspicious.append({
                    "type": "iframe_added",
                    "description": "New iframe detected",
                    "content": line.strip()[:200],
                })

            # Check for new form actions
            if "<form" in line_lower and "action=" in line_lower:
                action_match = re.search(r'action=["\']([^"\']+)', line)
                if action_match:
                    action = action_match.group(1)
                    suspicious.append({
                        "type": "form_action_changed",
                        "description": f"New form action: {action}",
                        "content": line.strip()[:200],
                    })

            # Check for new tracking/analytics
            if any(t in line_lower for t in [
                "pixel", "tracker", "analytics", "beacon", "fingerprint"
            ]):
                all_changes.append({
                    "type": "tracking",
                    "description": "New tracking code detected",
                    "content": line.strip()[:200],
                })

        # Summarize changes
        total_added = len(added_lines)
        total_removed = len(removed_lines)

        if total_added > 0 or total_removed > 0:
            all_changes.insert(0, {
                "type": "summary",
                "lines_added": total_added,
                "lines_removed": total_removed,
                "description": f"{total_added} lines added, {total_removed} lines removed since archived version",
            })

        return {
            "all_changes": all_changes[:20],
            "js_changes": js_changes[:10],
            "suspicious": suspicious[:10],
        }

    def _format_timestamp(self, ts: str) -> str:
        """Format a Wayback Machine timestamp."""
        try:
            dt = datetime.strptime(ts[:14], "%Y%m%d%H%M%S")
            return dt.strftime("%Y-%m-%d %H:%M")
        except Exception:
            return ts
