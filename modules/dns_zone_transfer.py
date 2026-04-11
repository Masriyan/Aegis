"""
DNS Zone Transfer (AXFR) Test

Attempts a zone transfer against all NS records for the target domain.
A successful AXFR is a critical misconfiguration that exposes the entire DNS zone.
"""

import aiohttp
import asyncio
import dns.resolver
import dns.zone
import dns.query
import dns.rdatatype
from typing import Dict, Any, Optional, List

from .base import BaseModule


class DNSZoneTransferModule(BaseModule):
    name = "dns_zone_transfer"
    description = "Tests for DNS zone transfer (AXFR) misconfiguration — reveals entire DNS zone if vulnerable."
    category = "DNS & Domain Intelligence"
    dependencies = []

    async def run(self, target: str, session: aiohttp.ClientSession, shared_state: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]

        results = {
            "domain": domain,
            "nameservers": [],
            "vulnerable": False,
            "zone_records": [],
            "total_records": 0,
            "tested_ns": 0,
            "vulnerable_ns": [],
        }

        # Get nameservers
        loop = asyncio.get_event_loop()
        ns_records = await loop.run_in_executor(None, self._get_nameservers, domain)
        results["nameservers"] = ns_records

        if not ns_records:
            results["error"] = "Could not resolve nameservers"
            return results

        # Try AXFR against each NS
        for ns in ns_records:
            results["tested_ns"] += 1
            zone_data = await loop.run_in_executor(None, self._try_axfr, domain, ns)

            if zone_data:
                results["vulnerable"] = True
                results["vulnerable_ns"].append(ns)
                results["zone_records"].extend(zone_data)

        results["total_records"] = len(results["zone_records"])

        # Deduplicate records
        seen = set()
        unique_records = []
        for rec in results["zone_records"]:
            key = f"{rec['name']}|{rec['type']}|{rec['value']}"
            if key not in seen:
                seen.add(key)
                unique_records.append(rec)
        results["zone_records"] = unique_records[:500]  # Cap output
        results["total_records"] = len(unique_records)

        if results["vulnerable"]:
            results["severity"] = "critical"
            results["risk_assessment"] = (
                f"CRITICAL: Zone transfer succeeded on {len(results['vulnerable_ns'])} nameserver(s). "
                f"Entire DNS zone ({results['total_records']} records) is exposed."
            )
        else:
            results["severity"] = "info"
            results["risk_assessment"] = "Zone transfer properly restricted on all nameservers."

        return results

    def _get_nameservers(self, domain: str) -> List[str]:
        """Resolve NS records for the domain."""
        try:
            answers = dns.resolver.resolve(domain, "NS")
            return [str(rdata.target).rstrip(".") for rdata in answers]
        except Exception:
            return []

    def _try_axfr(self, domain: str, nameserver: str) -> List[Dict[str, str]]:
        """Attempt zone transfer against a single nameserver."""
        records = []
        try:
            zone = dns.zone.from_xfr(
                dns.query.xfr(nameserver, domain, timeout=10, lifetime=15)
            )
            for name, node in zone.nodes.items():
                for rdataset in node.rdatasets:
                    for rdata in rdataset:
                        records.append({
                            "name": str(name),
                            "type": dns.rdatatype.to_text(rdataset.rdtype),
                            "ttl": rdataset.ttl,
                            "value": str(rdata),
                        })
        except dns.exception.FormError:
            pass  # Zone transfer refused — expected/good
        except dns.query.TransferError:
            pass  # Transfer refused
        except Exception:
            pass  # Connection refused, timeout, etc.
        return records
