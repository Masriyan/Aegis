"""
Infrastructure Pivot Graph

Builds a network graph of related infrastructure by pivoting through:
- IP → Reverse DNS → Related domains
- Domain → SSL Cert SANs → Related domains
- Domain → NS records → Shared nameserver domains
- Domain → MX records → Shared mail hosting
- Domain → ASN → Neighbor IPs
"""

import aiohttp
import asyncio
import socket
import ssl
import dns.resolver
from typing import Dict, Any, Optional, List, Set
from urllib.parse import urlparse

from .base import BaseModule


class InfraPivotModule(BaseModule):
    name = "infra_pivot"
    description = "Builds an infrastructure relationship graph by pivoting through DNS, SSL, ASN, and reverse DNS data."
    category = "Tactical OSINT"
    dependencies = []

    async def run(self, target: str, session: aiohttp.ClientSession, shared_state: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]

        results = {
            "domain": domain,
            "nodes": [],
            "edges": [],
            "pivots": {
                "ssl_sans": [],
                "ns_shared": [],
                "mx_shared": [],
                "reverse_dns": [],
                "asn_neighbors": [],
            },
            "related_domains": [],
        }

        loop = asyncio.get_event_loop()

        # Resolve target IP
        try:
            ip = socket.gethostbyname(domain)
        except socket.gaierror:
            results["error"] = f"Could not resolve {domain}"
            return results

        # Add root nodes
        results["nodes"].append({"id": domain, "type": "domain", "label": domain, "root": True})
        results["nodes"].append({"id": ip, "type": "ip", "label": ip})
        results["edges"].append({"from": domain, "to": ip, "label": "resolves_to"})

        related = set()

        # Pivot 1: SSL Certificate SANs
        sans = await loop.run_in_executor(None, self._get_ssl_sans, domain)
        for san in sans:
            if san != domain and san != f"*.{domain}":
                results["pivots"]["ssl_sans"].append(san)
                results["nodes"].append({"id": san, "type": "domain", "label": san})
                results["edges"].append({"from": domain, "to": san, "label": "ssl_san"})
                related.add(san)

        # Pivot 2: Nameserver sharing
        ns_records = await loop.run_in_executor(None, self._get_ns_records, domain)
        for ns in ns_records:
            ns_id = f"ns:{ns}"
            results["nodes"].append({"id": ns_id, "type": "nameserver", "label": ns})
            results["edges"].append({"from": domain, "to": ns_id, "label": "ns_record"})

        # Pivot 3: MX records
        mx_records = await loop.run_in_executor(None, self._get_mx_records, domain)
        for mx in mx_records:
            mx_id = f"mx:{mx}"
            results["nodes"].append({"id": mx_id, "type": "mail", "label": mx})
            results["edges"].append({"from": domain, "to": mx_id, "label": "mx_record"})

        # Pivot 4: Reverse DNS on target IP
        rdns = await loop.run_in_executor(None, self._reverse_dns, ip)
        for hostname in rdns:
            if hostname != domain:
                results["pivots"]["reverse_dns"].append(hostname)
                results["nodes"].append({"id": hostname, "type": "domain", "label": hostname})
                results["edges"].append({"from": ip, "to": hostname, "label": "reverse_dns"})
                related.add(hostname)

        # Pivot 5: ASN Neighbor IPs (same /24)
        neighbors = await loop.run_in_executor(None, self._get_neighbors, ip)
        for neighbor_ip, hostname in neighbors:
            if neighbor_ip != ip:
                results["pivots"]["asn_neighbors"].append({
                    "ip": neighbor_ip,
                    "hostname": hostname,
                })
                results["nodes"].append({"id": neighbor_ip, "type": "ip", "label": neighbor_ip})
                results["edges"].append({"from": ip, "to": neighbor_ip, "label": "same_subnet"})
                if hostname:
                    results["nodes"].append({"id": hostname, "type": "domain", "label": hostname})
                    results["edges"].append({"from": neighbor_ip, "to": hostname, "label": "ptr_record"})
                    related.add(hostname)

        results["related_domains"] = list(related)
        results["total_nodes"] = len(results["nodes"])
        results["total_edges"] = len(results["edges"])

        # Summary
        pivots_found = (
            len(results["pivots"]["ssl_sans"]) +
            len(results["pivots"]["reverse_dns"]) +
            len(results["pivots"]["asn_neighbors"])
        )

        if pivots_found > 5:
            results["risk_assessment"] = (
                f"Discovered {len(related)} related domains through infrastructure pivoting. "
                "Review for shadow IT, staging environments, or related organizations."
            )
        else:
            results["risk_assessment"] = f"Infrastructure mapping found {len(related)} related entities."

        return results

    def _get_ssl_sans(self, domain: str) -> List[str]:
        """Extract Subject Alternative Names from SSL certificate."""
        sans = []
        try:
            ctx = ssl.create_default_context()
            conn = socket.create_connection((domain, 443), timeout=5)
            sock = ctx.wrap_socket(conn, server_hostname=domain)
            cert = sock.getpeercert()
            sock.close()

            for field_type, value in cert.get("subjectAltName", []):
                if field_type == "DNS":
                    sans.append(value.lower())
        except Exception:
            pass
        return sans

    def _get_ns_records(self, domain: str) -> List[str]:
        """Get nameserver records."""
        try:
            answers = dns.resolver.resolve(domain, "NS")
            return [str(rdata.target).rstrip(".").lower() for rdata in answers]
        except Exception:
            return []

    def _get_mx_records(self, domain: str) -> List[str]:
        """Get MX records."""
        try:
            answers = dns.resolver.resolve(domain, "MX")
            return [str(rdata.exchange).rstrip(".").lower() for rdata in answers]
        except Exception:
            return []

    def _reverse_dns(self, ip: str) -> List[str]:
        """Reverse DNS lookup."""
        try:
            result = socket.gethostbyaddr(ip)
            hostnames = [result[0]] + list(result[1])
            return [h.lower() for h in hostnames if h]
        except Exception:
            return []

    def _get_neighbors(self, ip: str) -> List[tuple]:
        """Check a few IPs in the same /24 subnet for PTR records."""
        neighbors = []
        parts = ip.split(".")
        if len(parts) != 4:
            return []

        base = ".".join(parts[:3])
        target_last_octet = int(parts[3])

        # Check 5 IPs around the target
        check_range = range(
            max(1, target_last_octet - 3),
            min(255, target_last_octet + 4)
        )

        for last_octet in check_range:
            if last_octet == target_last_octet:
                continue
            neighbor_ip = f"{base}.{last_octet}"
            try:
                hostname = socket.gethostbyaddr(neighbor_ip)[0]
                neighbors.append((neighbor_ip, hostname.lower()))
            except Exception:
                neighbors.append((neighbor_ip, None))

            if len(neighbors) >= 6:
                break

        return neighbors
