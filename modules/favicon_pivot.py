"""
Favicon Hash → Shodan Pivot

Computes the favicon hash and auto-queries Shodan to find ALL servers
using the same favicon — reveals shadow infrastructure, staging servers,
forgotten instances, and related organizations.
"""

import aiohttp
import asyncio
import base64
import hashlib
import struct
import os
from typing import Dict, Any, Optional
from urllib.parse import urljoin

from .base import BaseModule


class FaviconPivotModule(BaseModule):
    name = "favicon_pivot"
    description = "Computes favicon hash and pivots through Shodan to find all servers sharing the same favicon."
    category = "Threat Intelligence"
    dependencies = []
    required_api_key_env = "SHODAN_API_KEY"

    async def run(self, target: str, session: aiohttp.ClientSession, shared_state: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        shodan_key = os.getenv("SHODAN_API_KEY", "")

        results = {
            "favicon_found": False,
            "favicon_url": None,
            "md5": None,
            "mmh3_hash": None,
            "shodan_query": None,
            "related_hosts": [],
            "total_matches": 0,
        }

        # Try to fetch favicon
        favicon_data = None
        favicon_url = None

        for path in ["/favicon.ico", "/favicon.png", "/apple-touch-icon.png"]:
            url = urljoin(target, path)
            try:
                resp = await self.async_fetch(url, session, timeout=aiohttp.ClientTimeout(total=10))
                if resp and resp.status == 200:
                    data = await resp.read()
                    resp.close()
                    if len(data) > 0 and len(data) < 1_000_000:  # Sanity check
                        favicon_data = data
                        favicon_url = url
                        break
            except Exception:
                continue

        if not favicon_data:
            return {"favicon_found": False, "message": "No favicon found"}

        results["favicon_found"] = True
        results["favicon_url"] = favicon_url
        results["size_bytes"] = len(favicon_data)
        results["md5"] = hashlib.md5(favicon_data).hexdigest()

        # Compute MurmurHash3 (Shodan uses this)
        b64_content = base64.encodebytes(favicon_data).decode()
        mmh3_hash = self._mmh3_hash32(b64_content)
        results["mmh3_hash"] = mmh3_hash
        results["shodan_query"] = f"http.favicon.hash:{mmh3_hash}"

        # Auto-pivot through Shodan
        if shodan_key and mmh3_hash:
            loop = asyncio.get_event_loop()
            hosts = await loop.run_in_executor(None, self._shodan_search, shodan_key, mmh3_hash)
            results["related_hosts"] = hosts[:50]
            results["total_matches"] = len(hosts)

            if len(hosts) > 1:
                results["risk_assessment"] = (
                    f"Found {len(hosts)} other hosts with identical favicon. "
                    "This may indicate shared infrastructure, staging environments, or related organizations."
                )
            else:
                results["risk_assessment"] = "Favicon appears unique — no related hosts found via Shodan."

        return results

    def _mmh3_hash32(self, data: str) -> int:
        """Simple MurmurHash3 implementation for favicon hashing."""
        try:
            import mmh3
            return mmh3.hash(data)
        except ImportError:
            # Fallback: pure Python murmurhash3 (32-bit)
            return self._py_mmh3_32(data.encode("utf-8"))

    def _py_mmh3_32(self, key: bytes, seed: int = 0) -> int:
        """Pure Python MurmurHash3 32-bit implementation."""
        length = len(key)
        nblocks = length // 4
        h1 = seed
        c1 = 0xcc9e2d51
        c2 = 0x1b873593
        mask = 0xFFFFFFFF

        for i in range(nblocks):
            k1 = struct.unpack_from("<I", key, i * 4)[0]
            k1 = (k1 * c1) & mask
            k1 = ((k1 << 15) | (k1 >> 17)) & mask
            k1 = (k1 * c2) & mask
            h1 ^= k1
            h1 = ((h1 << 13) | (h1 >> 19)) & mask
            h1 = (h1 * 5 + 0xe6546b64) & mask

        tail = key[nblocks * 4:]
        k1 = 0
        if len(tail) >= 3:
            k1 ^= tail[2] << 16
        if len(tail) >= 2:
            k1 ^= tail[1] << 8
        if len(tail) >= 1:
            k1 ^= tail[0]
            k1 = (k1 * c1) & mask
            k1 = ((k1 << 15) | (k1 >> 17)) & mask
            k1 = (k1 * c2) & mask
            h1 ^= k1

        h1 ^= length
        h1 ^= (h1 >> 16)
        h1 = (h1 * 0x85ebca6b) & mask
        h1 ^= (h1 >> 13)
        h1 = (h1 * 0xc2b2ae35) & mask
        h1 ^= (h1 >> 16)

        # Convert to signed 32-bit
        if h1 >= 0x80000000:
            h1 -= 0x100000000
        return h1

    def _shodan_search(self, api_key: str, mmh3_hash: int) -> list:
        """Search Shodan for hosts with matching favicon hash."""
        try:
            import shodan
            api = shodan.Shodan(api_key)
            results = api.search(f"http.favicon.hash:{mmh3_hash}", limit=50)
            hosts = []
            for match in results.get("matches", []):
                hosts.append({
                    "ip": match.get("ip_str"),
                    "port": match.get("port"),
                    "org": match.get("org"),
                    "hostnames": match.get("hostnames", []),
                    "location": f"{match.get('location', {}).get('country_name', 'Unknown')}",
                    "os": match.get("os"),
                    "product": match.get("product"),
                })
            return hosts
        except Exception:
            return []
