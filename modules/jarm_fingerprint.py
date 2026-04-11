"""
JARM TLS Fingerprinting

Creates a fingerprint of a server's TLS implementation.
Servers with the same JARM hash = same software/configuration.
Used to track C2 infrastructure, find related servers, and identify
malicious infrastructure.
"""

import aiohttp
import asyncio
import socket
import ssl
import struct
import hashlib
from typing import Dict, Any, Optional, List

from .base import BaseModule


class JARMFingerprintModule(BaseModule):
    name = "jarm_fingerprint"
    description = "JARM TLS fingerprinting — identifies related infrastructure by matching TLS implementation signatures."
    category = "Threat Intelligence"
    dependencies = []

    # 10 TLS Client Hello packet configurations used by JARM
    JARM_PROBES = [
        # (tls_version, ciphers, extensions, grease)
        {"version": b"\x03\x01", "name": "TLS 1.0 forward", "cipher_order": "forward"},
        {"version": b"\x03\x01", "name": "TLS 1.0 reverse", "cipher_order": "reverse"},
        {"version": b"\x03\x01", "name": "TLS 1.0 top-half", "cipher_order": "top_half"},
        {"version": b"\x03\x02", "name": "TLS 1.1 forward", "cipher_order": "forward"},
        {"version": b"\x03\x02", "name": "TLS 1.1 reverse", "cipher_order": "reverse"},
        {"version": b"\x03\x03", "name": "TLS 1.2 forward", "cipher_order": "forward"},
        {"version": b"\x03\x03", "name": "TLS 1.2 reverse", "cipher_order": "reverse"},
        {"version": b"\x03\x03", "name": "TLS 1.2 middle-out", "cipher_order": "middle_out"},
        {"version": b"\x03\x03", "name": "TLS 1.2 bottom-half", "cipher_order": "bottom_half"},
        {"version": b"\x03\x01", "name": "TLS 1.0 middle-out", "cipher_order": "middle_out"},
    ]

    # Standard cipher suites used in JARM probes
    CIPHERS = [
        0x0016, 0x0033, 0x0067, 0xc09e, 0xc0a2,  # 3DES, DHE
        0x002f, 0x0035, 0x009c, 0x009d, 0xc09c,  # AES-CBC, AES-GCM
        0xc09d, 0xc0a0, 0xc0a1, 0x0039, 0x006b,  # AES-CCM
        0xc013, 0xc014, 0xc023, 0xc024, 0xc027,  # ECDHE suites
        0xc028, 0xc02b, 0xc02c, 0xc02f, 0xc030,
        0xcca8, 0xcca9, 0x1301, 0x1302, 0x1303,  # TLS 1.3 suites
    ]

    async def run(self, target: str, session: aiohttp.ClientSession, shared_state: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]

        results = {
            "domain": domain,
            "jarm_hash": None,
            "probe_results": [],
            "tls_versions_supported": [],
            "raw_fingerprint": "",
        }

        loop = asyncio.get_event_loop()
        raw_responses = []

        for probe in self.JARM_PROBES:
            try:
                response = await asyncio.wait_for(
                    loop.run_in_executor(None, self._send_probe, domain, 443, probe),
                    timeout=10
                )
                raw_responses.append(response)
                results["probe_results"].append({
                    "probe": probe["name"],
                    "response": response,
                })

                if response and response != "|||":
                    version = response.split("|")[0] if "|" in response else ""
                    if version and version not in results["tls_versions_supported"]:
                        results["tls_versions_supported"].append(version)
            except (asyncio.TimeoutError, Exception):
                raw_responses.append("|||")
                results["probe_results"].append({
                    "probe": probe["name"],
                    "response": "timeout",
                })

        # Compute JARM hash
        raw_fp = ",".join(raw_responses)
        results["raw_fingerprint"] = raw_fp

        # The JARM hash is a fuzzy hash of all 10 probe responses
        jarm_hash = self._compute_jarm_hash(raw_responses)
        results["jarm_hash"] = jarm_hash

        # Known JARM hashes for common servers
        known_jarms = self._check_known_jarms(jarm_hash)
        if known_jarms:
            results["known_match"] = known_jarms
            results["risk_assessment"] = f"TLS fingerprint matches: {known_jarms['name']}"
        elif jarm_hash and jarm_hash != "0" * 62:
            results["risk_assessment"] = (
                f"Unique JARM fingerprint: {jarm_hash[:20]}... "
                "Use this to find related infrastructure on Shodan: "
                f"ssl.jarm:\"{jarm_hash}\""
            )
            results["shodan_query"] = f'ssl.jarm:"{jarm_hash}"'
        else:
            results["risk_assessment"] = "Could not generate JARM fingerprint (TLS not available or blocked)"

        return results

    def _send_probe(self, host: str, port: int, probe: dict) -> str:
        """Send a single JARM probe and capture the server response."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))

            # Build Client Hello packet
            client_hello = self._build_client_hello(host, probe)
            sock.send(client_hello)

            # Read Server Hello response
            response = sock.recv(1484)
            sock.close()

            if len(response) < 5:
                return "|||"

            return self._parse_server_hello(response)

        except Exception:
            return "|||"

    def _build_client_hello(self, host: str, probe: dict) -> bytes:
        """Build a TLS Client Hello packet based on probe config."""
        # Simplified Client Hello construction
        version = probe["version"]

        # Order ciphers based on probe config
        ciphers = list(self.CIPHERS)
        order = probe["cipher_order"]
        if order == "reverse":
            ciphers = list(reversed(ciphers))
        elif order == "top_half":
            mid = len(ciphers) // 2
            ciphers = ciphers[:mid]
        elif order == "bottom_half":
            mid = len(ciphers) // 2
            ciphers = ciphers[mid:]
        elif order == "middle_out":
            mid = len(ciphers) // 2
            new_ciphers = []
            for i in range(max(mid, len(ciphers) - mid)):
                if mid + i < len(ciphers):
                    new_ciphers.append(ciphers[mid + i])
                if mid - i - 1 >= 0:
                    new_ciphers.append(ciphers[mid - i - 1])
            ciphers = new_ciphers

        # Cipher bytes
        cipher_bytes = b""
        for c in ciphers:
            cipher_bytes += struct.pack(">H", c)
        cipher_len = struct.pack(">H", len(cipher_bytes))

        # SNI extension
        hostname = host.encode()
        sni = (
            b"\x00\x00"  # Extension type: SNI
            + struct.pack(">H", len(hostname) + 5)
            + struct.pack(">H", len(hostname) + 3)
            + b"\x00"
            + struct.pack(">H", len(hostname))
            + hostname
        )

        # Supported versions extension (for TLS 1.3 probes)
        supported_versions = b"\x00\x2b\x00\x03\x02\x03\x03"

        extensions = sni + supported_versions
        ext_len = struct.pack(">H", len(extensions))

        # Random bytes (32 bytes)
        import os
        random_bytes = os.urandom(32)

        # Session ID
        session_id = b"\x00"  # Empty session ID

        # Compression methods
        compression = b"\x01\x00"  # null compression

        # Client Hello payload
        hello = (
            version
            + random_bytes
            + session_id
            + cipher_len + cipher_bytes
            + compression
            + ext_len + extensions
        )

        hello_len = struct.pack(">I", len(hello))[1:]  # 3 bytes

        # Handshake header
        handshake = b"\x01" + hello_len + hello

        # Record header
        record = (
            b"\x16"  # Content type: Handshake
            + b"\x03\x01"  # TLS 1.0 record version (always)
            + struct.pack(">H", len(handshake))
            + handshake
        )

        return record

    def _parse_server_hello(self, data: bytes) -> str:
        """Parse the Server Hello response."""
        try:
            if len(data) < 11:
                return "|||"

            # Check content type
            content_type = data[0]
            if content_type == 0x15:  # Alert
                alert_level = data[5] if len(data) > 5 else 0
                alert_desc = data[6] if len(data) > 6 else 0
                return f"|||alert_{alert_desc}"

            if content_type != 0x16:  # Not handshake
                return "|||"

            # Record version
            rec_version = f"{data[1]}.{data[2]}"

            # Server Hello starts at offset 5
            handshake_type = data[5]
            if handshake_type != 0x02:  # Not Server Hello
                return "|||"

            # Server Hello version (offset 9-10)
            hello_version = f"{data[9]}.{data[10]}"

            # Cipher suite (offset 11+32+session_id_len)
            session_id_len = data[43] if len(data) > 43 else 0
            cipher_offset = 44 + session_id_len

            if len(data) > cipher_offset + 1:
                cipher = struct.unpack(">H", data[cipher_offset:cipher_offset + 2])[0]
                return f"{hello_version}|{cipher:04x}|{rec_version}"

            return f"{hello_version}||{rec_version}"

        except Exception:
            return "|||"

    def _compute_jarm_hash(self, responses: List[str]) -> str:
        """Compute the JARM hash from probe responses."""
        # Extract meaningful parts
        parts = []
        for resp in responses:
            # Take the cipher and version components
            clean = resp.replace("|||", "000|000|000").replace("timeout", "000|000|000")
            parts.append(clean)

        combined = "|".join(parts)

        if all(r == "|||" or r == "timeout" for r in responses):
            return "0" * 62

        # JARM uses a truncated SHA256 hash
        raw_hash = hashlib.sha256(combined.encode()).hexdigest()
        return raw_hash[:62]

    def _check_known_jarms(self, jarm_hash: str) -> Optional[Dict[str, str]]:
        """Check against known JARM fingerprint database."""
        known = {
            # Common web servers
            "Nginx": ["2ad2ad0002ad", "07d14d16d21d"],
            "Apache": ["2ad2ad16d2ad", "07d14d16d21d"],
            "Cloudflare": ["27d27d27d00027d", "29d29d15d29d"],
            # C2 frameworks
            "Cobalt Strike": ["07d14d16d21d21d07c42d43d00041d"],
            "Metasploit": ["00000000000000000000000000000000"],
        }

        for name, patterns in known.items():
            for pattern in patterns:
                if jarm_hash.startswith(pattern):
                    return {"name": name, "pattern": pattern}

        return None
