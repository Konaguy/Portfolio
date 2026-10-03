"""
Synthetic posts so the app is fully usable with no API keys (local dev,
sales demos). Clearly labelled: source "demo", handles under @demo-*,
indicators from RFC 5737 documentation IP ranges and the reserved .example
TLD, and CVE ids in the 9xxxxx range so they cannot be mistaken for real
advisories.
"""

from __future__ import annotations

import random
import secrets
import time

import httpx

from ..models import RawPost

AUTHORS = [("Demo Malware Lab", "demo-malwarelab"), ("Demo Threat Hunter", "demo-hunter"),
           ("Demo Reverse Engineer", "demo-re"), ("Demo DFIR Team", "demo-dfir"), ("Demo Vuln Watch", "demo-vulnwatch")]

TEMPLATES = [
    "🚨 {cve} in {product} is being actively exploited in the wild. No patch yet — treat as 0day. "
    "Mass scanning from {ip}. #{tag}",
    "New {family} infostealer campaign spreading via fake {product} updates. C2: {domain} / {ip}. "
    "SHA256 {sha}. #malware #{tag}",
    "Ransomware outbreak: {family} affiliates hitting {product} servers, double extortion, leak site live. "
    "Initial access via {cve}. #ransomware",
    "PoC published for {cve} ({product} auth bypass, CVSS 9.8). Expect exploitation within hours. Patch now. #{tag}",
    "Malicious npm package typosquatting {product}-utils drops a backdoor; pulls payload from hxxps://{domain}/p.js "
    "#supplychain",
    "Phishing wave using {product} lures and AiTM kits, credential harvest pages on {domain}. #phishing",
    "Botnet {family} added {cve} to its exploit kit — worm-like spreading observed, {ip} among top scanners. #{tag}",
    "Interesting {family} loader sample, md5 {md5}, sideloads via signed {product} binary. Writeup soon.",
]
PRODUCTS = ["EdgeGate VPN", "Acme FileShare", "Contoso Mail", "NimbusCI", "OrbitCMS", "Fabrikam SSO"]
FAMILIES = ["DemoStealer", "SampleLoader", "MockLocker", "TestBot", "PlaceholderRAT"]
TAGS = ["edgegate", "fileshare0day", "mocklocker", "threatintel"]


class DemoSource:
    name = "demo"

    def __init__(self, posts_per_poll: tuple[int, int] = (1, 3), seed: int | None = None):
        self._rng = random.Random(seed)
        self._range = posts_per_poll
        # A small, stable CVE pool so repeated mentions produce visible trends.
        self._cves = [f"CVE-2026-9{self._rng.randint(10000, 99999)}" for _ in range(4)]

    def _domain(self) -> str:
        return f"{self._rng.choice(['update', 'cdn', 'login', 'files'])}-{self._rng.randint(10, 99)}[.]example"

    def generate(self, n: int) -> list[RawPost]:
        out = []
        for _ in range(n):
            name, handle = self._rng.choice(AUTHORS)
            text = self._rng.choice(TEMPLATES).format(
                cve=self._rng.choice(self._cves), product=self._rng.choice(PRODUCTS),
                family=self._rng.choice(FAMILIES), tag=self._rng.choice(TAGS),
                ip=f"203.0.113[.]{self._rng.randint(1, 254)}", domain=self._domain(),
                sha=self._rng.randbytes(32).hex(), md5=self._rng.randbytes(16).hex(),
            )
            nid = secrets.token_hex(8)
            out.append(RawPost(source="demo", native_id=nid, author=name, author_handle=handle,
                               url=f"https://example.com/demo/{nid}", text=text, created_at=time.time()))
        return out

    async def fetch(self, client: httpx.AsyncClient) -> list[RawPost]:
        return self.generate(self._rng.randint(*self._range))
