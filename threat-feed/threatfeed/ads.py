"""
Free-tier advertising.

Two sources of inventory:
* House / direct-sold ads from config/ads.json (weighted rotation). These
  are what you sell directly to security vendors -- the most valuable
  inventory for a niche B2B audience.
* An optional ad network slot (EthicalAds) rendered client-side for unsold
  impressions.

Every ad is served with sponsored=True and the UI labels it "Sponsored":
in a threat-intel feed an ad that could be mistaken for an alert is both a
trust problem and an FTC disclosure problem.
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass(frozen=True)
class Ad:
    id: str
    advertiser: str
    headline: str
    body: str
    cta: str
    url: str
    weight: int = 1

    def as_item(self) -> dict:
        return {"type": "ad", "sponsored": True, "id": self.id, "advertiser": self.advertiser,
                "headline": self.headline, "body": self.body, "cta": self.cta,
                "click_url": f"/api/ads/{self.id}/click"}


class AdServer:
    def __init__(self, ads: list[Ad], network: dict | None = None, rng: random.Random | None = None):
        for a in ads:
            if urlparse(a.url).scheme != "https":
                raise ValueError(f"ad {a.id}: landing URL must be https")
        self.ads = {a.id: a for a in ads}
        self.network = network or {}
        self._rng = rng or random.Random()

    @classmethod
    def from_file(cls, path: str, ethicalads_publisher: str = "") -> "AdServer":
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except FileNotFoundError:
            data = {"ads": []}
        ads = [Ad(**a) for a in data.get("ads", [])]
        network = {"provider": "ethicalads", "publisher": ethicalads_publisher} if ethicalads_publisher else None
        return cls(ads, network)

    def pick(self) -> Ad | None:
        if not self.ads:
            return None
        ads = list(self.ads.values())
        return self._rng.choices(ads, weights=[a.weight for a in ads], k=1)[0]

    def interleave(self, items: list[dict], every_n: int) -> list[dict]:
        """Insert a sponsored card after every `every_n` posts (0 = none)."""
        if every_n <= 0:
            return items
        out = []
        for i, item in enumerate(items, 1):
            out.append(item)
            if i % every_n == 0:
                ad = self.pick()
                if ad:
                    out.append(ad.as_item())
                elif self.network:
                    out.append({"type": "ad", "sponsored": True, "network": self.network})
        return out
