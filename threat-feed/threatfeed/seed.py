"""
Backfill demo history so a fresh install has something to show (the Free
tier's 15-minute delay otherwise means an empty first screen).

    python -m threatfeed.seed --hours 48 --posts 300
"""

from __future__ import annotations

import argparse
import random
import time

from .config import Settings
from .enrich import enrich
from .sources.demo import DemoSource
from .store import Store


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--hours", type=float, default=48)
    ap.add_argument("--posts", type=int, default=300)
    args = ap.parse_args()

    store = Store(Settings().db_path)
    src = DemoSource()
    now = time.time()
    posts = []
    for raw in src.generate(args.posts):
        # Skew toward recent so the trend detector sees a spike.
        age = args.hours * 3600 * random.random() ** 2
        raw.created_at = now - age
        posts.append(enrich(raw, raw.created_at))
    print(f"inserted {len(store.insert_posts(posts))} demo posts")


if __name__ == "__main__":
    main()
