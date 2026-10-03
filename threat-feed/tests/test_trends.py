from threatfeed.enrich import enrich
from threatfeed.models import RawPost
from threatfeed.trends import detect_trends

NOW = 1_000_000.0


def post(text, handle, t):
    return enrich(RawPost("demo", f"{handle}{t}{text}", handle, handle, "https://e.com", text, t), t)


def test_spike_across_authors_trends():
    posts = [post("CVE-2026-1111 exploited", f"r{i}", NOW - 60 * i) for i in range(4)]
    trends = {t.term: t for t in detect_trends(posts, NOW)}
    assert trends["CVE-2026-1111"].recent == 4 and trends["CVE-2026-1111"].authors == 4


def test_single_author_cannot_manufacture_a_trend():
    posts = [post("CVE-2026-2222 exploited", "spammer", NOW - 60 * i) for i in range(10)]
    assert "CVE-2026-2222" not in {t.term for t in detect_trends(posts, NOW)}


def test_steady_baseline_scores_lower_than_new_spike():
    week = 7 * 24 * 3600
    old = [post("#steady", f"b{i}", NOW - 7 * 3600 - i * (week / 60)) for i in range(56)]
    recent = [post("#steady", f"a{i}", NOW - 60 * i) for i in range(4)]
    recent += [post("#newcampaign", f"c{i}", NOW - 60 * i) for i in range(4)]
    t = {x.term: x for x in detect_trends(old + recent, NOW)}
    assert t["#newcampaign"].score > t["#steady"].score


def test_generic_hashtags_ignored():
    posts = [post("#infosec", f"r{i}", NOW - i) for i in range(5)]
    assert "#infosec" not in {t.term for t in detect_trends(posts, NOW)}
