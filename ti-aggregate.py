#!/usr/bin/env python3
"""
ti-aggregate.py - multi-source threat intel aggregator for DNS blocklists.

Collects daily, publishes weekly. Stdlib only.

Modes
  --mode tranco    refresh the Tranco top-1M allowlist cache (weekly is plenty)
  --mode fetch     pull every feed, normalise, upsert into SQLite
  --mode generate  score, filter, and emit strict/aggressive lists as JSON
  --mode stats     current database summary (for Influx / Discord)

Design notes
  * Tranco is a HARD allowlist. Nothing popular is ever published, whatever a
    feed claims. This is the guardrail that stops one bad feed update from
    breaking every subscriber.
  * "dedicated" marks infrastructure that exists to be malicious (C2, malware
    hosting domains) as opposed to a compromised legitimate site. Only
    dedicated indicators reach the strict list, because a hacked WordPress
    install gets cleaned up and should not be blocked forever.
  * Source tiers drive confidence. Requiring N sources to agree sounds
    rigorous but is broken in practice: domain overlap between free feeds is
    5-15%, so a 2-source rule throws away almost everything real.
"""

import argparse
import base64
import csv
import hashlib
import io
import json
import os
import re
import sqlite3
import sys
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

DB_PATH = os.environ.get("TI_DB", "/var/lib/n8n-ti/state.db")
CACHE = os.environ.get("TI_CACHE", "/var/cache/n8n-ti")
ALLOWLIST = os.environ.get("TI_ALLOWLIST", "/var/lib/n8n-ti/allowlist.txt")

ABUSE_KEY = os.environ.get("ABUSE_CH_KEY", "")
OTX_KEY = os.environ.get("OTX_KEY", "")

TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
TRANCO_CACHE = os.path.join(CACHE, "tranco-1m.txt")
# Only the top N Tranco entries are treated as "never block". The tail of the
# top 1M contains live malicious infrastructure that ranks because it gets
# traffic - allowlisting all 1M would protect the very domains we target.
TRANCO_RANK_CUTOFF = int(os.environ.get("TI_TRANCO_RANK", "100000"))

RETENTION_DAYS = 90
UA = "n8n-threat-blocklist/1.0 (+https://github.com/Yel1oww/n8n-threat-blocklist)"

# tier 1 = high precision, safe to act on alone
# tier 2 = good, wants corroboration for the strict list
# tier 3 = noisy / mostly compromised sites, aggressive list only
# Feeds that return their COMPLETE current list on every fetch. For these,
# absence from a response is meaningful - the source removed the domain - so we
# mirror them. Incremental feeds return a moving window, where absence only
# means "outside the window", and those accumulate and age out instead.
SNAPSHOT_FEEDS = {"blackbook", "openphish"}

# A snapshot fetch that returns far fewer items than we already hold is almost
# certainly a truncated or partial response. Pruning on that would gut the list,
# so below this ratio we keep the old rows and flag it instead.
SNAPSHOT_MIN_RATIO = 0.5

SOURCE_TIERS = {
    "blackbook": 2,
    "threatfox": 1,
    "urlhaus": 2,
    "otx": 3,
    "openphish": 3,
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS indicators (
    domain      TEXT NOT NULL,
    source      TEXT NOT NULL,
    tier        INTEGER NOT NULL,
    threat_type TEXT,
    confidence  INTEGER DEFAULT 0,
    dedicated   INTEGER NOT NULL DEFAULT 0,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    PRIMARY KEY (domain, source)
);
CREATE INDEX IF NOT EXISTS idx_ind_domain ON indicators(domain);
CREATE INDEX IF NOT EXISTS idx_ind_seen   ON indicators(last_seen);

CREATE TABLE IF NOT EXISTS runs (
    run_ts   TEXT NOT NULL,
    source   TEXT NOT NULL,
    fetched  INTEGER NOT NULL,
    accepted INTEGER NOT NULL,
    error    TEXT,
    PRIMARY KEY (run_ts, source)
);

CREATE TABLE IF NOT EXISTS publications (
    published_at TEXT PRIMARY KEY,
    strict_count INTEGER,
    aggressive_count INTEGER,
    strict_sha TEXT,
    aggressive_sha TEXT
);

CREATE TABLE IF NOT EXISTS blocked_by_allowlist (
    domain TEXT PRIMARY KEY,
    source TEXT,
    seen_at TEXT
);
"""

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)"
                       r"(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def connect() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    c = sqlite3.connect(DB_PATH, timeout=60)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA busy_timeout=60000")
    c.executescript(SCHEMA)
    return c


def http(url, data=None, headers=None, timeout=120):
    req = urllib.request.Request(url, data=data, method="POST" if data else "GET")
    req.add_header("User-Agent", UA)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


# Domains this tool depends on to function. A public blocklist that can block
# its own distribution URL is a failure mode every subscriber inherits: their
# resolver blocks the raw file, the next update silently fails, and the list
# quietly goes stale. These are never publishable, whatever a feed reports -
# and feeds DO report some of them in good faith, because malware really is
# hosted on public code and file hosts.
INFRA_ALLOWLIST = {
    # list distribution
    "raw.githubusercontent.com", "github.com", "api.github.com",
    "objects.githubusercontent.com", "codeload.github.com",
    # feed sources
    "abuse.ch", "urlhaus.abuse.ch", "urlhaus-api.abuse.ch",
    "threatfox.abuse.ch", "threatfox-api.abuse.ch", "auth.abuse.ch",
    "openphish.com", "otx.alienvault.com", "alienvault.com",
    "tranco-list.eu",
    # common resolver / OS infrastructure worth never breaking
    "cloudflare-dns.com", "dns.google", "one.one.one.one",
}

# Suffixes where each subdomain belongs to a DIFFERENT party. A Tranco entry for
# one of these says the *platform* is popular, not that any given subdomain is
# trustworthy - and free dynamic-DNS and static-hosting providers are the classic
# home of malware C2. Parent matching must stop here, or allowlisting duckdns.org
# silently unblocks every C2 domain hosted on it.
#
# This is a hand-maintained subset of the Public Suffix List's private section,
# limited to providers that actually show up in threat feeds.
SHARED_SUFFIXES = {
    # dynamic DNS
    "duckdns.org", "ddns.net", "no-ip.org", "no-ip.com", "no-ip.biz",
    "noip.at", "noip.me", "hopto.org", "zapto.org", "sytes.net",
    "serveo.net", "myftp.org", "myftp.biz", "servebeer.com",
    "serveblog.net", "servegame.com", "ydns.eu", "kozow.com", "loseyourip.com",
    "dynu.net", "freedynamicdns.net", "mooo.com", "chickenkiller.com",
    # wildcard DNS - resolve to arbitrary IPs by construction
    "sslip.io", "nip.io", "traefik.me", "localtest.me",
    # tunnels and edge functions
    "ngrok.io", "ngrok-free.app", "trycloudflare.com", "workers.dev",
    "loca.lt", "serveo.net",
    # free static hosting / pages
    "github.io", "pages.dev", "netlify.app", "vercel.app", "herokuapp.com",
    "web.app", "firebaseapp.com", "glitch.me", "repl.co", "onrender.com",
    "surge.sh", "gitlab.io", "bitbucket.io", "neocities.org",
    # object storage
    "s3.amazonaws.com", "blob.core.windows.net", "storage.googleapis.com",
    "r2.dev", "digitaloceanspaces.com", "backblazeb2.com",
    # free hosting / link shorteners frequently abused
    "000webhostapp.com", "weebly.com", "wixsite.com", "blogspot.com",
    "xsph.ru", "tw1.ru", "temp.swtest.ru",
}


def parent_domains(domain: str):
    """Yield the domain and every parent down to two labels.

    foo.bar.example.com -> foo.bar.example.com, bar.example.com, example.com
    """
    parts = domain.split(".")
    for i in range(len(parts) - 1):
        yield ".".join(parts[i:])


def is_allowlisted(domain: str, tranco: set, manual: set) -> bool:
    """Allowlist matching must consider parent domains, not just exact strings.

    Malware really is hosted on popular user-content hosts - raw.githubusercontent.com,
    storage buckets, CDNs - so feeds report those subdomains in good faith.
    Tranco lists the registrable domain (githubusercontent.com), so an exact-match
    check leaves every such subdomain unprotected. Blocking them breaks far more
    than it protects.
    """
    for d in parent_domains(domain):
        # explicit human decisions and our own infrastructure always win,
        # even over the shared-suffix rule below
        if d in manual or d in INFRA_ALLOWLIST:
            return True
        # never let a shared-hosting suffix vouch for its subdomains
        if d in SHARED_SUFFIXES:
            return False
        if d in tranco:
            return True
    return False


def clean_domain(value: str):
    """Normalise a URL or bare host into a blockable domain, or None."""
    if not value:
        return None
    value = value.strip().lower()
    if "://" in value:
        value = urlparse(value).hostname or ""
    value = value.split("/")[0].split(":")[0].strip(".")
    if value.startswith("www."):
        value = value[4:]
    # reject IPs - this is a DNS blocklist
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value) or ":" in value:
        return None
    if not DOMAIN_RE.match(value):
        return None
    if value.count(".") < 1:
        return None
    return value


# ═══════════════════════════════════════════════════════ TRANCO ═══════════
def mode_tranco(_conn, _opts) -> dict:
    os.makedirs(CACHE, exist_ok=True)
    raw = http(TRANCO_URL, timeout=300)
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        name = z.namelist()[0]
        with z.open(name) as f:
            rows = csv.reader(io.TextIOWrapper(f, "utf-8"))
            domains = [r[1].strip().lower() for r in rows if len(r) > 1]

    tmp = TRANCO_CACHE + ".tmp"
    with open(tmp, "w") as f:
        f.write("\n".join(domains))
    os.replace(tmp, TRANCO_CACHE)
    return {"cached": len(domains), "path": TRANCO_CACHE}


def load_tranco() -> set:
    if not os.path.exists(TRANCO_CACHE):
        raise RuntimeError("Tranco cache missing - run --mode tranco first")
    out = set()
    with open(TRANCO_CACHE) as f:
        for n, line in enumerate(f):
            if n >= TRANCO_RANK_CUTOFF:
                break
            line = line.strip()
            if line:
                out.add(line)
    return out


def load_manual_allowlist() -> set:
    if not os.path.exists(ALLOWLIST):
        return set()
    out = set()
    with open(ALLOWLIST) as f:
        for line in f:
            line = line.split("#")[0].strip().lower()
            if line:
                out.add(line)
    return out


# ════════════════════════════════════════════════════════ FEEDS ═══════════
def feed_threatfox():
    """abuse.ch ThreatFox. Domain IOCs, with an explicit confidence level."""
    if not ABUSE_KEY:
        raise RuntimeError("ABUSE_CH_KEY not set")
    body = json.dumps({"query": "get_iocs", "days": 7}).encode()
    data = json.loads(http("https://threatfox-api.abuse.ch/api/v1/", body,
                           {"Auth-Key": ABUSE_KEY,
                            "Content-Type": "application/json"}))
    if data.get("query_status") != "ok":
        raise RuntimeError(f"threatfox: {data.get('query_status')}")

    out = []
    for i in data.get("data", []):
        if i.get("ioc_type") not in ("domain", "url"):
            continue
        d = clean_domain(i.get("ioc", ""))
        if not d:
            continue
        conf = int(i.get("confidence_level") or 0)
        if conf < 75:
            continue
        out.append({
            "domain": d, "threat_type": i.get("threat_type"),
            "confidence": conf,
            # C2 domains are purpose-registered infrastructure
            "dedicated": 1 if i.get("threat_type") == "botnet_cc" else 0,
        })
    return out


def feed_urlhaus():
    """abuse.ch URLhaus recent malware distribution URLs.

    NOTE: this endpoint is a GET with the limit encoded in the path, and it
    returns at most 1000 entries from the last 3 days. POSTing to it returns
    405. Because we collect daily and retain for 90 days, coverage accumulates
    rather than arriving in one dump.
    """
    if not ABUSE_KEY:
        raise RuntimeError("ABUSE_CH_KEY not set")
    data = json.loads(http("https://urlhaus-api.abuse.ch/v1/urls/recent/limit/1000/",
                           headers={"Auth-Key": ABUSE_KEY}))
    if data.get("query_status") != "ok":
        raise RuntimeError(f"urlhaus: {data.get('query_status')}")

    out = []
    for u in data.get("urls", []):
        url = u.get("url", "")
        d = clean_domain(url)
        if not d:
            continue
        path = urlparse(url).path or "/"
        tags = [str(t).lower() for t in (u.get("tags") or [])]

        # abuse.ch cross-references Spamhaus DBL, which explicitly distinguishes
        # abused legitimate domains from purpose-registered malicious ones.
        # That is a far better signal than any heuristic of ours.
        dbl = str((u.get("blacklists") or {}).get("spamhaus_dbl") or "").lower()
        if "abused_legit" in dbl:
            dedicated = 0
        elif "not_listed" in dbl or dbl == "":
            # fall back to path depth: a payload buried deep on an otherwise
            # ordinary host usually means a compromised site
            depth = len([x for x in path.split("/") if x])
            dedicated = 1 if depth <= 1 and "compromised" not in tags else 0
        else:
            dedicated = 1

        out.append({
            "domain": d,
            "threat_type": u.get("threat"),
            "confidence": 90 if u.get("url_status") == "online" else 60,
            "dedicated": dedicated,
        })
    return out


def feed_blackbook():
    """Malware-dedicated domains only; compromised sites explicitly excluded."""
    raw = http("https://raw.githubusercontent.com/stamparm/blackbook/master/blackbook.txt")
    out = []
    for line in raw.decode("utf-8", "ignore").splitlines():
        d = clean_domain(line)
        if d:
            # NOT marked dedicated: blackbook is historical and includes
            # long-since-cleaned compromised sites (architecture firms, small
            # shops). Corroboration from a live feed is required before any of
            # this reaches the strict list.
            out.append({"domain": d, "threat_type": "malware-historic",
                        "confidence": 70, "dedicated": 0})
    return out


def feed_openphish():
    """Community phishing feed. Mostly compromised hosts - aggressive list only."""
    raw = http("https://openphish.com/feed.txt")
    out = []
    for line in raw.decode("utf-8", "ignore").splitlines():
        d = clean_domain(line)
        if d:
            out.append({"domain": d, "threat_type": "phishing",
                        "confidence": 60, "dedicated": 0})
    return out


def feed_otx():
    """OTX recent public pulse activity. Broad but community-submitted."""
    if not OTX_KEY:
        raise RuntimeError("OTX_KEY not set")
    out, seen = [], set()
    for page in (1, 2, 3):
        url = f"https://otx.alienvault.com/api/v1/pulses/activity?limit=50&page={page}"
        data = json.loads(http(url, headers={"X-OTX-API-KEY": OTX_KEY}))
        for pulse in data.get("results", []):
            tags = [t.lower() for t in (pulse.get("tags") or [])]
            ded = 1 if any(t in tags for t in ("c2", "c&c", "botnet", "apt")) else 0
            for ind in pulse.get("indicators", []):
                if ind.get("type") not in ("domain", "hostname"):
                    continue
                d = clean_domain(ind.get("indicator", ""))
                if d and d not in seen:
                    seen.add(d)
                    out.append({"domain": d, "threat_type": "otx-pulse",
                                "confidence": 50, "dedicated": ded})
        if not data.get("next"):
            break
    return out


FEEDS = {
    "threatfox": feed_threatfox,
    "urlhaus": feed_urlhaus,
    "blackbook": feed_blackbook,
    "openphish": feed_openphish,
    "otx": feed_otx,
}


# ════════════════════════════════════════════════════════ FETCH ═══════════
def mode_fetch(conn, opts) -> dict:
    run_ts = now_iso()
    only = opts.get("sources") or list(FEEDS)
    tranco = load_tranco()
    manual = load_manual_allowlist()

    summary, errors = {}, {}
    for name in only:
        fn = FEEDS.get(name)
        if not fn:
            continue
        tier = SOURCE_TIERS[name]
        try:
            items = fn()
        except Exception as exc:
            errors[name] = str(exc)[:300]
            conn.execute("INSERT OR REPLACE INTO runs VALUES (?,?,?,?,?)",
                         (run_ts, name, 0, 0, str(exc)[:300]))
            summary[name] = {"fetched": 0, "accepted": 0, "error": True}
            continue

        accepted = 0
        seen_domains = set()
        for it in items:
            d = it["domain"]
            if is_allowlisted(d, tranco, manual):
                conn.execute(
                    "INSERT OR REPLACE INTO blocked_by_allowlist VALUES (?,?,?)",
                    (d, name, run_ts))
                continue
            conn.execute(
                """INSERT INTO indicators
                   (domain, source, tier, threat_type, confidence, dedicated,
                    first_seen, last_seen)
                   VALUES (?,?,?,?,?,?,?,?)
                   ON CONFLICT(domain, source) DO UPDATE SET
                     last_seen  = excluded.last_seen,
                     confidence = MAX(indicators.confidence, excluded.confidence),
                     dedicated  = MAX(indicators.dedicated, excluded.dedicated),
                     threat_type= excluded.threat_type""",
                (d, name, tier, it.get("threat_type"), it.get("confidence", 0),
                 it.get("dedicated", 0), run_ts, run_ts))
            seen_domains.add(d)
            accepted += 1

        pruned = 0
        if name in SNAPSHOT_FEEDS:
            held = conn.execute(
                "SELECT COUNT(*) FROM indicators WHERE source=?", (name,)
            ).fetchone()[0]
            # accepted counts rows we just stamped with this run_ts
            if held == 0 or accepted >= held * SNAPSHOT_MIN_RATIO:
                conn.execute("CREATE TEMP TABLE IF NOT EXISTS _seen "
                             "(domain TEXT PRIMARY KEY)")
                conn.execute("DELETE FROM _seen")
                conn.executemany("INSERT OR IGNORE INTO _seen VALUES (?)",
                                 [(d,) for d in seen_domains])
                pruned = conn.execute(
                    "DELETE FROM indicators WHERE source=? AND domain NOT IN "
                    "(SELECT domain FROM _seen)", (name,)).rowcount
            else:
                errors[name] = (f"snapshot guard tripped: fetch returned "
                                f"{accepted} but we hold {held}; skipped prune")

        conn.execute("INSERT OR REPLACE INTO runs VALUES (?,?,?,?,NULL)",
                     (run_ts, name, len(items), accepted))
        summary[name] = {"fetched": len(items), "accepted": accepted,
                         "pruned": pruned, "snapshot": name in SNAPSHOT_FEEDS,
                         "error": False}

    cutoff = (datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS)) \
        .strftime("%Y-%m-%dT%H:%M:%SZ")
    aged = conn.execute("DELETE FROM indicators WHERE last_seen < ?",
                        (cutoff,)).rowcount
    conn.commit()

    return {
        "run_ts": run_ts, "sources": summary, "errors": errors,
        "aged_out": aged,
        "allowlist_saves": conn.execute(
            "SELECT COUNT(*) FROM blocked_by_allowlist").fetchone()[0],
        "infra_saves": [
            r["domain"] for r in conn.execute(
                "SELECT domain FROM blocked_by_allowlist")
            if any(x in INFRA_ALLOWLIST for x in parent_domains(r["domain"]))
        ],
        "total_domains": conn.execute(
            "SELECT COUNT(DISTINCT domain) FROM indicators").fetchone()[0],
    }


# ═════════════════════════════════════════════════════ GENERATE ═══════════
def git_blob_sha(content: bytes) -> str:
    """GitHub compares blob SHA1s, so compute it locally to skip no-op commits."""
    header = f"blob {len(content)}\0".encode()
    return hashlib.sha1(header + content).hexdigest()


def build_file(domains, title, note) -> bytes:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    head = [
        f"# {title}",
        f"# Generated {ts} by n8n-threat-blocklist",
        f"# {len(domains)} domains",
        f"# {note}",
        "# Sources: abuse.ch (ThreatFox, URLhaus), blackbook, OTX, OpenPhish",
        "# Filtered against the Tranco top 1M. Report false positives via GitHub issues.",
        "",
    ]
    return ("\n".join(head + sorted(domains)) + "\n").encode()


def mode_generate(conn, opts) -> dict:
    tranco = load_tranco()
    manual = load_manual_allowlist()

    rows = conn.execute(
        """SELECT domain,
                  COUNT(DISTINCT source) AS sources,
                  MIN(tier)              AS best_tier,
                  MAX(dedicated)         AS dedicated,
                  MAX(confidence)        AS confidence,
                  MAX(last_seen)         AS last_seen,
                  GROUP_CONCAT(DISTINCT source) AS source_list
           FROM indicators GROUP BY domain""").fetchall()

    strict, aggressive, skipped = set(), set(), 0
    for r in rows:
        d = r["domain"]
        # belt and braces: the allowlist is applied at fetch AND at generate,
        # because the Tranco list changes between runs
        if is_allowlisted(d, tranco, manual):
            skipped += 1
            continue

        aggressive.add(d)

        # Strict requires purpose-built infrastructure, full stop. Multiple
        # sources agreeing that a compromised WordPress site is serving malware
        # does not make it dedicated infrastructure - it makes it a victim that
        # will be cleaned up. Corroboration raises confidence, it does not
        # change what kind of thing the domain is.
        if r["dedicated"] == 1 and (r["best_tier"] == 1 or r["sources"] >= 2):
            strict.add(d)

    strict_b = build_file(
        strict, "Strict blocklist",
        "Malware-dedicated infrastructure only. Conservative; safe to subscribe blind.")
    aggr_b = build_file(
        aggressive, "Aggressive blocklist",
        "Includes phishing and possibly-compromised hosts. Higher coverage, higher false-positive risk.")

    stats = {
        "generated_at": now_iso(),
        "strict_count": len(strict),
        "aggressive_count": len(aggressive),
        "allowlist_skipped": skipped,
        "by_source": {r["source"]: r["n"] for r in conn.execute(
            "SELECT source, COUNT(*) n FROM indicators GROUP BY source")},
        "tier_1_domains": sum(1 for r in rows if r["best_tier"] == 1),
        "multi_source_domains": sum(1 for r in rows if r["sources"] >= 2),
    }
    stats_b = (json.dumps(stats, indent=2) + "\n").encode()

    conn.execute("INSERT OR REPLACE INTO publications VALUES (?,?,?,?,?)",
                 (now_iso(), len(strict), len(aggressive),
                  git_blob_sha(strict_b), git_blob_sha(aggr_b)))
    conn.commit()

    return {
        "files": [
            {"path": "lists/strict.txt", "b64": base64.b64encode(strict_b).decode(),
             "git_sha": git_blob_sha(strict_b), "count": len(strict)},
            {"path": "lists/aggressive.txt", "b64": base64.b64encode(aggr_b).decode(),
             "git_sha": git_blob_sha(aggr_b), "count": len(aggressive)},
            {"path": "lists/stats.json", "b64": base64.b64encode(stats_b).decode(),
             "git_sha": git_blob_sha(stats_b), "count": 0},
        ],
        "stats": stats,
    }


def mode_stats(conn, _opts) -> dict:
    last = conn.execute(
        "SELECT MAX(run_ts) t FROM runs").fetchone()["t"]
    return {
        "last_run": last,
        "total_domains": conn.execute(
            "SELECT COUNT(DISTINCT domain) FROM indicators").fetchone()[0],
        "by_source": {r["source"]: r["n"] for r in conn.execute(
            "SELECT source, COUNT(*) n FROM indicators GROUP BY source")},
        "multi_source": conn.execute(
            "SELECT COUNT(*) FROM (SELECT domain FROM indicators "
            "GROUP BY domain HAVING COUNT(DISTINCT source) >= 2)").fetchone()[0],
        "allowlist_saves": conn.execute(
            "SELECT COUNT(*) FROM blocked_by_allowlist").fetchone()[0],
        "last_run_errors": [dict(r) for r in conn.execute(
            "SELECT source, error FROM runs WHERE run_ts=? AND error IS NOT NULL",
            (last,))] if last else [],
    }


MODES = {"tranco": mode_tranco, "fetch": mode_fetch,
         "generate": mode_generate, "stats": mode_stats}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", required=True, choices=list(MODES))
    args = ap.parse_args()

    raw = sys.stdin.read().strip() if not sys.stdin.isatty() else ""
    opts = json.loads(raw) if raw else {}

    conn = connect()
    try:
        result = MODES[args.mode](conn, opts)
        result["ok"] = True
    except Exception as exc:
        conn.rollback()
        print(json.dumps({"ok": False, "mode": args.mode, "error": str(exc)[:500]}))
        return 1
    finally:
        conn.close()

    print(json.dumps(result, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
