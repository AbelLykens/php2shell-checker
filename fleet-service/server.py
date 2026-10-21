#!/usr/bin/env python3
"""
php2shell fleet-check service
=============================
Lightweight, dependency-free (stdlib-only) web service that checks the
php2shell posture (CVE-2026-109618/619, PHP session.upload_progress) of
URLs you are authorized to test.

Architecture split (keep the server as dumb and as light as possible):

  SERVER (this file) - does ONLY what the browser cannot:
    * cross-origin HTTP requests with readable responses (status + headers)
    * bounded outbound queueing (protects targets and this host)
    * per-IP rate limiting, TTL result cache, SSRF guards, size/time caps
    * stores and serves the shared patched-release list: one place to
      update it for every visitor, no per-browser configuration
    * ships RAW FACTS only - no interpretation, no verdicts

  CLIENT (index.html, served by this server) - everything else runs locally
  in the operator's browser:
    * version comparison against the server-side patched-release list
    * block-test interpretation, verdicts, rendering, polling
    * results stay in the visitor's browser session only - no export endpoint

API:
  GET  /api/pow?for=scan|status
                       -> {"id", "bits", "expires_in_s"} one-time PoW challenge
  POST /api/scan      {"urls": [url], "level": "banner"|"block", "force"?,
                       "pow": {"id": ..., "nonce": ...}}
                       one URL at a time (max_urls_per_job, default 1);
                       requires a solved "scan" challenge -> random job UUID
  GET  /api/job/<id>?pow_id=..&pow_nonce=..
                       -> queue position while waiting, job state + per-URL
                       facts when done; requires a solved "status" challenge
  GET  /api/releases  -> {"patched_releases": [...]} (shared, server-side)
  POST /api/releases  {"patched_releases": [...], "token": "..."}
                      replace the shared list (admin token required)
  GET  /api/health    -> queue depth / workers / uptime / config summary
  GET  /               -> index.html (the client UI)

Proof of work (hashcash-style, abuse brake):
  Both write/poll endpoints require a fresh single-use challenge: the client
  finds nonce so SHA-256("<id>:<nonce>") has >= <bits> leading zero bits.
  Submissions are expensive (pow_scan_bits, ~1s of browser CPU), status polls
  are cheap (pow_poll_bits, milliseconds) but still CPU-throttle polling.
  Challenges are random, purpose-bound, expire after pow_ttl seconds, and are
  burned on use (replay-proof). 0 bits disables a flow (tests).

Caches (busy-server design):
  * OG preview cards are cached ON DISK (og-cache dir next to the DB by
    default), not in process memory - a restart keeps its cache and a busy
    box does not trade RAM for PNGs. Entries expire after _OG_TTL seconds;
    the GC thread removes stale files.
  * A localhost memcached (127.0.0.1:11211, --memcached none to disable)
    acts as a read-only METRICS BUS: a 1s publisher thread writes the live
    queue depth, in-flight/active counts and per-job queue positions
    (keys "p2s:queue_depth", "p2s:in_flight", "p2s:jobs_active",
    "p2s:qp/<job_id>"). Status polls read the O(1) position from memcached
    instead of scanning the queue under its lock; the exact in-process
    computation stays as fallback. Every memcached call is best-effort with
    a reconnect backoff: if memcached dies, the service keeps running and
    falls back to local computation automatically.

Probes (deliberately inert, never exploit-shaped):
  Every probe follows redirects like a browser would: up to max_redirects
  hops, each hop SSRF-guarded; 301/302/303 convert POST->GET, 307/308 keep
  the method and body. Facts record the FIRST-hop status (what the edge did
  to the original request - this is what verdicts use) separately from the
  final status after following, plus the redirect count.
  banner level: 1 GET - reads status + a few headers (and notes whether a PHP
                session cookie was set),
                body capped at read_limit bytes.
  block level:  adds 6 requests - per method (POST, PUT, PATCH) one urlencoded
                baseline + one multipart request with a single neutral text
                field ("probe"). Blocking only POST is not enough: PHP 8.4's
                request_parse_body() lets apps parse multipart bodies on other
                methods, so reachability is checked per method.
                No session cookie, no
                file part, no upload-progress field, no stalling - it cannot
                engage the vulnerable path. It only answers "does multipart
                get rejected before PHP parses the body, on any method?".

Persistence (results -> limit re-tests):
  SQLite in WAL mode via the Store class (the only place SQL lives).
  Fresh stored results (within cache_ttl) are served instead of re-probing,
  across restarts. "force": true in POST /api/scan bypasses the store.
  Rows older than retain_hours are purged by the GC thread. SQLite is more
  than sufficient here: writes are one small row per probe, bounded by the
  worker cap and rate limit; WAL readers never block the writer; one
  connection per thread (thread-local). Swap in Postgres only if you ever
  run multiple service instances against one shared database.

Run:  python3 server.py [--host 0.0.0.0] [--port 8971] [--workers 8]
                       [--db PATH|none] [--retain-hours 168]
                       [--max-urls 1] [--admin-token TOKEN]
                       [--memcached ADDR|none] [--og-cache-dir DIR|none]
  (admin token also readable from env PHP2SHELL_ADMIN_TOKEN,
   memcached address from env PHP2SHELL_MEMCACHED)
"""

import argparse
import bisect
import hashlib
import hmac
import html
import ipaddress
import json
import os
import queue
import re
import secrets
import socket
import sqlite3
import ssl
import struct
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zlib
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = "1.1.0"

DEFAULTS = dict(
    host="127.0.0.1",
    port=8971,
    workers=8,                # outbound concurrency cap (the queueing knob)
    max_urls_per_job=1,       # one URL at a time; raise via --max-urls for fleet mode
    max_body_bytes=1 << 20,   # request body cap for /api/scan
    read_limit=16 * 1024,    # max bytes read from any target response
    connect_read_timeout=8.0,  # seconds, per outbound request
    max_redirects=3,
    cache_ttl=600.0,         # seconds: identical (url, level) re-checks served from memory
    job_ttl=1800.0,          # seconds: completed jobs kept for collection
    rate_per_minute=30,      # job submissions per client IP per minute
    queue_limit=2000,        # max queued items; submissions beyond -> 503
    allow_private=False,     # NEVER enable in production: permits private/loopback targets
    allow_http=False,        # NEVER enable in production: tests only - http targets
                             # are probed as https otherwise (always-https rule)
    allowlist_file=None,     # optional file of allowed host suffixes, one per line
    verify_tls=True,
    user_agent="php2shell-fleet-check/1.0 (authorized inventory check)",
    db_path=None,            # default: fleet-check.db next to server.py ('none' disables)
    retain_hours=168.0,      # how long stored results/jobs are kept (history window)
    trust_proxy=False,       # honor X-Forwarded-For from loopback peers (behind nginx)
    admin_token=None,       # token for POST /api/releases (or env PHP2SHELL_ADMIN_TOKEN)
    pow_scan_bits=18,       # PoW difficulty for job submission (~1s in a browser)
    pow_poll_bits=12,       # lighter PoW for status polls (CPU-throttles polling)
    pow_scan_max_extra=4,   # adaptive: +1 scan bit per queue doubling past 2x workers
    pow_open_per_ip=64,     # unsolved challenges one client IP may hold at once
    pow_ttl=180.0,          # seconds a PoW challenge stays valid; single-use
    memcached="127.0.0.1:11211",  # localhost metrics bus ('none' disables)
    og_cache_dir=None,      # default: og-cache/ next to the DB file ('none' disables)
    metrics_interval=1.0,   # seconds between memcached metrics publishes
)

BOUNDARY = "----php2shellfleetcheck7d1a"
# Header names are normalized to JSON-friendly keys in the facts payload
# (the client reads x_powered_by / content_type with underscores).
HEADER_MAP = {
    "server": "server",
    "x-powered-by": "x_powered_by",
    "content-type": "content_type",
    "location": "location",
}

# Session cookies that reveal a PHP runtime behind a hidden version banner.
_SESSION_COOKIES = ("phpsessid", "laravel_session")


def _php_session_cookie(headers):
    """True when the response sets a PHP-looking session cookie. Reads ALL
    Set-Cookie lines (repeated header), lower-cased match."""
    try:
        cookies = headers.get_all("Set-Cookie") or []
    except AttributeError:  # plain dict-like header store
        v = headers.get("Set-Cookie")
        cookies = [v] if v else []
    return any(c and any(k in c.lower() for k in _SESSION_COOKIES)
               for c in cookies)


class ProbeError(Exception):
    pass


# ---------------------------------------------------------------- outbound HTTP

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # 3xx surfaces as HTTPError -> returned as a normal result


def _opener(cfg):
    if cfg["verify_tls"]:
        ctx = ssl.create_default_context()
    else:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return urllib.request.build_opener(
        _NoRedirect, urllib.request.HTTPSHandler(context=ctx)
    )


def _drain(resp, limit):
    """Read a capped slice and close, so targets log a completed request."""
    try:
        resp.read(limit)
    except Exception:
        pass
    finally:
        try:
            resp.close()
        except Exception:
            pass


def _guard_url(url, cfg, allowlist):
    """SSRF guard: http(s) only, DNS-resolved, refuse non-global addresses."""
    p = urllib.parse.urlsplit(url)
    if p.scheme not in ("http", "https"):
        raise ProbeError("scheme not allowed: %s" % (p.scheme or "(none)"))
    if not p.hostname:
        raise ProbeError("no hostname")
    try:
        port = p.port or (443 if p.scheme == "https" else 80)
    except ValueError:
        raise ProbeError("invalid port")
    if allowlist is not None and not _allowed_host(p.hostname, allowlist):
        raise ProbeError("host not in allowlist")
    try:
        infos = socket.getaddrinfo(
            p.hostname, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
        )
    except socket.gaierror as e:
        raise ProbeError("dns: %s" % e)
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not cfg["allow_private"] and not ip.is_global:
            raise ProbeError("blocked target address: %s" % ip)


def _allowed_host(host, allowlist):
    host = host.lower().rstrip(".")
    return any(host == a or host.endswith("." + a) for a in allowlist)


def http_probe(url, method="GET", data=None, headers=None, follow=True, cfg=None,
               allowlist=None):
    """One request with browser-like redirect following.

    Up to max_redirects hops, each hop SSRF-guarded. On redirect we MUST strip
    the URL (paths, query parameters, fragments) and follow only domains/hosts
    (bare root /). 301/302/303 convert POST->GET (as browsers and curl -L do);
    307/308 keep method and body.
    Returns raw facts: final status, first-hop status (what the edge did to
    the ORIGINAL request - verdicts use this, so a later app-level 403 on a
    redirected GET can never fake an "edge block"), redirect count, final
    URL, and the header snapshot of the last hop."""
    current = url
    sent_method, sent_data = method, data
    hops, seen, first_status = 0, set(), None
    status, hdrs, php_cookie = None, {}, False
    proto = None
    t0 = time.monotonic()

    def _err(msg):
        # keep whatever hop state was gathered for client-side diagnostics
        d = {"error": msg, "redirects": hops,
             "ms": int((time.monotonic() - t0) * 1000)}
        if first_status is not None:
            d["first_status"] = first_status
        if status is not None:
            d["status"] = status
        return d

    while True:
        try:
            _guard_url(current, cfg, allowlist)
        except ProbeError as e:
            return _err(str(e))
        seen.add(current.rstrip("/"))
        h = {"User-Agent": cfg["user_agent"]}
        if headers and sent_data is not None:
            # caller headers (Content-Type) describe the body; resend them on
            # every hop that still carries that body (i.e. 307/308 follow-ups)
            h.update(headers)
        req = urllib.request.Request(current, data=sent_data, headers=h,
                                     method=sent_method)
        try:
            with _opener(cfg).open(req, timeout=cfg["connect_read_timeout"]) as resp:
                status = getattr(resp, "status", None) or resp.getcode()
                hdrs = {nk: resp.headers.get(hk) for hk, nk in HEADER_MAP.items()}
                php_cookie = _php_session_cookie(resp.headers)
                proto = "HTTP/%.1f" % (getattr(resp, "version", 11) / 10.0)
                _drain(resp, cfg["read_limit"])
        except urllib.error.HTTPError as e:
            status = e.code
            hdrs = {nk: e.headers.get(hk) for hk, nk in HEADER_MAP.items()}
            php_cookie = _php_session_cookie(e.headers)
            _drain(e, cfg["read_limit"])
        except urllib.error.URLError as e:
            reason = getattr(e, "reason", None)
            return _err("%s: %s" % (type(reason).__name__, reason) if reason else "url error")
        except (socket.timeout, TimeoutError):
            return _err("timeout")
        except (ConnectionError, ssl.SSLError, OSError) as e:
            return _err(type(e).__name__)
        if first_status is None:
            first_status = status
        loc = hdrs.get("location")
        if follow and 300 <= status < 400 and loc and hops < cfg["max_redirects"]:
            raw_nxt = urllib.parse.urljoin(current, loc)
            sp = urllib.parse.urlsplit(raw_nxt)
            if sp.scheme not in ("http", "https") or not sp.netloc:
                break  # non-http target or malformed: report what we have
            scheme = sp.scheme.lower()
            if not cfg.get("allow_http", False) and scheme == "http":
                scheme = "https"
            # Strip path, query parameters and fragment - just follow domains at bare root /
            nxt = urllib.parse.urlunsplit((scheme, sp.netloc.lower(), "/", "", ""))
            if nxt.rstrip("/") in seen:
                break  # redirect loop, already visited domain, or redirected to same domain
            if status in (301, 302, 303):
                sent_method, sent_data = "GET", None
            # 307/308 keep the method and body
            current, hops = nxt, hops + 1
            continue
        break
    out = {
        "status": status,
        "first_status": first_status,
        "final_url": current,
        "redirects": hops,
        "ms": int((time.monotonic() - t0) * 1000),
    }
    if proto:
        out["proto"] = proto
    out.update({k: v for k, v in hdrs.items() if v})
    if php_cookie:
        out["php_session_cookie"] = True
    return out


def multipart_probe_body():
    body = (
        "--%s\r\n"
        "Content-Disposition: form-data; name=\"probe\"\r\n\r\n"
        "php2shell-block-test\r\n"
        "--%s--\r\n" % (BOUNDARY, BOUNDARY)
    ).encode("ascii")
    return body, {"Content-Type": "multipart/form-data; boundary=%s" % BOUNDARY}


def sanitize_target(u, allow_http=False):
    """Strict sanity for one scan target. Returns (clean_url, None) or
    (None, reason). Deliberately conservative - this is the front door for
    requests WE send, so anything odd is refused before a job is created:

    - absolute http(s) URL only (bare hosts get https:// prepended)
    - ALWAYS HTTPS: an http:// target is probed as https:// instead
      (allow_http=True only exists for the local test-suite mock origins)
    - BARE DOMAINS/SUBDOMAINS ONLY: no path content (anything beyond "/"),
      no query parameters, no fragment, no path traversal (../ or ..\\)
    - no whitespace/control characters, no backslashes, no userinfo
    - host must be a dotted DNS name or an IP literal (single-label names
      like `localhost` are refused - they only ever point inwards)
    """
    if not isinstance(u, str):
        return None, "URL must be a string"
    u = u.strip()
    if not u:
        return None, "empty URL"
    if len(u) > 2048:
        return None, "URL too long (max 2048)"
    if re.search(r"[\s\x00-\x1f\x7f]", u):
        return None, "whitespace or control characters in URL"
    if "\\" in u:
        return None, "backslashes not allowed in URL"
    if re.search(r"(^|/)\.\.(/|$)", u):
        return None, "path traversal (..) not allowed"
    if "?" in u:
        return None, "query parameters not allowed - scan the bare domain"
    if "#" in u:
        return None, "fragments (#) are never sent - submit the URL without it"
    if not re.match(r"^[a-z][a-z0-9+.\-]*://", u, re.I):
        u = "https://" + u
    if not re.match(r"^https?://", u, re.I):
        return None, "only http(s) URLs are scanned"
    if re.match(r"^http://", u, re.I) and not allow_http:
        u = "https://" + u[7:]   # always probe https
    try:
        sp = urllib.parse.urlsplit(u)
        sp.port   # validates the port
    except ValueError:
        return None, "invalid port in URL"
    netloc = sp.netloc
    if "@" in netloc:
        return None, "credentials in URL not allowed"
    host = sp.hostname or ""
    if not host or "%" in host:
        return None, "missing or malformed host"
    if not (re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host)
            or re.fullmatch(r"[0-9a-f:]+", host, re.I)):   # v4 / v6 literal
        host = host.rstrip(".")
        if "." not in host:
            return None, "single-label host refused (use a public DNS name)"
        if len(host) > 253 or not all(
                re.fullmatch(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?", l, re.I)
                for l in host.split(".")):
            return None, "malformed host name"
    if sp.path not in ("", "/"):
        return None, ("only bare domains/subdomains are scanned - "
                      "strip the path")
    clean = urllib.parse.urlunsplit(
        (sp.scheme.lower(), netloc.lower(), sp.path or "", "", ""))
    return clean, None


def probe_url(url, level, cfg, allowlist):
    """Full fact-gathering for one URL. Never sends exploit-shaped traffic."""
    facts = {"url": url, "level": level}
    t0 = time.monotonic()
    facts["get"] = http_probe(url, "GET", cfg=cfg, allowlist=allowlist)
    if level == "block":
        # Multipart reachability across methods: blocking POST alone is not
        # enough - PHP 8.4's request_parse_body() lets apps parse multipart
        # bodies on PUT/PATCH as well. Per method: one urlencoded baseline
        # (does the route accept this method at all?) + one inert multipart
        # POST (does anything reject it by content type before PHP?).
        ue_body = urllib.parse.urlencode({"probe": "php2shell-block-test"}).encode()
        mp_body, mp_headers = multipart_probe_body()
        keys = []
        for method in ("POST", "PUT", "PATCH"):
            name = method.lower()
            facts["%s_urlencoded" % name] = http_probe(
                url, method, ue_body,
                {"Content-Type": "application/x-www-form-urlencoded"},
                cfg=cfg, allowlist=allowlist,
            )
            facts["%s_multipart" % name] = http_probe(
                url, method, mp_body, mp_headers, cfg=cfg, allowlist=allowlist
            )
            keys.append(name)
        # connection-level failure on the POST baseline -> nothing else can
        # work either; mark instead of asking again. Keep the baseline's error
        # so the UI can show WHY the probes were skipped.
        if "error" in facts["post_urlencoded"]:
            be = facts["post_urlencoded"].get("error")
            for name in keys:
                for kind in ("urlencoded", "multipart"):
                    k = "%s_%s" % (name, kind)
                    if "error" in facts[k]:
                        facts[k] = {"skipped": "baseline failed", "baseline_error": be}
    facts["elapsed_ms"] = int((time.monotonic() - t0) * 1000)
    return facts


# ------------------------------------------------------------------ job engine

class Job(object):
    __slots__ = ("id", "urls", "level", "results", "created", "lock", "force",
                 "seq")

    def __init__(self, job_id, urls, level, force=False, seq=0):
        self.id = job_id
        self.urls = urls
        self.level = level
        self.results = {}
        self.created = time.time()
        self.lock = threading.Lock()
        self.force = force
        self.seq = seq


# ------------------------------------------------------------------ persistence

SCHEMA = """
CREATE TABLE IF NOT EXISTS results (
    url        TEXT NOT NULL,
    level      TEXT NOT NULL,
    fetched_at REAL NOT NULL,
    facts_json TEXT NOT NULL,
    PRIMARY KEY (url, level)
);
CREATE TABLE IF NOT EXISTS jobs (
    id           TEXT PRIMARY KEY,
    created      REAL NOT NULL,
    level        TEXT NOT NULL,
    total        INTEGER NOT NULL,
    done         INTEGER NOT NULL DEFAULT 0,
    submitted_by TEXT
);
CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at REAL NOT NULL
);
"""


class Store(object):
    """Persistent result store: SQLite in WAL mode.

    Why SQLite and not Postgres: this service writes one small row per
    completed probe plus one row per job, bounded by the worker cap and the
    per-IP rate limit - far inside SQLite's comfort zone. WAL mode gives
    concurrent readers that never block (and are never blocked by) the
    writer; writers serialize via the busy timeout. The one real rule -
    one connection per thread - is handled with thread-local connections.

    If you ever run multiple service instances against one shared database,
    replace this class with a Postgres implementation: it is deliberately
    the only place SQL lives.
    """

    def __init__(self, path):
        self.path = path
        self._local = threading.local()
        d = os.path.dirname(os.path.abspath(path))
        if d:
            os.makedirs(d, exist_ok=True)
        c = self._conn()
        c.executescript(SCHEMA)
        c.commit()

    def _conn(self):
        c = getattr(self._local, "conn", None)
        if c is None:
            c = sqlite3.connect(self.path, timeout=5.0)
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA synchronous=NORMAL")
            self._local.conn = c
        return c

    def get_fresh(self, url, level, max_age):
        row = self._conn().execute(
            "SELECT fetched_at, facts_json FROM results WHERE url = ? AND level = ?",
            (url, level),
        ).fetchone()
        if not row:
            return None
        fetched_at, blob = row
        if time.time() - fetched_at > max_age:
            return None
        try:
            facts = json.loads(blob)
        except ValueError:
            return None
        facts["cached"] = True
        facts["fetched_at"] = fetched_at
        return facts

    def put_result(self, url, level, facts):
        self._conn().execute(
            "INSERT INTO results (url, level, fetched_at, facts_json) VALUES (?, ?, ?, ?)"
            " ON CONFLICT(url, level) DO UPDATE SET"
            " fetched_at = excluded.fetched_at, facts_json = excluded.facts_json",
            (url, level, time.time(), json.dumps(facts)),
        )
        self._conn().commit()

    def put_job(self, job_id, level, total, submitted_by):
        self._conn().execute(
            "INSERT OR REPLACE INTO jobs (id, created, level, total, done, submitted_by)"
            " VALUES (?, ?, ?, ?, 0, ?)",
            (job_id, time.time(), level, total, submitted_by),
        )
        self._conn().commit()

    def finalize_job(self, job_id, done):
        self._conn().execute("UPDATE jobs SET done = ? WHERE id = ?", (done, job_id))
        self._conn().commit()

    def purge(self, older_than):
        c = self._conn()
        c.execute("DELETE FROM results WHERE fetched_at < ?", (older_than,))
        c.execute("DELETE FROM jobs WHERE created < ?", (older_than,))
        c.commit()

    def stats(self):
        c = self._conn()
        rows = c.execute("SELECT COUNT(*) FROM results").fetchone()[0]
        jobs = c.execute("SELECT COUNT(*) FROM jobs").fetchone()[0]
        try:
            size = os.path.getsize(self.path)
        except OSError:
            size = 0
        return {"db_path": self.path, "result_rows": rows, "job_rows": jobs,
                "db_bytes": size}

    def get_setting(self, key):
        row = self._conn().execute(
            "SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row[0] if row else None

    def set_setting(self, key, value):
        self._conn().execute(
            "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)"
            " ON CONFLICT(key) DO UPDATE SET"
            " value = excluded.value, updated_at = excluded.updated_at",
            (key, value, time.time()))
        self._conn().commit()


_VERSION_RE = re.compile(r"^\d+(?:\.\d+){0,3}$")


def _validate_releases(raw):
    """Validate a patched-releases list; an empty list is an explicit clear.
    Returns (list, error) - exactly one of them is None."""
    if not isinstance(raw, list):
        return None, "patched_releases must be a list"
    if len(raw) > 32:
        return None, "too many entries (max 32)"
    out = []
    for v in raw:
        if not isinstance(v, str):
            return None, "entries must be strings"
        v = v.strip()
        if not _VERSION_RE.match(v):
            return None, "invalid version: %r" % v[:24]
        if v not in out:
            out.append(v)
    return out, None


def load_allowlist(path):
    if not path:
        return None
    entries = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip().lower()
            if line and not line.startswith("#"):
                entries.append(line)
    return entries or None


# ---------------------------------------------------------------- metrics bus

class Memcache(object):
    """Minimal memcached text-protocol client (stdlib sockets only).

    Role in this service: a localhost METRICS BUS for queue state - the
    publisher thread writes queue depth / in-flight / per-job queue
    positions, status polls read positions back in O(1) instead of scanning
    the queue under its lock. Not a data store: every value carries a short
    TTL and the service degrades gracefully without it (see _fallbacks).

    One persistent connection, serialized by a lock (traffic is tiny:
    one pipelined write per metrics tick + one GET per status poll).
    A failure opens a circuit for `retry_backoff` seconds so a dead
    memcached costs nothing per request; every call returns None/False
    instead of raising - callers fall back to local computation."""

    def __init__(self, addr, timeout=1.0, retry_backoff=5.0):
        host, _, port = str(addr).rpartition(":")
        self.addr = ((host or "127.0.0.1"), int(port) if port else 11211)
        self.timeout = timeout
        self.retry_backoff = retry_backoff
        self.lock = threading.Lock()
        self.sock = None
        self.down_until = 0.0     # circuit breaker (monotonic)
        self.last_ok = 0.0        # last successful exchange (monotonic)

    # -- wire protocol -----------------------------------------------------

    def _connect(self):
        self.sock = socket.create_connection(self.addr, timeout=self.timeout)
        self.sock.settimeout(self.timeout)

    def _close(self):
        try:
            if self.sock is not None:
                self.sock.close()
        except OSError:
            pass
        self.sock = None

    def _recv_until(self, buf, marker):
        """Accumulate into bytearray `buf` until `marker` (bytes) is seen;
        returns everything up to and including the marker."""
        while marker not in buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("memcached closed connection")
            buf.extend(chunk)
        i = buf.find(marker) + len(marker)
        out = bytes(buf[:i])
        del buf[:i]
        return out

    def _exchange(self, payload, n_replies, markers):
        """Send payload, collect n_replies CRLF-terminated replies."""
        buf = bytearray()
        self.sock.sendall(payload)
        return [self._recv_until(buf, b"\r\n") for _ in range(n_replies)]

    # -- public API (all best-effort) ---------------------------------------

    def _available(self):
        return self.sock is not None or time.monotonic() >= self.down_until

    def _run(self, fn):
        """Run a wire operation with connect + circuit-breaker handling.
        Returns fn()'s result or None on any failure."""
        if not self._available():
            return None
        with self.lock:
            if not self._available():
                return None
            try:
                if self.sock is None:
                    self._connect()
                out = fn()
                self.down_until = 0.0
                self.last_ok = time.monotonic()
                return out
            except (OSError, ValueError):
                self._close()
                self.down_until = time.monotonic() + self.retry_backoff
                return None

    def set(self, key, value, ttl=10):
        data = value if isinstance(value, bytes) else str(value).encode()
        key = key.encode()
        cmd = b"set " + key + b" 0 " + str(int(ttl)).encode() \
            + b" " + str(len(data)).encode() + b"\r\n" + data + b"\r\n"

        def op():
            replies = self._exchange(cmd, 1, None)
            return replies and replies[0].startswith(b"STORED")
        return bool(self._run(op) or False)

    def set_many(self, items, ttl=10):
        """Pipelined set: one round trip for N keys.
        items: iterable of (key, value). Returns True when all stored."""
        keys = list(items)
        if not keys:
            return True
        payload = bytearray()
        for key, value in keys:
            data = value if isinstance(value, bytes) else str(value).encode()
            payload += (b"set " + key.encode() + b" 0 "
                        + str(int(ttl)).encode() + b" "
                        + str(len(data)).encode() + b"\r\n" + data + b"\r\n")

        def op():
            replies = self._exchange(bytes(payload), len(keys), None)
            return len(replies) == len(keys)
        return bool(self._run(op) or False)

    def get(self, key):
        """Value bytes or None (miss / down)."""
        cmd = b"get " + key.encode() + b"\r\n"
        buf = bytearray()

        # data blocks need exact-length reads, not markers - handled inline
        def op():
            self.sock.sendall(cmd)
            line = self._recv_until(buf, b"\r\n")
            if not line.startswith(b"VALUE "):
                return None   # END (miss) or an error line -> treat as miss
            nbytes = int(line.rsplit(b" ", 1)[1])
            raw = self._recv_exact(buf, nbytes + 2)  # data + CRLF
            self._recv_until(buf, b"END\r\n")
            return raw[:nbytes]
        return self._run(op)

    def get_int(self, key):
        v = self.get(key)
        if v is None:
            return None
        try:
            return int(v)
        except ValueError:
            return None

    def _recv_exact(self, buf, n):
        while len(buf) < n:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("memcached closed connection")
            buf.extend(chunk)
        out = bytes(buf[:n])
        del buf[:n]
        return out

    def delete(self, key):
        cmd = b"delete " + key.encode() + b"\r\n"

        def op():
            replies = self._exchange(cmd, 1, None)
            return replies and replies[0].startswith(b"DELETED")
        return bool(self._run(op) or False)

    def healthy(self):
        """Live probe for /api/health - a real round trip, cheap and local."""
        return self.set("p2s:health", "1", ttl=5)


class ServiceState(object):
    def __init__(self, cfg):
        self.cfg = cfg
        self.allowlist = load_allowlist(cfg["allowlist_file"])
        self.store = None
        if cfg.get("db_path"):
            self.store = Store(cfg["db_path"])
        # Server-side patched-releases list: shared by all clients, so the
        # site is fully usable by everyone with zero browser configuration.
        self.releases_lock = threading.Lock()
        self.patched_releases = []
        if self.store is not None:
            raw = self.store.get_setting("patched_releases")
            if raw:
                try:
                    self.patched_releases = json.loads(raw)
                except ValueError:
                    pass
        self.jobs = {}
        self.jobs_lock = threading.Lock()
        self.q = queue.Queue(maxsize=cfg["queue_limit"])
        self.cache = {}
        self.cache_lock = threading.Lock()
        self.rate = {}
        self.rate_lock = threading.Lock()
        self.stats_lock = threading.Lock()
        self.in_flight = 0
        self.started_at = time.time()
        self.stop = threading.Event()
        self.workers = []
        self.pow = {}            # challenge id -> (expires, purpose, bits, ip)
        self.pow_open = {}       # ip -> unsolved challenges outstanding
        self.pow_lock = threading.Lock()
        self.seq = 0             # FIFO sequence for queue-position reporting
        self.seq_lock = threading.Lock()
        # metrics bus (localhost memcached, optional): queue depth + per-job
        # positions are published by a 1s thread; readers fall back to local
        # computation whenever a value is missing. og_cards live on disk.
        mc = cfg.get("memcached")
        self.mc = Memcache(mc) if mc and mc != "none" else None
        og_dir = cfg.get("og_cache_dir")
        if og_dir is None or og_dir == "":
            base = (os.path.dirname(os.path.abspath(cfg["db_path"]))
                    if cfg.get("db_path")
                    else os.path.dirname(os.path.abspath(__file__)))
            og_dir = os.path.join(base, "og-cache")
        self.og = None if og_dir == "none" else _OgCache(og_dir)
        # Secret salt for generating/verifying finding access keys
        # (16-char alphanumeric token appended to share URL for instant retrieval)
        self.salt = None
        if self.store is not None:
            self.salt = self.store.get_setting("secret_salt")
            if not self.salt:
                self.salt = secrets.token_hex(32)
                self.store.set_setting("secret_salt", self.salt)
        if not self.salt:
            self.salt = secrets.token_hex(32)

    def finding_key(self, domain):
        """16 alphanumeric characters unique to domain + server's secret salt."""
        d = domain.lower().strip()
        return hmac.new(self.salt.encode("utf-8"), d.encode("utf-8"),
                        hashlib.sha256).hexdigest()[:16]

    def verify_finding_key(self, domain, key):
        """Verify whether the key matches domain + secret salt."""
        if not key or len(key) != 16 or not key.isalnum():
            return False
        expected = self.finding_key(domain)
        return hmac.compare_digest(expected, key.lower())

    def get_finding_by_key(self, domain, key):
        """If key matches domain + salt, return cached result immediately."""
        if not self.verify_finding_key(domain, key):
            return None
        d = domain.lower().strip()
        facts = None
        # 1. Hot memory cache
        with self.cache_lock:
            for (k_url, k_lvl), (ts, val) in self.cache.items():
                if k_lvl == "block" and _host_of(k_url) == d:
                    facts = dict(val)
                    facts["cached"] = True
                    facts["fetched_at"] = ts
                    break
        # 2. Memcached
        if facts is None and self.mc is not None:
            cands = ["https://" + d, "https://" + d + "/", "http://" + d, "http://" + d + "/"]
            for cand in cands:
                try:
                    mc_res = self.mc.get("p2s:res:" + hashlib.sha256(
                        ("%s|block" % cand).encode("utf-8")).hexdigest())
                    if mc_res:
                        facts = json.loads(mc_res.decode("utf-8"))
                        facts["cached"] = True
                        break
                except Exception:
                    pass
        # 3. Persistent SQLite store
        if facts is None and self.store is not None:
            cands = ["https://" + d, "https://" + d + "/", "http://" + d, "http://" + d + "/"]
            for cand in cands:
                facts = self.store.get_fresh(cand, "block", 30 * 86400)
                if facts is not None:
                    break
            if facts is None:
                # also search store by host prefix if port was in url
                try:
                    row = self.store._conn().execute(
                        "SELECT fetched_at, facts_json FROM results WHERE level = 'block' "
                        "AND (url LIKE ? OR url LIKE ?) ORDER BY fetched_at DESC LIMIT 1",
                        ("http://" + d + ":%", "https://" + d + ":%"),
                    ).fetchone()
                    if row:
                        fetched_at, blob = row
                        facts = json.loads(blob)
                        facts["cached"] = True
                        facts["fetched_at"] = fetched_at
                except Exception:
                    pass
        if facts is not None:
            facts["finding_key"] = self.finding_key(d)
        return facts

    # -- proof of work ------------------------------------------------------
    # Hashcash-style: client finds nonce so that SHA-256("<id>:<nonce>") has
    # >= <bits> leading zero bits. Challenges are random, single-use, expire
    # quickly, and are purpose-bound ("scan" vs "status" carry different
    # difficulties, so polls are cheaper than submissions).

    def scan_bits_extra(self):
        """Adaptive scan difficulty: +1 bit (2x the work) per doubling of the
        queue beyond 2x workers, capped at pow_scan_max_extra. Polls stay
        cheap - they only follow work that already paid to get in."""
        depth, t, extra = self.q.qsize(), 2 * max(1, self.cfg["workers"]), 0
        while depth >= t and extra < self.cfg.get("pow_scan_max_extra", 0):
            extra += 1
            t *= 2
        return extra

    def _pow_drop(self, cid):
        """Remove a challenge + its per-IP count. Caller holds pow_lock."""
        entry = self.pow.pop(cid, None)
        if entry is not None:
            ip = entry[3]
            n = self.pow_open.get(ip, 0) - 1
            if n > 0:
                self.pow_open[ip] = n
            else:
                self.pow_open.pop(ip, None)
        return entry

    def issue_pow(self, purpose, ip=""):
        """Returns a challenge dict, None (global memory bound) or
        {"error": ...} when this IP already holds too many unsolved ones."""
        extra = 0
        if purpose == "scan":
            bits = self.cfg["pow_scan_bits"]
            if bits > 0:
                extra = self.scan_bits_extra()
                bits += extra
        else:
            bits = self.cfg["pow_poll_bits"]
        if bits <= 0:
            return {"disabled": True, "bits": 0}
        with self.pow_lock:
            if len(self.pow) > 10000:
                return None  # memory bound; a challenge costs the issuer nothing
            # per-IP cap: one client cannot fill the global pool and lock
            # every other visitor out for pow_ttl
            if self.pow_open.get(ip, 0) >= self.cfg.get("pow_open_per_ip", 64):
                return {"error": "too many open challenges"}
            cid = uuid.uuid4().hex
            self.pow[cid] = (time.time() + self.cfg["pow_ttl"], purpose, bits, ip)
            self.pow_open[ip] = self.pow_open.get(ip, 0) + 1
        ch = {"id": cid, "bits": bits, "expires_in_s": int(self.cfg["pow_ttl"])}
        if extra:
            ch["busy"] = True   # client: "server busy - longer proof of work"
        return ch

    _POW_NONCE_RE = re.compile(r"[0-9a-f]{1,16}$")

    def check_pow(self, cid, nonce, purpose):
        """Validate and BURN a challenge (single-use). Returns None or error."""
        bits_cfg = (self.cfg["pow_scan_bits"] if purpose == "scan"
                    else self.cfg["pow_poll_bits"])
        if bits_cfg <= 0:
            return None  # pow disabled for this flow
        if not isinstance(cid, str) or not isinstance(nonce, str) \
                or not self._POW_NONCE_RE.match(nonce):
            return "pow required/invalid"
        with self.pow_lock:
            entry = self._pow_drop(cid)  # burned even if checks below fail
        if entry is None:
            return "pow invalid or already used"
        expires, p, bits, _ip = entry
        if p != purpose:
            return "pow purpose mismatch"
        if time.time() > expires:
            return "pow expired"
        got = 256 - int.from_bytes(
            hashlib.sha256(("%s:%s" % (cid, nonce)).encode()).digest()
        ).bit_length()
        if got < bits:
            return "pow too weak"
        return None

    def _next_seq(self):
        with self.seq_lock:
            self.seq += 1
            return self.seq


    # -- submission -----------------------------------------------------

    def _rate_ok(self, ip):
        with self.rate_lock:
            dq = self.rate.setdefault(ip, deque())
            now = time.time()
            while dq and now - dq[0] > 60.0:
                dq.popleft()
            if len(dq) >= self.cfg["rate_per_minute"]:
                return False
            dq.append(now)
            return True

    def submit(self, raw_urls, level, ip, force=False):
        """Returns (job_id, total, error). Exactly one of job_id/error set."""
        if level not in ("banner", "block"):
            return None, 0, "level must be 'banner' or 'block'"
        if not isinstance(raw_urls, list) or not raw_urls:
            return None, 0, "urls must be a non-empty list"
        if len(raw_urls) > self.cfg["max_urls_per_job"]:
            return None, 0, "too many urls (max %d per job)" % self.cfg["max_urls_per_job"]
        if not self._rate_ok(ip):
            return None, 0, "rate limit exceeded, retry later"

        valid, rejected = [], {}
        seen = set()
        for u in raw_urls:
            if not isinstance(u, str):
                continue
            u = u.strip()
            if not u or u in seen:
                continue
            seen.add(u)
            if len(u) > 2048:
                rejected[u] = {"error": "url too long"}
                continue
            if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", u):
                u = "https://" + u  # bare host -> https
            if urllib.parse.urlsplit(u).scheme not in ("http", "https"):
                rejected[u] = {"error": "scheme not allowed (http/https only)"}
                continue
            valid.append(u)
        if not valid and not rejected:
            return None, 0, "no usable urls"

        if self.q.qsize() + len(valid) > self.cfg["queue_limit"]:
            return None, 0, "server queue full, retry later"

        job_id = uuid.uuid4().hex[:12]
        # job.urls includes rejected entries too, so clients render them
        # (with their error facts) instead of silently dropping them.
        seq = self._next_seq()
        job = Job(job_id, valid + list(rejected.keys()), level, force, seq)
        job.results.update(
            (u, dict(r, url=u, level=level,
                     fetched_at=time.time())) for u, r in rejected.items()
        )
        with self.jobs_lock:
            self.jobs[job_id] = job
        if self.store is not None:
            try:
                self.store.put_job(job_id, level, len(job.urls), ip)
                if not valid:
                    self.store.finalize_job(job_id, len(job.results))  # rejected-only job
            except Exception:
                pass  # persistence is best-effort; scanning must not fail
        for i, u in enumerate(valid):
            self.q.put_nowait((job_id, u, seq + i))
        return job_id, len(job.urls), None

    # -- workers ---------------------------------------------------------

    def start_workers(self):
        for _ in range(self.cfg["workers"]):
            t = threading.Thread(target=self._worker, daemon=True)
            t.start()
            self.workers.append(t)
        gc = threading.Thread(target=self._gc_loop, daemon=True)
        gc.start()
        pub = threading.Thread(target=self._metrics_loop, daemon=True)
        pub.start()
        self.workers.append(pub)   # stopped via self.stop, like the rest

    def _worker(self):
        while not self.stop.is_set():
            try:
                item = self.q.get(timeout=1.0)
            except queue.Empty:
                continue
            try:
                if item is None:
                    break
                job_id, url, _seq = item
                with self.jobs_lock:
                    job = self.jobs.get(job_id)
                if job is None:
                    continue
                key = (url, job.level)
                facts = None
                # Check cache only if cache_ttl > 0 and not force
                if not job.force and self.cfg["cache_ttl"] > 0:
                    # L1: hot in-memory cache (same-run dedupe).
                    with self.cache_lock:
                        hit = self.cache.get(key)
                        if hit and time.time() - hit[0] < self.cfg["cache_ttl"]:
                            facts = dict(hit[1])
                            facts["cached"] = True
                            facts["fetched_at"] = hit[0]
                    # L2: memcached results JSON (fast out-of-process cache)
                    if facts is None and self.mc is not None:
                        try:
                            mc_res = self.mc.get("p2s:res:" + hashlib.sha256(
                                ("%s|%s" % (url, job.level)).encode("utf-8")).hexdigest())
                            if mc_res:
                                facts = json.loads(mc_res.decode("utf-8"))
                                facts["cached"] = True
                        except Exception:
                            facts = None
                    # L3: persistent store (survives restarts; skipped on force)
                    if facts is None and self.store is not None:
                        try:
                            facts = self.store.get_fresh(
                                url, job.level, self.cfg["cache_ttl"])
                        except Exception:
                            facts = None  # persistence is best-effort

                    # If we got a cache hit, ensure it still satisfies current SSRF/allowlist rules
                    if facts is not None and not self.cfg["allow_private"]:
                        try:
                            _guard_url(url, self.cfg, self.allowlist)
                        except ProbeError:
                            facts = None

                if facts is None:
                    with self.stats_lock:
                        self.in_flight += 1
                    try:
                        facts = probe_url(url, job.level, self.cfg, self.allowlist)
                    except Exception as e:  # never let one URL kill a worker
                        facts = {"url": url, "level": job.level,
                                 "error": "internal: %s" % e}
                    finally:
                        with self.stats_lock:
                            self.in_flight -= 1
                    facts["fetched_at"] = time.time()  # client shows the test date
                    # Attach secret finding_key for finished checks
                    host = _host_of(url)
                    if host:
                        facts["finding_key"] = self.finding_key(host)
                    if self.cfg["cache_ttl"] > 0:
                        with self.cache_lock:
                            self.cache[key] = (time.time(), facts)
                        if self.mc is not None:
                            try:
                                self.mc.set("p2s:res:" + hashlib.sha256(
                                    ("%s|%s" % (url, job.level)).encode("utf-8")).hexdigest(),
                                    json.dumps(facts),
                                    ttl=int(self.cfg["cache_ttl"]))
                            except Exception:
                                pass
                        if self.store is not None:
                            try:
                                self.store.put_result(url, job.level, facts)
                            except Exception:
                                pass
                with job.lock:
                    job.results[url] = facts
                    finished = len(job.results) >= len(job.urls)
                if finished and self.store is not None:
                    try:
                        self.store.finalize_job(job_id, len(job.results))
                    except Exception:
                        pass
            finally:
                try:
                    self.q.task_done()
                except ValueError:
                    pass

    def _gc_loop(self):
        while not self.stop.wait(30.0):
            now = time.time()
            with self.jobs_lock:
                stale = [k for k, j in self.jobs.items() if now - j.created > self.cfg["job_ttl"]]
                for k in stale:
                    del self.jobs[k]
            with self.cache_lock:
                stale = [k for k, v in self.cache.items()
                         if now - v[0] > self.cfg["cache_ttl"]]
                for k in stale:
                    del self.cache[k]
            if self.store is not None:
                try:
                    self.store.purge(now - self.cfg["retain_hours"] * 3600.0)
                except Exception:
                    pass
            with self.pow_lock:  # drop expired PoW challenges
                stale = [k for k, v in self.pow.items() if v[0] < now]
                for k in stale:
                    self._pow_drop(k)
            if self.og is not None:
                try:
                    self.og.gc()   # stale OG card files off the disk
                except Exception:
                    pass

    def _metrics_loop(self):
        """Publish queue state to the localhost memcached bus every
        metrics_interval seconds. Pipelined writes: counters
        (p2s:queue_depth / p2s:in_flight / p2s:jobs_active, TTL 10s) and
        p2s:qp/<job_id> per queued job (TTL 5s, so positions of finished
        jobs expire on their own). Status polls read these instead of
        scanning the queue under its lock; everything here is best-effort -
        with memcached down the loop simply skips and readers fall back."""
        interval = max(0.2, float(self.cfg.get("metrics_interval", 1.0)))
        while not self.stop.wait(interval):
            if self.mc is None:
                return
            try:
                with self.jobs_lock:
                    jobs_active = sum(
                        1 for j in self.jobs.values()
                        if len(j.results) < len(j.urls))
                counters = [
                    ("p2s:queue_depth", self.q.qsize()),
                    ("p2s:in_flight", self.in_flight),
                    ("p2s:jobs_active", jobs_active),
                ]
                with self.q.mutex:      # one snapshot of the queue
                    queued = [it for it in self.q.queue
                              if isinstance(it, tuple) and len(it) == 3]
                positions = []
                if queued:
                    seqs = sorted(it[2] for it in queued)
                    first = {}          # job -> its earliest item's seq
                    for job_id, _u, s in queued:
                        if job_id not in first or s < first[job_id]:
                            first[job_id] = s
                    positions = [
                        ("p2s:qp/" + job_id,
                         # position = queued items ahead of the job's first
                         # item (same formula as the in-process fallback)
                         bisect.bisect_left(seqs, s))
                        for job_id, s in first.items()
                    ]
                self.mc.set_many(counters, ttl=10)
                if positions:
                    self.mc.set_many(positions, ttl=5)
            except Exception:
                continue   # never let metrics kill anything

    def shutdown(self):
        self.stop.set()
        for _ in self.workers:
            try:
                self.q.put_nowait(None)
            except queue.Full:
                pass

    def get_releases(self):
        with self.releases_lock:
            return list(self.patched_releases)

    def set_releases(self, releases):
        """Replace the shared patched-release list. Returns None on success,
        an error string otherwise (persists across restarts via the store)."""
        if self.store is None:
            return "persistence disabled: cannot store releases"
        self.store.set_setting("patched_releases", json.dumps(releases))
        with self.releases_lock:
            self.patched_releases = list(releases)
        return None

    def og_image(self, url):
        """PNG preview card for a URL - READ-ONLY: renders whatever result is
        already stored (any age; the card shows when it was tested). It never
        queues a probe, so scrapers cannot trigger scans. Accepts the same
        friendly ?url= form as the page (scheme/trailing slash optional)."""
        url = _norm_target(url)
        if url is None:
            return None
        hit = self.og.get(url) if self.og is not None else None
        if hit is not None:
            return hit
        facts = None
        if self.mc is not None:
            for cand in dict.fromkeys((url, url.rstrip("/"), url.rstrip("/") + "/")):
                try:
                    mc_res = self.mc.get("p2s:res:" + hashlib.sha256(
                        ("%s|block" % cand).encode("utf-8")).hexdigest())
                    if mc_res:
                        facts = json.loads(mc_res.decode("utf-8"))
                        facts.pop("cached", None)
                        break
                except Exception:
                    pass
        if facts is None and self.store is not None:
            # the store keys by exactly what was scanned; try both slash forms
            for cand in dict.fromkeys((url, url.rstrip("/"), url.rstrip("/") + "/")):
                facts = self.store.get_fresh(cand, "block", 30 * 86400)
                if facts is not None:
                    break
            if facts is not None:
                facts.pop("cached", None)
        png = og_png(facts, self.get_releases())
        if self.og is not None:
            self.og.put(url, png)
        return png

    # -- readouts ----------------------------------------------------------

    def snapshot(self, job_id):
        with self.jobs_lock:
            job = self.jobs.get(job_id)
        if job is None:
            return None
        with job.lock:
            results = dict(job.results)
        total = len(job.urls)
        done = len(results)
        state = "done" if done >= total else ("running" if done else "queued")
        if state == "done":
            for u, f in results.items():
                if isinstance(f, dict) and "finding_key" not in f:
                    host = _host_of(u)
                    if host:
                        f["finding_key"] = self.finding_key(host)
        # queue position: how many scan items submitted BEFORE this job are
        # still waiting in the queue (in-flight work is reported separately).
        # Fast path: the memcached metrics bus publishes positions every
        # second - read O(1) from there. Fallback (bus down, key expired or
        # job submitted between ticks): the exact in-process scan below.
        ahead = 0
        if state != "done":
            published = self.mc.get_int("p2s:qp/" + job.id) if self.mc else None
            if published is not None:
                ahead = published
            else:
                with self.q.mutex:
                    ahead = sum(1 for it in self.q.queue
                                if isinstance(it, tuple) and it[2] < job.seq)
        return {
            "job_id": job.id,
            "level": job.level,
            "urls": job.urls,
            "total": total,
            "done": done,
            "state": state,
            "queue_position": ahead,
            "in_flight": self.in_flight,
            "results": results,
        }

    def health(self):
        with self.jobs_lock:
            jobs_active = sum(1 for j in self.jobs.values() if len(j.results) < len(j.urls))
        with self.cache_lock:
            cache_size = len(self.cache)
        health = {
            "service": "php2shell-fleet-check",
            "version": VERSION,
            "uptime_s": int(time.time() - self.started_at),
            "workers": self.cfg["workers"],
            "queue_depth": self.q.qsize(),
            "in_flight": self.in_flight,
            "jobs_active": jobs_active,
            "cache_size": cache_size,
            "store": self.store.stats() if self.store else None,
            "patched_releases": self.get_releases(),
            "config": {
                "workers": self.cfg["workers"],
                "rate_per_minute": self.cfg["rate_per_minute"],
                "cache_ttl_s": self.cfg["cache_ttl"],
                "max_urls_per_job": self.cfg["max_urls_per_job"],
                "allowlist": bool(self.allowlist),
                "allow_private": self.cfg["allow_private"],
                "verify_tls": self.cfg["verify_tls"],
                "trust_proxy": self.cfg.get("trust_proxy", False),
                "pow_scan_bits": self.cfg["pow_scan_bits"],
                "pow_poll_bits": self.cfg["pow_poll_bits"],
                "pow_scan_bits_now": (self.cfg["pow_scan_bits"]
                                      + self.scan_bits_extra()
                                      if self.cfg["pow_scan_bits"] > 0 else 0),
                "pow_scan_max_extra": self.cfg.get("pow_scan_max_extra", 0),
                "pow_open_per_ip": self.cfg.get("pow_open_per_ip", 64),
            },
        }
        if self.store:
            health["config"]["db_path"] = self.cfg["db_path"]
            health["config"]["retain_hours"] = self.cfg["retain_hours"]
        if self.og is not None:
            health["config"]["og_cache_dir"] = self.og.dir
        if self.mc is not None:
            health["memcached"] = {
                "addr": "%s:%s" % self.mc.addr,
                "ok": bool(self.mc.healthy()),
            }
        return health


# ---------------------------------------------------------------- HTTP server

_INDEX = None       # cached index.html bytes
_INDEX_HTML = None  # decoded once; ?url= requests get OG meta injected
_LLMS = None        # decoded once; /llms.txt served as text/plain

# ------------------------------------------- OG preview cards (link shares)

# The tested URL lives in a REAL query param (?url=...) so link-preview
# scrapers can be served an image. Scrapers do not run JS, so the preview
# card needs a server-side render: this is the ONLY place outside the
# browser with verdict logic, and it mirrors the client's interpret() —
# both are locked by the test suites (e2e: python port, node: JS original).
_OG_TTL = 600          # seconds a rendered PNG is reused ("cache a bit")
_OG_CACHE_MAX_FILES = 4096   # disk cache cap; oldest files dropped beyond this

OG_W, OG_H = 1200, 630

try:
    from PIL import Image, ImageDraw, ImageFont
    _HAVE_PIL = True
except ImportError:      # degraded preview: flat card, no text
    _HAVE_PIL = False

# dark-mode palette (matches html[data-theme=dark] in index.html)
_OG_C = {
    "bg": (21, 26, 33), "card": (29, 36, 46), "border": (57, 67, 79),
    "fg": (215, 221, 229), "muted": (147, 160, 173),
    "bad": ((60, 26, 26), (241, 154, 154), (107, 47, 47)),
    "ok": ((23, 52, 34), (127, 211, 154), (44, 92, 63)),
    "info": ((28, 40, 54), (159, 192, 224), (51, 80, 107)),
    "warn": ((58, 47, 20), (232, 200, 119), (107, 90, 38)),
}


def _og_font(size, mono=False):
    name = "DejaVuSansMono.ttf" if mono else "DejaVuSans.ttf"
    try:
        return ImageFont.truetype("/usr/share/fonts/truetype/dejavu/" + name, size)
    except Exception:
        return ImageFont.load_default(size=size)


def _php_preview(facts, releases):
    """Mirror of the client's phpDimension (server-side patched list)."""
    g = facts.get("get") or {}
    if "error" in g:
        return {"cls": "info", "text": "no response"}
    m = re.search(r"PHP/(\d+(?:\.\d+)+)", str(g.get("x_powered_by") or ""), re.I)
    if not m:
        seen = "PHP app (session cookie), " if g.get("php_session_cookie") else ""
        return {"cls": "info",
                "text": seen + "version hidden — unknown (HTTP %s)" % (g.get("status") or "?")}
    v = m.group(1)
    if not releases:
        return {"cls": "info", "text": v + " — patched list not set"}
    parts = v.split(".")
    maj = int(parts[0])
    mino = int(parts[1]) if len(parts) > 1 else 0
    if maj < 8:
        return {"cls": "bad", "text": v + " — EOL branch, no fix coming"}
    entry = None
    for p in releases:
        pp = p.split(".")
        if len(pp) > 1 and int(pp[0]) == maj and int(pp[1]) == mino:
            entry = p
            break
    # an 8.x branch older than every listed 8.x branch is EOL (8.0/8.1 by now)
    minors = [int(p.split(".")[1]) for p in releases
              if len(p.split(".")) > 1 and int(p.split(".")[0]) == maj]
    if entry is None and minors and mino < min(minors):
        return {"cls": "bad", "text": v + " — EOL branch, no fix coming"}
    if entry is None:
        return {"cls": "info", "text": v + " — no data for this branch — unknown"}
    key = lambda s: tuple(int(x) for x in s.split("."))
    if key(v) >= key(entry):
        return {"cls": "ok", "text": v + " ≥ " + entry}
    return {"cls": "bad", "text": v + " < " + entry}


def _blk_preview(facts):
    """Mirror of the client's blockDimension."""
    if facts.get("level") != "block":
        return None
    g = facts.get("get") or {}
    php_ev = bool(g.get("php_session_cookie") or g.get("x_powered_by"))
    tail = " — PHP present, version unknown" if php_ev else None

    def st(p):
        if "first_status" in p:
            return p["first_status"]
        if p.get("redirect"):
            return 302
        return p.get("status") or 0

    def is_through(p):
        if not p or "error" in p or p.get("skipped"):
            return False
        fs = p.get("first_status", p.get("status", 0))
        if 200 <= fs < 300:
            return True
        if fs in (307, 308) and 200 <= (p.get("status") or 0) < 300:
            return True
        return False

    ue = facts.get("post_urlencoded") or {}
    mps = [(m, facts.get(m.lower() + "_multipart"))
           for m in ("POST", "PUT", "PATCH")]
    mps = [(m, p) for m, p in mps if p and not p.get("skipped")]
    if not mps:
        if "error" in ue:
            return {"cls": "info", "static": True,
                    "text": "probe error (%s)" % ue["error"]}
        be = ue.get("baseline_error")
        return {"cls": "info", "static": True,
                "text": "POST requests dropped before any processing"
                        + (" (%s)" % be if be else "")
                        + (tail or " — no PHP indicators")}
    if any("error" in p for _, p in mps):
        return {"cls": "info", "text": "probe error"}
    all405 = all(st(p) in (405, 501)
                 for p in [ue] + [p for _, p in mps])
    if all405:
        ms = "+".join(m for m, _ in mps)
        # PHP signs ON the 405s = PHP generated it, after parsing the upload
        signed = [m for m, p in mps
                  if p.get("php_session_cookie") or p.get("x_powered_by")]
        if signed:
            sl = signed[0] if len(signed) < 2 \
                else ", ".join(signed[:-1]) + " and " + signed[-1]
            return {"cls": "bad", "php405": True,
                    "text": "NOT BLOCKED — PHP itself answered 405 on " + sl}
        if php_ev:
            return {"cls": "ok", "static": True, "not_vuln": True,
                    "text": "uploads refused with 405 before PHP saw them (%s)"
                            % ms}
        return {"cls": "info", "static": True,
                "text": "no request-body processing (405/501 on %s)"
                        " — static hosting likely" % ms}
    def and_list(a):
        return a[0] if len(a) < 2 else ", ".join(a[:-1]) + " and " + a[-1]

    through = [m for m, p in mps if is_through(p)]
    if through:
        return {"cls": "bad",
                "text": "NOT BLOCKED — test uploads were accepted on "
                        + and_list(through)}
    # a redirect is NOT a block (PHP parses the body before the app's 3xx;
    # 301/302/303 follow-ups are GETs) - never green/static
    redir = [m for m, p in mps if 300 <= st(p) < 400]
    if redir:
        if php_ev:
            return {"cls": "bad",
                    "text": "NOT BLOCKED — test uploads were redirected, "
                            "not blocked, on " + and_list(redir)}
        return {"cls": "info",
                "text": "INCONCLUSIVE — test uploads were redirected on "
                        + and_list(redir)}
    if is_through(ue):
        return {"cls": "ok", "text": "active (multipart rejected on "
                + ("POST+PUT+PATCH" if len(mps) == 3 else "POST") + ", likely before PHP)"}
    # When every probe (including GET) was edge-blocked (403/406), mark WAF assumed.
    gst = st(g)
    is_blk = lambda s: s in (403, 406)
    if is_blk(gst) and is_blk(st(ue)) and all(is_blk(st(p)) for _, p in mps):
        return {"cls": "warn", "waf": True,
                "text": "WAF assumed (%s on GET+%s)"
                        % (gst, "+".join(m for m, _ in mps))}
    rej = ", ".join("%s %s" % (m, st(p)) for m, p in mps)
    return {"cls": "info",
            "text": "all rejected (%s) — edge vs app-level indistinguishable remotely"
                    % rej}


def _verdict_preview(facts, releases):
    """Mirror of the client's interpret(). Returns (label, cls, php, blk)."""
    g = facts.get("get") or {}
    php = _php_preview(facts, releases)
    blk = _blk_preview(facts)
    ue = facts.get("post_urlencoded") or {}
    if "connectionrefused" in str(g.get("error") or "").lower():
        return "OFFLINE", "ok", php, blk
    if "error" in g and (blk is None or "error" in ue or blk.get("static")):
        return "UNREACHABLE", "info", php, blk
    if blk and blk.get("waf"):
        return "TEST BLOCKED", "warn", php, blk
    if php["cls"] == "bad" and blk and blk["cls"] == "bad":
        return "EXPOSED", "bad", php, blk
    if php["cls"] == "bad":
        return "UNPATCHED", "bad", php, blk
    if blk and blk.get("not_vuln"):
        return ("PATCHED" if php["cls"] == "ok"
                else "(PROBABLY) NOT VULNERABLE"), "ok", php, blk
    if blk and blk["cls"] == "ok":
        return "BLOCKED", "ok", php, blk
    if blk and blk["cls"] == "bad":
        if g.get("php_session_cookie") or g.get("x_powered_by") \
                or blk.get("php405"):
            return "ASSUMED VULNERABLE", "bad", php, blk
        return "UNKNOWN", "info", php, blk
    if (blk and blk.get("static") and php["cls"] == "info"
            and not g.get("php_session_cookie") and not g.get("x_powered_by")):
        return "NO PHP DETECTED", "ok", php, blk
    if php["cls"] == "ok":
        return "PATCHED", "ok", php, blk
    return "UNKNOWN", "info", php, blk


def _og_chip(d, x, y, text, pal, font, max_w, max_lines=1):
    """Draw a chip (bordered rectangle + wrapped text); returns its height."""
    if not text:
        return 0
    lines, cur = [], ""
    for w in str(text).split(" "):
        cand = (cur + " " + w).strip()
        if d.textlength(cand, font=font) <= max_w or not cur:
            cur = cand
        else:
            lines.append(cur)
            cur = w
    if cur:
        lines.append(cur)
    if len(lines) > max_lines:
        lines = lines[:max_lines]
        lines[-1] = _og_text_fit(d, lines[-1] + "…", font, max_w)
    lh = font.size + 8
    w = max(int(d.textlength(t, font=font)) for t in lines) + 20
    h = len(lines) * lh + 10
    d.rectangle([x, y, x + w, y + h], fill=pal[0], outline=pal[2], width=2)
    for i, t in enumerate(lines):
        d.text((x + 10, y + 6 + i * lh), t, font=font, fill=pal[1])
    return h


def _og_text_fit(d, text, font, max_w):
    while text and d.textlength(text, font=font) > max_w:
        text = text[:-2] if text.endswith("…") else text[:-1] + "…"
    return text


def _host_of(u):
    """Bare domain (host lowercased, port stripped) of an http(s) URL, or ''.

    Mirrors the client's hostOf()+bareDomain: the OG arrow shows and links
    the bare domain, and the different-host test is port-insensitive.
    """
    m = re.match(r"^https?://([^/?#]+)", str(u or ""), re.I)
    if not m:
        return ""
    h = m.group(1).lower()
    if ":" in h and not h.startswith("["):
        h = h.split(":", 1)[0]
    return h


def _norm_target(raw):
    """Normalize a ?url= value to a full http(s) URL, or None if unusable.

    Accepts every shape a link may carry: a full URL (encoded or plain), or
    the friendly form the UI writes - scheme + trailing slash stripped, '&'
    shown as '~' so it cannot split the query string. '~' inside a target
    path is rare; the ambiguity is documented and accepted."""
    if not raw:
        return None
    u = urllib.parse.unquote(str(raw).replace("~", "&")).strip()
    if not u:
        return None
    m = re.match(r"^([a-z][a-z0-9+.\-]*):", u, re.I)
    if m:
        # carries an explicit scheme: only http(s) is usable
        if not re.match(r"^https?://", u, re.I):
            return None
    else:
        u = "https://" + u
    if len(u) > 2048:
        return None
    try:
        sp = urllib.parse.urlsplit(u)
    except Exception:
        return None
    if not sp.netloc:
        return None
    return urllib.parse.urlunsplit(
        (sp.scheme.lower(), sp.netloc.lower(), sp.path or "", sp.query or "", sp.fragment or "")
    )


def og_png(facts, releases):
    """Render the dark-mode result card as a PNG. facts=None -> 'not tested'."""
    if _HAVE_PIL:
        img = Image.new("RGB", (OG_W, OG_H), _OG_C["bg"])
        d = ImageDraw.Draw(img)
        d.rectangle([40, 40, OG_W - 40, OG_H - 40],
                    fill=_OG_C["card"], outline=_OG_C["border"], width=2)
        f_title = _og_font(28)
        f_url = _og_font(36, mono=True)
        f_lab = _og_font(20)
        f_chip = _og_font(26)
        f_verdict = _og_font(34)
        f_small = _og_font(22, mono=True)
        mx = OG_W - 120
        d.text((80, 74), "php2shell check", font=f_title, fill=_OG_C["muted"])
        if facts is None:
            d.text((80, 150), "no stored result for this URL yet",
                   font=_og_font(34), fill=_OG_C["fg"])
            d.text((80, 210), "run a check, then re-open this link",
                   font=_og_font(24), fill=_OG_C["muted"])
        else:
            url = _og_text_fit(d, str(facts.get("url") or ""), f_url, mx)
            d.text((80, 120), url, font=f_url, fill=_OG_C["fg"])
            # redirect end-domain, same "url -> endhost" line the live header
            # shows when the probe followed redirects onto another host.
            # Prefer GET's redirect, fall back to POST probes if GET didn't redirect.
            redir_p = next(
                (p for p in (facts.get("get"), facts.get("post_urlencoded"),
                             facts.get("post_multipart"))
                 if p and (p.get("redirects") or 0) > 0 and p.get("final_url")),
                facts.get("get") or {})
            end_h = _host_of(redir_p.get("final_url"))
            orig_h = _host_of(facts.get("url"))
            redir = end_h and orig_h and end_h != orig_h \
                and (redir_p.get("redirects") or 0) > 0
            label, cls, php, blk = _verdict_preview(facts, releases)
            chip_max = mx - 30   # text width cap: chip padding + border stay inside the card
            if redir:
                d.text((80, 168), "\u2192 " + _og_text_fit(d, end_h, f_small, mx - 40),
                       font=f_small, fill=_OG_C["muted"])
                # tightened spacing to make room for the extra line
                d.text((80, 206), "VERDICT", font=f_lab, fill=_OG_C["muted"])
                _og_chip(d, 80, 232, label, _OG_C[cls], f_verdict, chip_max)
                d.text((80, 298), "PHP banner", font=f_lab, fill=_OG_C["muted"])
                _og_chip(d, 80, 324, php["text"], _OG_C[php["cls"]], f_chip, chip_max)
                d.text((80, 390), "vulnerability check", font=f_lab, fill=_OG_C["muted"])
                btxt = blk["text"] if blk else "not tested"
                _og_chip(d, 80, 416, btxt, _OG_C[blk["cls"] if blk else "info"], f_chip,
                         chip_max, max_lines=1)
                foot = OG_H - 70
            else:
                d.text((80, 214), "VERDICT", font=f_lab, fill=_OG_C["muted"])
                _og_chip(d, 80, 244, label, _OG_C[cls], f_verdict, chip_max)
                d.text((80, 322), "PHP banner", font=f_lab, fill=_OG_C["muted"])
                _og_chip(d, 80, 350, php["text"], _OG_C[php["cls"]], f_chip, chip_max)
                d.text((80, 422), "vulnerability check", font=f_lab, fill=_OG_C["muted"])
                btxt = blk["text"] if blk else "not tested"
                _og_chip(d, 80, 450, btxt, _OG_C[blk["cls"] if blk else "info"], f_chip,
                         chip_max, max_lines=2)
                foot = OG_H - 92
            fa = facts.get("fetched_at")
            when = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(fa)) if fa else "?"
            d.text((80, foot), "tested %s · patch & mitigation status for CVE-2026-109618/619"
                   % when, font=f_small, fill=_OG_C["muted"])
        import io
        buf = io.BytesIO()
        img.save(buf, "PNG", optimize=True)
        return buf.getvalue()
    # no Pillow: flat dark card with the verdict color as a stripe
    label, cls = ("NOT TESTED", "info")
    stripe = _OG_C[cls][0]
    rows = bytearray()
    for yy in range(OG_H):
        px = stripe if 40 <= yy < 120 else _OG_C["bg"] if yy < 40 or yy >= OG_H - 40 else _OG_C["card"]
        rows += bytes(px) * OG_W + b"\x00"
    comp = zlib.compress(bytes(rows), 6)

    def chunk(tag, data):
        c = struct.pack(">I", len(data)) + tag + data
        return c + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    ihdr = struct.pack(">IIBBBBB", OG_W, OG_H, 8, 2, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", comp) + chunk(b"IEND", b""))


class _OgCache(object):
    """Disk-backed TTL cache so repeated previews of the same URL render
    once - across restarts, and without holding PNGs in process memory on a
    busy server. Files are keyed by the (normalized) URL's SHA-256; mtime is
    the freshness marker, so expiry + the GC's purge need no side index."""

    def __init__(self, directory):
        self.dir = directory
        os.makedirs(self.dir, exist_ok=True)

    def _path(self, url):
        return os.path.join(
            self.dir, hashlib.sha256(url.encode("utf-8", "replace"))
            .hexdigest()[:32] + ".png")

    def get(self, url):
        try:
            st = os.stat(self._path(url))
            if time.time() - st.st_mtime > _OG_TTL:
                return None
            with open(self._path(url), "rb") as f:
                return f.read()
        except OSError:
            return None

    def put(self, url, png):
        p = self._path(url)
        tmp = "%s.tmp.%d" % (p, threading.get_ident())
        try:
            with open(tmp, "wb") as f:
                f.write(png)
            os.replace(tmp, p)   # atomic: readers never see a half PNG
        except OSError:
            try:
                os.unlink(tmp)
            except OSError:
                pass

    def gc(self, ttl=_OG_TTL):
        """Delete stale files; enforce the file-count cap (oldest first)."""
        try:
            entries = []
            now = time.time()
            for name in os.listdir(self.dir):
                p = os.path.join(self.dir, name)
                try:
                    st = os.stat(p)
                except OSError:
                    continue
                if now - st.st_mtime > ttl:
                    try:
                        os.unlink(p)
                    except OSError:
                        pass
                else:
                    entries.append((st.st_mtime, p))
            entries.sort()
            for _mt, p in entries[:max(0, len(entries) - _OG_CACHE_MAX_FILES)]:
                try:
                    os.unlink(p)
                except OSError:
                    pass
        except OSError:
            pass


_OG = None   # instantiated per ServiceState (needs the configured cache dir)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "php2shell-fleet-check/" + VERSION
    timeout = 60

    # -- helpers -----------------------------------------------------------

    @property
    def state(self):
        return self.server.state

    def _client_ip(self):
        """Client IP for rate limiting. Behind a reverse proxy (--trust-proxy),
        X-Forwarded-For is honored, but ONLY when the direct peer is loopback,
        so the header cannot be spoofed from outside."""
        peer = self.client_address[0]
        if self.state.cfg.get("trust_proxy") and peer in ("127.0.0.1", "::1"):
            xff = (self.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
            if xff:
                return xff
        return peer

    def _json(self, obj, status=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _static(self):
        global _INDEX, _INDEX_HTML
        if _INDEX is None:
            path = __file__.rsplit("/", 1)[0] + "/index.html"
            try:
                with open(path, "rb") as f:
                    _INDEX = f.read()
            except OSError:
                self._json({"error": "index.html not found next to server.py"}, 500)
                return
        if _INDEX_HTML is None:
            _INDEX_HTML = _INDEX.decode("utf-8")
        page = _INDEX_HTML
        # link previews (WhatsApp/Slack/Twitter/...) do not run JS and ignore
        # fragments - inject OG meta only when a target is present. The image
        # is the server-rendered dark-mode card for that URL's stored result.
        # Share format: the path after "/" IS the target URL (e.g.
        # /example.com). Legacy query-form shares (?url=<u> and ?<u>) get a
        # permanent 301 to the path form; /api/og keeps its url= parameter.
        sp = urllib.parse.urlsplit(self.path)
        if sp.path not in ("", "/"):
            raw_path = sp.path.lstrip("/").strip("/")
            parts = [p for p in raw_path.split("/") if p]
            # Check if this is /<domain>/<KEY16>
            cand_domain = parts[0].lower() if parts else ""
            cand_key = parts[1] if len(parts) >= 2 else ""
            if len(cand_key) == 16 and cand_key.isalnum() and self.state.verify_finding_key(cand_domain, cand_key):
                u = _norm_target(cand_domain)
            else:
                u = _norm_target(sp.path.lstrip("/"))
            if u:
                host = (self.headers.get("Host") or "").strip() or "php2shell.site"
                meta = (
                    '<meta property="og:title" content="php2shell check — %s">\n'
                    '  <meta property="og:description" content='
                    '"Patch & mitigation status for CVE-2026-109618/619 '
                    '(PHP session.upload_progress) — inert, raw-facts only.">\n'
                    '  <meta property="og:image" content="https://%s/api/og?url=%s">\n'
                    '  <meta property="og:image:width" content="1200">\n'
                    '  <meta property="og:image:height" content="630">\n'
                    '  <meta name="twitter:card" content="summary_large_image">'
                ) % (html.escape(u, quote=True), html.escape(host, quote=True),
                     urllib.parse.quote(u, safe=""))
                page = page.replace("</head>", meta + "\n</head>", 1)
        elif sp.query:
            # legacy query-form shares: 301 to the /<target> path form
            if sp.query.startswith("url=") and len(sp.query) > 4:
                legacy = urllib.parse.unquote(
                    sp.query[4:].replace("~", "&")).strip()
            else:
                legacy = urllib.parse.unquote(sp.query.replace("~", "&")).strip()
            norm = _norm_target(legacy) if legacy else None
            if norm:
                nice = re.sub(r"^https?://", "", norm, flags=re.I).rstrip("/")
                loc = "/" + urllib.parse.quote(nice, safe="/:._~-")
                self.send_response(301)
                self.send_header("Location", loc)
                self.send_header("Content-Length", "0")
                self.send_header("Cache-Control", "public, max-age=86400")
                self.end_headers()
                return
        body = page.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _llms(self):
        global _LLMS
        if _LLMS is None:
            path = __file__.rsplit("/", 1)[0] + "/llms.txt"
            try:
                with open(path, "rb") as f:
                    _LLMS = f.read()
            except OSError:
                return self._json({"error": "llms.txt not found next to server.py"}, 500)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(_LLMS)))
        self.send_header("Cache-Control", "public, max-age=600")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(_LLMS)

    def log_message(self, fmt, *args):
        line = fmt % args
        try:
            status = int(line.split('"')[2].split()[0])
        except Exception:
            status = 0
        if "POST /api/scan" in line or "POST /api/releases" in line or status >= 500:
            sys.stderr.write("%s\n" % line)

    # -- routes ------------------------------------------------------------

    def do_GET(self):
        try:
            path = urllib.parse.urlsplit(self.path).path
            if path == "/api/health":
                return self._json(self.state.health())
            if path == "/api/releases":
                return self._json(
                    {"patched_releases": self.state.get_releases()})
            if path == "/api/og":
                # link-preview image for ?url= shares; read-only + cached
                q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                png = self.state.og_image((q.get("url") or [""])[0])
                if png is None:
                    return self._json({"error": "url must be http(s)"}, 422)
                self.send_response(200)
                self.send_header("Content-Type", "image/png")
                self.send_header("Content-Length", str(len(png)))
                self.send_header("Cache-Control", "public, max-age=600")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(png)
                return
            if path == "/api/finding":
                # Instant key-authenticated finding lookup without PoW
                q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                domain = (q.get("domain") or [""])[0].lower().strip()
                key = (q.get("key") or [""])[0]
                if not domain or not key:
                    return self._json({"error": "domain and key required"}, 400)
                facts = self.state.get_finding_by_key(domain, key)
                if facts is None:
                    return self._json({"error": "invalid finding key or expired result"}, 404)
                return self._json({"domain": domain, "key": key, "facts": facts})
            if path == "/api/pow":
                # issue a one-time PoW challenge; ?for=scan|status picks the
                # difficulty (scan rises with queue depth). Cheap to issue,
                # worthless without solving: bounded per IP + globally inside
                # issue_pow().
                q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                purpose = (q.get("for") or ["scan"])[0]
                if purpose not in ("scan", "status"):
                    return self._json({"error": "for must be scan|status"}, 422)
                ch = self.state.issue_pow(purpose, self._client_ip())
                if ch is None:
                    return self._json({"error": "server busy"}, 503)
                if "error" in ch:
                    return self._json(ch, 429)
                return self._json(ch)
            m = re.match(r"^/api/job/([0-9a-f]+)$", path)
            if m:
                # status checks need a fresh PoW too (CPU-throttles polling)
                q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                err = self.state.check_pow(
                    (q.get("pow_id") or [None])[0],
                    (q.get("pow_nonce") or [None])[0], "status")
                if err:
                    return self._json({"error": err}, 401)
                snap = self.state.snapshot(m.group(1))
                if snap is None:
                    return self._json({"error": "unknown or expired job"}, 404)
                return self._json(snap)
            if path == "/llms.txt":
                return self._llms()
            if not path.startswith("/api/"):
                # "/" and /<target> share paths all serve the UI page
                return self._static()
            return self._json({"error": "not found"}, 404)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            self._json({"error": "internal: %s" % e}, 500)

    def do_POST(self):
        try:
            path = urllib.parse.urlsplit(self.path).path
            # Parse the body for every POST path (with keep-alive, an unread
            # body would corrupt the next request on the connection).
            n = int(self.headers.get("Content-Length") or 0)
            if n > self.state.cfg["max_body_bytes"]:
                self.close_connection = True
                return self._json({"error": "body too large"}, 413)
            raw = self.rfile.read(n) if n else b""
            try:
                data = json.loads(raw or b"{}")
            except ValueError:
                return self._json({"error": "invalid JSON body"}, 400)
            if not isinstance(data, dict):
                return self._json({"error": "JSON body must be an object"}, 400)
            if path == "/api/releases":
                return self._update_releases(data)
            if path != "/api/scan":
                return self._json({"error": "not found"}, 404)
            # front-door URL sanity BEFORE the PoW check: a bad target must
            # not cost the client its solved challenge
            urls_in = data.get("urls")
            if not isinstance(urls_in, list) or not urls_in:
                return self._json({"error": "urls must be a non-empty list"}, 422)
            urls = []
            allow_http = bool(self.state.cfg.get("allow_http"))
            for u in urls_in:
                cu, err = sanitize_target(u, allow_http=allow_http)
                if err:
                    return self._json(
                        {"error": "rejected %s: %s" % (str(u)[:200], err)}, 422)
                urls.append(cu)
            # submissions must carry a solved PoW challenge (verified + burned)
            pow_data = data.get("pow")
            if not isinstance(pow_data, dict):
                pow_data = {}
            err = self.state.check_pow(pow_data.get("id"), pow_data.get("nonce"),
                                       "scan")
            if err:
                return self._json({"error": err}, 401)
            job_id, total, err = self.state.submit(
                urls, data.get("level", "banner"),
                self._client_ip(), force=bool(data.get("force", False))
            )
            if err:
                status = 429 if "rate limit" in err else (
                    422 if "urls" in err or "level" in err else 503)
                return self._json({"error": err}, status)
            return self._json({
                "job_id": job_id,
                "total": total,
                "queue_depth": self.state.q.qsize(),
            })
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            self._json({"error": "internal: %s" % e}, 500)

    def _update_releases(self, data):
        """POST /api/releases - replace the shared patched-release list.

        Token-gated with hmac.compare_digest (constant time). The public UI
        deliberately has no admin form: operators update this with curl."""
        token = self.state.cfg.get("admin_token")
        if not token:
            return self._json({"error": "admin token not configured"}, 403)
        got = data.get("token")
        if not isinstance(got, str) or not hmac.compare_digest(got, token):
            return self._json({"error": "invalid token"}, 403)
        releases, err = _validate_releases(data.get("patched_releases"))
        if err:
            return self._json({"error": err}, 422)
        err = self.state.set_releases(releases)
        if err:
            return self._json({"error": err}, 500)
        return self._json({"ok": True, "patched_releases": releases})


class FleetHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, state):
        ThreadingHTTPServer.__init__(self, addr, Handler)
        self.state = state


def main(argv=None):
    ap = argparse.ArgumentParser(description="php2shell fleet-check service")
    ap.add_argument("--host", default=DEFAULTS["host"])
    ap.add_argument("--port", type=int, default=DEFAULTS["port"])
    ap.add_argument("--workers", type=int, default=DEFAULTS["workers"],
                    help="outbound concurrency cap (default 8)")
    ap.add_argument("--rate", type=int, default=DEFAULTS["rate_per_minute"],
                    help="job submissions per client IP per minute")
    ap.add_argument("--cache-ttl", type=float, default=DEFAULTS["cache_ttl"])
    ap.add_argument("--db", default=None,
                    help="SQLite results DB path (default: fleet-check.db next to "
                         "server.py; 'none' disables persistence)")
    ap.add_argument("--retain-hours", type=float, default=DEFAULTS["retain_hours"],
                    help="how long stored results are kept (default 168h = 7 days)")
    ap.add_argument("--allowlist", default=None,
                    help="file with allowed host suffixes, one per line")
    ap.add_argument("--allow-private", action="store_true",
                    help="permit private/loopback targets (labs/tests only)")
    ap.add_argument("--insecure-tls", action="store_true",
                    help="do not verify target certificates (internal fleets)")
    ap.add_argument("--trust-proxy", action="store_true",
                    help="trust X-Forwarded-For from loopback peers (behind nginx)")
    ap.add_argument("--max-urls", type=int, default=DEFAULTS["max_urls_per_job"],
                    help="URLs accepted per job (default 1: one URL at a time)")
    ap.add_argument("--admin-token", default=None,
                    help="token for POST /api/releases (default: env PHP2SHELL_ADMIN_TOKEN)")
    ap.add_argument("--pow-scan-bits", type=int, default=DEFAULTS["pow_scan_bits"],
                    help="PoW difficulty for job submission (0 disables, default 18)")
    ap.add_argument("--pow-poll-bits", type=int, default=DEFAULTS["pow_poll_bits"],
                    help="PoW difficulty for status polls (0 disables, default 12)")
    ap.add_argument("--memcached", default=None, metavar="ADDR|none",
                    help="localhost memcached for the queue metrics bus "
                         "(default 127.0.0.1:11211, env PHP2SHELL_MEMCACHED, "
                         "'none' disables - service falls back to local computation)")
    ap.add_argument("--og-cache-dir", default=None, metavar="DIR|none",
                    help="directory for rendered OG card PNGs on disk "
                         "(default: og-cache/ next to the DB file; 'none' disables)")
    args = ap.parse_args(argv)

    cfg = dict(DEFAULTS)
    cfg.update(host=args.host, port=args.port, workers=args.workers,
               rate_per_minute=args.rate, cache_ttl=args.cache_ttl,
               allowlist_file=args.allowlist, allow_private=args.allow_private,
               verify_tls=not args.insecure_tls, retain_hours=args.retain_hours,
               trust_proxy=args.trust_proxy, max_urls_per_job=args.max_urls,
               pow_scan_bits=args.pow_scan_bits, pow_poll_bits=args.pow_poll_bits,
               admin_token=args.admin_token or os.environ.get("PHP2SHELL_ADMIN_TOKEN"))
    mc = args.memcached or os.environ.get("PHP2SHELL_MEMCACHED") \
        or DEFAULTS["memcached"]
    cfg["memcached"] = None if mc.strip().lower() == "none" else mc.strip()
    ogd = args.og_cache_dir
    cfg["og_cache_dir"] = None if (ogd is None or ogd.strip().lower() == "none") \
        else ogd
    db = args.db
    if db is None:
        db = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "fleet-check.db")
    if not db.strip() or db.strip().lower() == "none":
        db = None
    cfg["db_path"] = db

    state = ServiceState(cfg)
    state.start_workers()
    httpd = FleetHTTPServer((cfg["host"], cfg["port"]), state)
    print("php2shell fleet-check %s  ->  http://%s:%d/  (workers=%d, rate=%d/min)"
          % (VERSION, cfg["host"], cfg["port"], cfg["workers"], cfg["rate_per_minute"]),
          flush=True)
    print("results store: %s" % (cfg["db_path"] or "disabled (memory cache only)"),
          flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        state.shutdown()
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
