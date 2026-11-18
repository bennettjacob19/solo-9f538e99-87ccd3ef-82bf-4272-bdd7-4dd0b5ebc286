"""Shared configuration and the SQLite state plane.

Three processes (web console / resolver / authoritative endpoint) share one
SQLite database in WAL mode:

  control   -- desired behaviour of the authoritative endpoint, written by the
               web console, read by the authoritative endpoint per query.
  cache     -- the resolver's cache.  Absolute epoch deadlines are stored, so a
               resolver restart can never extend the validity of an old A
               record; the stale window simply keeps counting down.
  dns64     -- the DNS64 /96 synthesis prefix, committed by the web console.
               The row survives restarts; only a committed update replaces it.
  query_log -- every client query the resolver answered, with its source.
  auth_log  -- every query the authoritative endpoint saw, with the action it
               took (answered / nxdomain / dropped / delayed).
"""
from __future__ import annotations

import fcntl
import ipaddress
import os
import sqlite3
import threading
import time
from contextlib import contextmanager

# --------------------------------------------------------------------------
# Configuration (environment overridable; defaults are the spec values).
# --------------------------------------------------------------------------
FIXED_DOMAIN = os.environ.get("FIXED_DOMAIN", "service.example").strip().rstrip(".")
FQDN = FIXED_DOMAIN + "."

DB_PATH = os.environ.get("DB_PATH", "/data/app.db")

FRESH_TTL = float(os.environ.get("FRESH_TTL", "5"))        # successful answers are fresh for 5s
STALE_WINDOW = float(os.environ.get("STALE_WINDOW", "20"))  # stale A usable <=20s after expiry
UPSTREAM_TIMEOUT = float(os.environ.get("UPSTREAM_TIMEOUT", "2.0"))

AUTH_HOST = os.environ.get("AUTH_HOST", "127.0.0.1")
AUTH_PORT = int(os.environ.get("AUTH_PORT", "5354"))
RESOLVER_HOST = os.environ.get("RESOLVER_HOST", "127.0.0.1")
RESOLVER_PORT = int(os.environ.get("RESOLVER_PORT", "5353"))
WEB_PORT = int(os.environ.get("WEB_PORT", "8000"))

DEFAULT_IP = os.environ.get("DEFAULT_IP", "192.0.2.10")
DEFAULT_DELAY = float(os.environ.get("DEFAULT_DELAY", "3.0"))

# DNS64: IPv6-only clients reach IPv4-only services through a /96 prefix.
DNS64_WELL_KNOWN_PREFIX = "64:ff9b::/96"
DNS64_PREFIX = os.environ.get("DNS64_PREFIX", DNS64_WELL_KNOWN_PREFIX)

SCHEMA = """
CREATE TABLE IF NOT EXISTS control (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  mode TEXT NOT NULL,              -- a | nxdomain | delay | timeout
  ip TEXT NOT NULL,
  delay_seconds REAL NOT NULL,
  updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS cache (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  qname TEXT NOT NULL,
  rcode TEXT NOT NULL,             -- NOERROR | NXDOMAIN
  a_record TEXT,                   -- NULL once NXDOMAIN is confirmed (old A purged)
  fetched_at REAL NOT NULL,        -- last successful upstream answer (epoch)
  fresh_until REAL NOT NULL,       -- serve-fresh deadline (epoch)
  stale_until REAL,                -- A only: last moment a stale A may be served
  nx_confirmed_at REAL
);
CREATE TABLE IF NOT EXISTS query_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  qname TEXT, qtype TEXT, source TEXT, rcode TEXT, answers TEXT, detail TEXT
);
CREATE TABLE IF NOT EXISTS auth_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  qname TEXT, qtype TEXT, mode TEXT, action TEXT, detail TEXT
);
CREATE TABLE IF NOT EXISTS dns64 (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  prefix TEXT NOT NULL,            -- committed /96 synthesis prefix
  updated_at REAL NOT NULL
);
"""

_LOG_TABLES = ("query_log", "auth_log")

# Serialises "check the committed DNS64 prefix" + "build the answer" in the
# resolver against "commit a new prefix" in the web process.  flock is per open
# file description, so it works across processes as well as threads; it is
# released automatically if a process dies.  The lock file lives next to the
# database so every role sees the same one.
_DNS64_LOCK_PATH = DB_PATH + ".dns64.lock"
_dns64_lock_thread = threading.Lock()


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=15000")
    return conn


def init_db() -> None:
    directory = os.path.dirname(DB_PATH)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with _connect() as c:
        c.executescript(SCHEMA)
        c.execute(
            "INSERT OR IGNORE INTO control(id, mode, ip, delay_seconds, updated_at)"
            " VALUES (1, 'a', ?, ?, ?)",
            (DEFAULT_IP, DEFAULT_DELAY, time.time()),
        )
        # Seed the DNS64 prefix once; later starts keep whatever was committed.
        try:
            prefix = _parse_dns64_prefix(DNS64_PREFIX)
        except ValueError:
            prefix = _parse_dns64_prefix(DNS64_WELL_KNOWN_PREFIX)
        c.execute(
            "INSERT OR IGNORE INTO dns64(id, prefix, updated_at) VALUES (1, ?, ?)",
            (str(prefix), time.time()),
        )


# --------------------------------------------------------------------------
# DNS64 prefix (+ the lock that makes prefix updates linearisable)
# --------------------------------------------------------------------------
def _parse_dns64_prefix(value: str) -> ipaddress.IPv6Network:
    """Accept only a canonical /96 IPv6 network."""
    net = ipaddress.ip_network(str(value).strip(), strict=True)
    if net.version != 6:
        raise ValueError("DNS64 prefix must be an IPv6 network")
    if net.prefixlen != 96:
        raise ValueError("DNS64 prefix must be a /96")
    return net


@contextmanager
def dns64_lock():
    """Hold the cross-process DNS64 lock.

    The resolver takes it around "read the committed prefix + build the AAAA
    answer"; the web console takes it around "validate + write the prefix".
    That ordering guarantees an AAAA answer built after a successful update
    can never contain the previous prefix, even for a query that started
    before the update: either it read the old prefix and finished before the
    writer committed, or it reads after the commit.
    """
    with _dns64_lock_thread:
        directory = os.path.dirname(_DNS64_LOCK_PATH)
        if directory:
            os.makedirs(directory, exist_ok=True)
        fd = os.open(_DNS64_LOCK_PATH, os.O_CREAT | os.O_RDWR, 0o644)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)


def get_dns64_prefix() -> ipaddress.IPv6Network:
    """The committed prefix, or the configured default if nothing is stored."""
    with _connect() as c:
        row = c.execute("SELECT prefix FROM dns64 WHERE id = 1").fetchone()
    if row:
        try:
            return _parse_dns64_prefix(row["prefix"])
        except ValueError:
            pass
    return _parse_dns64_prefix(DNS64_PREFIX)


def set_dns64_prefix(value: str) -> ipaddress.IPv6Network:
    """Validate then commit a new prefix.  Raises ValueError (and leaves the
    stored prefix untouched) for anything that is not a /96 IPv6 network."""
    prefix = _parse_dns64_prefix(value)
    with dns64_lock():
        with _connect() as c:
            c.execute(
                "INSERT INTO dns64(id, prefix, updated_at) VALUES (1, ?, ?)"
                " ON CONFLICT(id) DO UPDATE SET prefix = excluded.prefix,"
                " updated_at = excluded.updated_at",
                (str(prefix), time.time()),
            )
    return prefix


def synthesise_aaaa(prefix: ipaddress.IPv6Network, ipv4: str) -> str:
    """Embed an IPv4 address in the low 32 bits of the /96 prefix."""
    net = ipaddress.ip_network(prefix, strict=False)
    packed = net.network_address.packed[:12] + ipaddress.IPv4Address(ipv4).packed
    return str(ipaddress.IPv6Address(packed))


# --------------------------------------------------------------------------
# control table (web writes, authoritative endpoint reads)
# --------------------------------------------------------------------------
def get_control() -> dict | None:
    with _connect() as c:
        row = c.execute("SELECT * FROM control WHERE id = 1").fetchone()
        return dict(row) if row else None


def set_control(mode: str, ip: str, delay_seconds: float) -> None:
    with _connect() as c:
        c.execute(
            "UPDATE control SET mode = ?, ip = ?, delay_seconds = ?, updated_at = ?"
            " WHERE id = 1",
            (mode, ip, float(delay_seconds), time.time()),
        )


# --------------------------------------------------------------------------
# cache table (resolver only)
# --------------------------------------------------------------------------
def get_cache() -> dict | None:
    with _connect() as c:
        row = c.execute("SELECT * FROM cache WHERE id = 1").fetchone()
        return dict(row) if row else None


def put_cache_a(ip: str, now: float) -> None:
    """Store a freshly fetched A record: fresh for FRESH_TTL, then stale-usable
    for STALE_WINDOW more seconds.  Absolute epochs are persisted, so a restart
    does not extend either deadline."""
    with _connect() as c:
        c.execute(
            "INSERT INTO cache(id, qname, rcode, a_record, fetched_at, fresh_until,"
            "                 stale_until, nx_confirmed_at)"
            " VALUES (1, ?, 'NOERROR', ?, ?, ?, ?, NULL)"
            " ON CONFLICT(id) DO UPDATE SET"
            "   qname = excluded.qname, rcode = 'NOERROR',"
            "   a_record = excluded.a_record, fetched_at = excluded.fetched_at,"
            "   fresh_until = excluded.fresh_until, stale_until = excluded.stale_until,"
            "   nx_confirmed_at = NULL",
            (FQDN, ip, now, now + FRESH_TTL, now + FRESH_TTL + STALE_WINDOW),
        )


def put_cache_nxdomain(now: float) -> None:
    """Confirm NXDOMAIN.  Any old A record is purged immediately and durably:
    from this moment no answer may contain the old A again, and NXDOMAIN itself
    is only cached fresh (never used as stale backup)."""
    with _connect() as c:
        c.execute(
            "INSERT INTO cache(id, qname, rcode, a_record, fetched_at, fresh_until,"
            "                 stale_until, nx_confirmed_at)"
            " VALUES (1, ?, 'NXDOMAIN', NULL, ?, ?, NULL, ?)"
            " ON CONFLICT(id) DO UPDATE SET"
            "   qname = excluded.qname, rcode = 'NXDOMAIN', a_record = NULL,"
            "   fetched_at = excluded.fetched_at, fresh_until = excluded.fresh_until,"
            "   stale_until = NULL, nx_confirmed_at = excluded.nx_confirmed_at",
            (FQDN, now, now + FRESH_TTL, now),
        )


# --------------------------------------------------------------------------
# logs
# --------------------------------------------------------------------------
def _log(table: str, columns: tuple[str, ...], values: tuple) -> None:
    assert table in _LOG_TABLES
    cols = ", ".join(columns)
    marks = ", ".join("?" for _ in columns)
    with _connect() as c:
        c.execute(f"INSERT INTO {table}({cols}) VALUES ({marks})", values)
        c.execute(
            f"DELETE FROM {table} WHERE id NOT IN"
            f" (SELECT id FROM {table} ORDER BY id DESC LIMIT 300)"
        )


def log_query(qname, qtype, source, rcode, answers, detail) -> None:
    _log(
        "query_log",
        ("ts", "qname", "qtype", "source", "rcode", "answers", "detail"),
        (time.time(), qname, qtype, source, rcode, answers, detail),
    )


def log_auth(qname, qtype, mode, action, detail) -> None:
    _log(
        "auth_log",
        ("ts", "qname", "qtype", "mode", "action", "detail"),
        (time.time(), qname, qtype, mode, action, detail),
    )


def recent(table: str, limit: int = 15) -> list[dict]:
    assert table in _LOG_TABLES
    with _connect() as c:
        rows = c.execute(
            f"SELECT * FROM {table} ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]
