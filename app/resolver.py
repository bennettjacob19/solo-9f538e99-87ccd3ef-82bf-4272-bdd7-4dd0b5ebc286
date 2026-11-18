"""Caching UDP DNS resolver for one fixed internal domain.

Behaviour (all timings from app.common, defaults are the spec values):

  * a successful A answer is cached fresh for FRESH_TTL (5s) and served from
    cache with the remaining TTL;
  * after expiry the resolver re-fetches.  If the upstream times out (or its
    reply is unusable) the old A record may be served stale for at most
    STALE_WINDOW (20s) past expiry; beyond that the answer is SERVFAIL;
  * NXDOMAIN is cached fresh only -- it is never used as stale backup;
  * confirming NXDOMAIN purges the old A record durably (SQLite), so no later
    answer contains the old A again;
  * every upstream attempt uses a dedicated socket with a random transaction
    ID and matches the question section, so a late answer to an already
    timed-out query is never read and can never resurrect the old A;
  * cache deadlines are absolute epochs persisted in SQLite, so a restart does
    not extend the validity of an old A record;
  * DNS64: an AAAA query reuses exactly the A cache/upstream/stale path above
    and embeds the IPv4 address in the low 32 bits of the committed /96 prefix
    (no separate AAAA cache and no upstream AAAA traffic).  The synthesized
    TTL never exceeds the remaining validity of the A record it came from, so
    a stale A is synthesized only inside its original 20s window.  The prefix
    is read and the packet sent under a cross-process lock shared with the web
    console, so an AAAA answer emitted after a successful prefix update can
    never carry the superseded prefix.

The resolver reports where each answer came from in an additional-section TXT
record (_src.<domain> TXT "source=upstream|cache-fresh|cache-stale|none ...")
and logs every query to the query_log table for the web console.
"""
from __future__ import annotations

import random
import socket
import threading
import time
import traceback

from dnslib import A, AAAA, CLASS, QTYPE, RCODE, RR, TXT, DNSHeader, DNSRecord

from . import common


def _same_name(a, b) -> bool:
    return str(a).rstrip(".").lower() == str(b).rstrip(".").lower()


def upstream_query() -> DNSRecord | None:
    """One-shot upstream A query for the fixed domain.

    A dedicated UDP socket per attempt plus a random transaction ID means a
    late answer to an earlier, already timed-out query can never be read back
    (the socket is closed) and can never be mistaken for the answer to a later
    query (ID + question must match).
    """
    query = DNSRecord.question(common.FQDN, "A")
    query.header.id = random.randint(0, 0xFFFF)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(query.pack(), (common.AUTH_HOST, common.AUTH_PORT))
        deadline = time.monotonic() + common.UPSTREAM_TIMEOUT
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            sock.settimeout(remaining)
            try:
                data, _addr = sock.recvfrom(4096)
            except socket.timeout:
                return None
            try:
                resp = DNSRecord.parse(data)
            except Exception:
                continue  # unparsable stray datagram: keep waiting
            if resp.header.id != query.header.id:
                continue  # stray/late packet for someone else: ignore
            if not _same_name(resp.q.qname, query.q.qname):
                continue
            return resp
    except OSError:
        return None
    finally:
        sock.close()


def _a_rr(ip: str, ttl: int) -> RR:
    return RR(common.FQDN, QTYPE.A, CLASS.IN, ttl, A(ip))


def _aaaa_rr(ip: str, ttl: int) -> RR:
    return RR(common.FQDN, QTYPE.AAAA, CLASS.IN, ttl, AAAA(ip))


def _reply(query: DNSRecord, rcode: int, answers=(), source="none", detail="") -> DNSRecord:
    rep = DNSRecord(
        DNSHeader(
            id=query.header.id, qr=1, aa=0, ra=1, rd=query.header.rd, rcode=rcode
        ),
        q=query.q,
    )
    for rr in answers:
        rep.add_answer(rr)
    meta = f"source={source}" + (f" {detail}" if detail else "")
    rep.add_ar(RR(f"_src.{common.FQDN}", QTYPE.TXT, CLASS.IN, 0, TXT(meta)))
    return rep


def lookup_a() -> dict:
    """Resolve the fixed domain's A record through the cache/upstream/stale path.

    Returns an outcome dict shared by the A and the DNS64 AAAA paths:
      status      -- NOERROR (with ip + ttl), NXDOMAIN or SERVFAIL
      ttl         -- the A-style TTL (what an A answer would carry)
      valid_until -- epoch until which the A record may be used at all
                     (fresh_until / stale_until); None for negatives
      source      -- upstream | cache-fresh | cache-stale | none
      detail      -- human-readable explanation for logs / the console
    """
    now = time.time()
    row = common.get_cache()

    # 1) fresh cache hits
    if row and row["rcode"] == "NOERROR" and row["a_record"] and now < row["fresh_until"]:
        return {
            "status": "NOERROR",
            "ip": row["a_record"],
            "ttl": max(1, int(row["fresh_until"] - now + 0.999)),
            "valid_until": row["fresh_until"],
            "source": "cache-fresh",
            "detail": f"fresh A from cache fresh_left={row['fresh_until'] - now:.1f}",
        }
    if row and row["rcode"] == "NXDOMAIN" and now < row["fresh_until"]:
        return {
            "status": "NXDOMAIN",
            "ip": None,
            "ttl": 0,
            "valid_until": None,
            "source": "cache-fresh",
            "detail": f"fresh NXDOMAIN from cache fresh_left={row['fresh_until'] - now:.1f}",
        }

    # 2) expired: ask the authoritative endpoint
    resp = upstream_query()
    now2 = time.time()

    if resp is not None and resp.header.rcode == RCODE.NOERROR:
        ips = [str(rr.rdata) for rr in resp.rr if rr.rtype == QTYPE.A]
        if ips:
            common.put_cache_a(ips[0], now2)
            # A freshly fetched record is valid for FRESH_TTL from the fetch.
            return {
                "status": "NOERROR",
                "ip": ips[0],
                "ttl": int(common.FRESH_TTL),
                "valid_until": now2 + common.FRESH_TTL,
                "source": "upstream",
                "detail": f"fetched A={ips[0]}",
            }

    if resp is not None and resp.header.rcode == RCODE.NXDOMAIN:
        # Confirming NXDOMAIN purges the old A record (durably, in SQLite).
        common.put_cache_nxdomain(now2)
        return {
            "status": "NXDOMAIN",
            "ip": None,
            "ttl": 0,
            "valid_until": None,
            "source": "upstream",
            "detail": "NXDOMAIN confirmed; old A purged",
        }

    # 3) upstream timeout / unusable reply: maybe serve the stale A record
    #    (NXDOMAIN is never served stale).
    row = common.get_cache()
    if (
        row
        and row["rcode"] == "NOERROR"
        and row["a_record"]
        and row["stale_until"]
        and now2 < row["stale_until"]
    ):
        return {
            "status": "NOERROR",
            "ip": row["a_record"],
            "ttl": max(1, int(row["stale_until"] - now2 + 0.999)),
            "valid_until": row["stale_until"],
            "source": "cache-stale",
            "detail": f"upstream timeout; serving stale A stale_left={row['stale_until'] - now2:.1f}",
        }

    return {
        "status": "SERVFAIL",
        "ip": None,
        "ttl": 0,
        "valid_until": None,
        "source": "none",
        "detail": "upstream timeout; no usable cache",
    }


_RCODE = {"NOERROR": RCODE.NOERROR, "NXDOMAIN": RCODE.NXDOMAIN, "SERVFAIL": RCODE.SERVFAIL}


def resolve_a(query: DNSRecord) -> tuple[DNSRecord, str, str]:
    """Resolve the fixed domain's A record.  Returns (reply, source, detail)."""
    outcome = lookup_a()
    answers = [_a_rr(outcome["ip"], outcome["ttl"])] if outcome["status"] == "NOERROR" else []
    return (
        _reply(query, _RCODE[outcome["status"]], answers,
               outcome["source"], outcome["detail"]),
        outcome["source"],
        outcome["detail"],
    )


def resolve_aaaa(query: DNSRecord, sock: socket.socket, addr) -> tuple[DNSRecord, str, str]:
    """Resolve AAAA by DNS64: reuse the A path, embed the IPv4 address in the
    committed /96 prefix, then send the reply while still holding the DNS64
    lock so it can never carry a prefix that has already been superseded.

    Also sends non-synthesized negative/SERVFAIL replies itself so the caller
    has one uniform flow; returns (reply, source, detail) for logging.
    """
    outcome = lookup_a()
    source, detail = outcome["source"], outcome["detail"]
    if outcome["status"] != "NOERROR":
        # Fresh NXDOMAIN is returned verbatim; a failed refresh with no usable
        # A becomes SERVFAIL.  Neither is a synthesis and neither uses a prefix.
        rep = _reply(query, _RCODE[outcome["status"]], [], source, detail)
        sock.sendto(rep.pack(), addr)
        return rep, source, detail

    with common.dns64_lock():
        prefix = common.get_dns64_prefix()
        aaaa = common.synthesise_aaaa(prefix, outcome["ip"])
        # The A record is usable until valid_until; never outlive it, and never
        # exceed the TTL the A answer itself would carry.
        now = time.time()
        if outcome["valid_until"] is not None:
            ttl = min(outcome["ttl"], max(0, int(outcome["valid_until"] - now)))
        else:
            ttl = outcome["ttl"]
        rep = _reply(
            query, RCODE.NOERROR, [_aaaa_rr(aaaa, ttl)], source,
            f"{detail} dns64={prefix} a={outcome['ip']} ttl_left={ttl}",
        )
        sock.sendto(rep.pack(), addr)
    return rep, source, detail


def handle_packet(data: bytes, addr, sock: socket.socket) -> None:
    qname = qtype = "?"
    try:
        query = DNSRecord.parse(data)
        qname = str(query.q.qname)
        qtype = QTYPE[query.q.qtype]
        if not _same_name(query.q.qname, common.FQDN):
            rep = _reply(query, RCODE.REFUSED, [], "none", "out-of-scope")
            source, detail = "none", "out-of-scope"
            sock.sendto(rep.pack(), addr)
        elif query.q.qtype == QTYPE.A:
            rep, source, detail = resolve_a(query)
            sock.sendto(rep.pack(), addr)
        elif query.q.qtype == QTYPE.AAAA:
            # Sends the packet itself, inside the DNS64 lock.
            rep, source, detail = resolve_aaaa(query, sock, addr)
        else:
            rep = _reply(query, RCODE.NOERROR, [], "none", "nodata")
            source, detail = "none", "nodata"
            sock.sendto(rep.pack(), addr)
        answers = ";".join(
            f"{QTYPE[rr.rtype]}={rr.rdata}(ttl={rr.ttl})" for rr in rep.rr
        ) or "-"
        common.log_query(qname, qtype, source, RCODE[rep.header.rcode], answers, detail)
    except Exception:
        common.log_query(qname, qtype, "error", "SERVFAIL", "-",
                         traceback.format_exc(limit=3))


def main() -> None:
    common.init_db()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", common.RESOLVER_PORT))
    print(
        f"[resolver] {common.FQDN} on udp/{common.RESOLVER_PORT}, "
        f"upstream {common.AUTH_HOST}:{common.AUTH_PORT}, "
        f"fresh={common.FRESH_TTL}s stale={common.STALE_WINDOW}s "
        f"timeout={common.UPSTREAM_TIMEOUT}s dns64={common.get_dns64_prefix()}",
        flush=True,
    )
    while True:
        data, addr = sock.recvfrom(4096)
        threading.Thread(target=handle_packet, args=(data, addr, sock),
                         daemon=True).start()


if __name__ == "__main__":
    main()
