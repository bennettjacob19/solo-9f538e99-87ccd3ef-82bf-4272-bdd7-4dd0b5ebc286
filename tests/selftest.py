#!/usr/bin/env python3
"""End-to-end self-test for the serve-stale DNS duty system.

Spawns auth + resolver + web on loopback with the production timing
parameters (fresh TTL 5s, stale window 20s, upstream timeout 2s) and drives
the key interleavings:

  A. basic fetch / fresh-cache hit / TTL countdown / refresh after expiry
  B. upstream timeout after expiry -> stale A (<=20s) -> SERVFAIL beyond
  C. confirmed NXDOMAIN purges the old A; NXDOMAIN is never served stale
  D. a late (delayed) old answer cannot resurrect anything
  E. resolver restart does not extend the old A's validity
  F. web console smoke test (page, mode switch, query, state)
  G. DNS64: AAAA synthesis from the A cache, TTL bounded by A validity, prefix
     update atomicity/validation/persistence, NXDOMAIN and SERVFAIL passthrough

Exits non-zero if any check fails.  Runtime: ~95s.
"""
from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from dnslib import QTYPE, DNSRecord  # noqa: E402

DOMAIN = "service.example"
AUTH_PORT, RES_PORT, WEB_PORT = 15354, 15353, 18000
TMP = tempfile.mkdtemp(prefix="dns-selftest-")
DB = os.path.join(TMP, "app.db")

env = dict(os.environ)
env.update(
    DB_PATH=DB,
    FIXED_DOMAIN=DOMAIN,
    AUTH_HOST="127.0.0.1",
    AUTH_PORT=str(AUTH_PORT),
    RESOLVER_HOST="127.0.0.1",
    RESOLVER_PORT=str(RES_PORT),
    WEB_PORT=str(WEB_PORT),
    FRESH_TTL="5",
    STALE_WINDOW="20",
    UPSTREAM_TIMEOUT="2",
    DEFAULT_IP="192.0.2.10",
    DEFAULT_DELAY="3",
    PYTHONPATH=ROOT,
    PYTHONUNBUFFERED="1",
)

procs: dict[str, subprocess.Popen] = {}
FAILS: list[str] = []


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def start(name: str, module: str) -> None:
    log = open(os.path.join(TMP, f"{name}.log"), "ab")
    procs[name] = subprocess.Popen(
        [sys.executable, "-m", module],
        cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT,
    )


def stop(name: str) -> None:
    p = procs.get(name)
    if p and p.poll() is None:
        p.terminate()
        try:
            p.wait(5)
        except subprocess.TimeoutExpired:
            p.kill()


def set_mode(mode: str, ip: str = "192.0.2.10", delay: float = 3.0) -> None:
    conn = sqlite3.connect(DB, timeout=15)
    conn.execute("PRAGMA busy_timeout=15000")
    conn.execute(
        "INSERT INTO control(id, mode, ip, delay_seconds, updated_at)"
        " VALUES (1, ?, ?, ?, ?)"
        " ON CONFLICT(id) DO UPDATE SET mode=excluded.mode, ip=excluded.ip,"
        " delay_seconds=excluded.delay_seconds, updated_at=excluded.updated_at",
        (mode, ip, delay, time.time()),
    )
    conn.commit()
    conn.close()


def get_cache() -> dict | None:
    conn = sqlite3.connect(DB, timeout=15)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM cache WHERE id = 1").fetchone()
    conn.close()
    return dict(row) if row else None


def auth_actions() -> list[tuple]:
    conn = sqlite3.connect(DB, timeout=15)
    rows = conn.execute(
        "SELECT mode, action, detail FROM auth_log ORDER BY id"
    ).fetchall()
    conn.close()
    return rows


def clear_cache() -> None:
    conn = sqlite3.connect(DB, timeout=15)
    conn.execute("PRAGMA busy_timeout=15000")
    conn.execute("DELETE FROM cache WHERE id = 1")
    conn.commit()
    conn.close()


def dns_query(qtype: str = "A") -> tuple[int, list[tuple], str | None]:
    """Returns (rcode, [(type, data, ttl)], source)."""
    q = DNSRecord.question(DOMAIN, qtype)
    data = q.send("127.0.0.1", RES_PORT, timeout=8)
    rep = DNSRecord.parse(data)
    answers = [(QTYPE[rr.rtype], str(rr.rdata), rr.ttl) for rr in rep.rr]
    src = None
    for rr in rep.ar:
        if rr.rtype == QTYPE.TXT:
            txt = str(rr.rdata).strip('"')
            if txt.startswith("source="):
                src = txt.split("=", 1)[1].split()[0]
    return rep.header.rcode, answers, src


def synthesise(prefix: str, ipv4: str) -> str:
    import ipaddress

    net = ipaddress.ip_network(prefix, strict=False)
    return str(ipaddress.IPv6Address(net.network_address.packed[:12]
                                     + ipaddress.IPv4Address(ipv4).packed))


def post_json(path: str, body: dict, timeout: float = 10) -> tuple[int, dict]:
    req = urllib.request.Request(
        f"http://127.0.0.1:{WEB_PORT}{path}", data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def check(name: str, cond: bool, info: str = "") -> None:
    print(f"  [{'PASS' if cond else 'FAIL'}] {name} {info}", flush=True)
    if not cond:
        FAILS.append(name)


def sleep_until(ts: float) -> None:
    time.sleep(max(0.0, ts - time.time()))


def wait_resolver_ready(timeout: float = 25) -> bool:
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            dns_query()
            return True
        except Exception:
            time.sleep(0.3)
    return False


def wait_web_ready(timeout: float = 25) -> bool:
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{WEB_PORT}/api/state", timeout=2
            ) as r:
                if r.status == 200:
                    return True
        except Exception:
            time.sleep(0.3)
    return False


# --------------------------------------------------------------------------
# scenario
# --------------------------------------------------------------------------
def main() -> int:
    print(f"[selftest] workdir={TMP}", flush=True)
    start("auth", "app.auth_server")
    start("resolver", "app.resolver")
    start("web", "app.web")
    try:
        if not (wait_resolver_ready() and wait_web_ready()):
            print("  [FAIL] services did not come up")
            return 1

        # -- A. basic fetch / fresh cache / refresh --------------------------
        print("A. 基本应答与新鲜缓存", flush=True)
        clear_cache()  # the readiness probe already populated the cache
        set_mode("a", "192.0.2.10")
        rc, ans, src = dns_query()
        check("A1 上游取回 A", rc == 0 and ans == [("A", "192.0.2.10", 5)]
              and src == "upstream", f"rcode={rc} ans={ans} src={src}")
        rc, ans, src = dns_query()
        check("A2 命中新鲜缓存", rc == 0 and src == "cache-fresh"
              and ans and ans[0][1] == "192.0.2.10" and 1 <= ans[0][2] <= 5,
              f"ans={ans} src={src}")
        set_mode("a", "192.0.2.20")  # change the A record on the auth side
        rc, ans, src = dns_query()
        check("A3 缓存期内仍给旧 IP", rc == 0 and src == "cache-fresh"
              and ans and ans[0][1] == "192.0.2.10", f"ans={ans} src={src}")
        time.sleep(5.5)
        rc, ans, src = dns_query()
        check("A4 过期后重新取回新 IP", rc == 0 and src == "upstream"
              and ans == [("A", "192.0.2.20", 5)], f"ans={ans} src={src}")
        cache = get_cache()
        fresh_until, stale_until = cache["fresh_until"], cache["stale_until"]

        # -- B. stale on timeout, SERVFAIL beyond the window -----------------
        print("B. 过期+上游超时 -> 旧 A 沿用 <=20s -> SERVFAIL", flush=True)
        set_mode("timeout")
        sleep_until(fresh_until + 0.5)
        t0 = time.time()
        rc, ans, src = dns_query()
        check("B1 上游超时后给旧 A(stale)",
              rc == 0 and src == "cache-stale" and ans
              and ans[0][1] == "192.0.2.20"
              and stale_until - time.time() - 1 <= ans[0][2] <= 20,
              f"ans={ans} src={src} 耗时={time.time()-t0:.1f}s")
        sleep_until(stale_until - 4)
        rc, ans, src = dns_query()
        check("B2 窗口末尾仍是 stale", rc == 0 and src == "cache-stale",
              f"ans={ans} src={src}")
        sleep_until(stale_until + 1)
        rc, ans, src = dns_query()
        check("B3 超过 20s 返回 SERVFAIL", rc == 2 and not ans and src == "none",
              f"rcode={rc} ans={ans} src={src}")

        # -- C. NXDOMAIN purges old A; NXDOMAIN never served stale -----------
        print("C. 确认 NXDOMAIN 清除旧 A；NXDOMAIN 不作过期备用", flush=True)
        set_mode("a", "192.0.2.30")
        rc, ans, src = dns_query()
        assert rc == 0 and src == "upstream", f"setup failed: {rc} {src}"
        set_mode("nxdomain")
        time.sleep(5.5)  # let the fresh A expire
        rc, ans, src = dns_query()
        check("C1 上游确认 NXDOMAIN", rc == 3 and not ans and src == "upstream",
              f"rcode={rc} ans={ans} src={src}")
        cache = get_cache()
        check("C2 旧 A 已被持久清除",
              cache["rcode"] == "NXDOMAIN" and cache["a_record"] is None
              and cache["stale_until"] is None,
              f"cache={cache}")
        set_mode("timeout")
        time.sleep(5.5)  # let the fresh NXDOMAIN expire
        rc, ans, src = dns_query()
        check("C3 NXDOMAIN 不作 stale 备用 -> SERVFAIL",
              rc == 2 and not ans and src == "none",
              f"rcode={rc} ans={ans} src={src}")

        # -- D. late old answer cannot resurrect -----------------------------
        print("D. 超时后迟到的旧答复不能复活记录", flush=True)
        set_mode("a", "192.0.2.40")
        rc, ans, src = dns_query()
        assert rc == 0 and src == "upstream", f"setup failed: {rc} {src}"
        set_mode("delay", "192.0.2.40", 3.0)  # 3s delay > 2s upstream timeout
        time.sleep(5.5)  # fresh A expires
        t0 = time.time()
        rc, ans, src = dns_query()  # upstream times out at 2s; delayed A lands ~1s later
        check("D1 延迟模式下先按超时处理 -> stale",
              rc == 0 and src == "cache-stale" and 1.8 <= time.time() - t0 <= 4,
              f"ans={ans} src={src} 耗时={time.time()-t0:.1f}s")
        time.sleep(1.5)  # the delayed A has now arrived at a closed socket
        set_mode("nxdomain")
        rc, ans, src = dns_query()
        check("D2 随后确认 NXDOMAIN", rc == 3 and src == "upstream",
              f"rcode={rc} src={src}")
        set_mode("timeout")
        time.sleep(5.5)  # past NXDOMAIN freshness; delayed A long arrived
        rc, ans, src = dns_query()
        check("D3 迟到旧 A 未复活任何记录 -> SERVFAIL",
              rc == 2 and not ans, f"rcode={rc} ans={ans} src={src}")
        cache = get_cache()
        check("D4 缓存中仍无 A 记录", cache["a_record"] is None,
              f"cache={cache}")
        delayed = [r for r in auth_actions() if r[0] == "delay" and r[1] == "answered"]
        check("D5 权威端确实发出过延迟应答（被解析器丢弃）", len(delayed) >= 1,
              f"delay 应答次数={len(delayed)}")

        # -- E. restart does not extend validity -----------------------------
        print("E. 重启不延长旧 A 有效期", flush=True)
        set_mode("a", "192.0.2.50")
        rc, ans, src = dns_query()
        assert rc == 0 and src == "upstream", f"setup failed: {rc} {src}"
        stale_until = get_cache()["stale_until"]
        time.sleep(4)
        stop("resolver")
        time.sleep(1)
        start("resolver", "app.resolver")  # restart with the same DB
        set_mode("timeout")
        assert wait_resolver_ready(), "resolver did not come back"
        sleep_until(stale_until - 4)
        rc, ans, src = dns_query()
        check("E1 重启后窗口内仍可用旧 A(绝对期限未变)",
              rc == 0 and src == "cache-stale" and ans
              and ans[0][1] == "192.0.2.50", f"ans={ans} src={src}")
        sleep_until(stale_until + 2)
        rc, ans, src = dns_query()
        check("E2 到达原绝对期限即 SERVFAIL（未被重启延长）",
              rc == 2 and not ans, f"rcode={rc} ans={ans} src={src}")

        # -- F. web console smoke test ---------------------------------------
        print("F. 网页控制台冒烟", flush=True)
        with urllib.request.urlopen(f"http://127.0.0.1:{WEB_PORT}/", timeout=5) as r:
            body = r.read().decode()
        check("F1 主页可访问", r.status == 200 and "DNS" in body)
        req = urllib.request.Request(
            f"http://127.0.0.1:{WEB_PORT}/api/mode",
            data=json.dumps({"mode": "a", "ip": "192.0.2.60"}).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=5) as r:
            ok = json.load(r)["ok"]
        check("F2 网页切换模式生效", ok and get_control_mode() == "a")
        req = urllib.request.Request(f"http://127.0.0.1:{WEB_PORT}/api/query",
                                     method="POST")
        with urllib.request.urlopen(req, timeout=15) as r:
            res = json.load(r)
        check("F3 网页发起查询并显示来源",
              res["ok"] and res["rcode"] == "NOERROR"
              and res["source"] in ("upstream", "cache-fresh")
              and res["answers"] and res["answers"][0]["data"] == "192.0.2.60",
              f"res={res.get('rcode')} src={res.get('source')}")
        with urllib.request.urlopen(
                f"http://127.0.0.1:{WEB_PORT}/api/state", timeout=5) as r:
            st = json.load(r)
        check("F4 状态接口含控制/缓存/日志",
              st["control"]["mode"] == "a" and st["cache"]
              and len(st["resolver_log"]) > 0 and len(st["auth_log"]) > 0)
        req = urllib.request.Request(
            f"http://127.0.0.1:{WEB_PORT}/api/mode",
            data=json.dumps({"mode": "bogus"}).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            urllib.request.urlopen(req, timeout=5)
            check("F5 非法模式被拒绝", False)
        except urllib.error.HTTPError as e:
            check("F5 非法模式被拒绝", e.code == 400)

        # -- G. DNS64 --------------------------------------------------------
        print("G. DNS64 AAAA 合成 / 前缀更新 / 校验 / 持久化", flush=True)
        P1, P2 = "64:ff9b::/96", "2001:db8:64::/96"
        status, res = post_json("/api/dns64", {"prefix": P1})
        check("G1 可设置 /96 前缀", status == 200 and res["ok"]
              and res["prefix"] == "64:ff9b::/96", f"res={res}")

        set_mode("a", "192.0.2.70")
        clear_cache()
        rc, ans, src = dns_query("AAAA")
        check("G2 AAAA 由 A 合成（回源）",
              rc == 0 and len(ans) == 1 and ans[0][0] == "AAAA"
              and ans[0][1] == synthesise(P1, "192.0.2.70")
              and 1 <= ans[0][2] <= 5 and src == "upstream", f"ans={ans} src={src}")
        cache = get_cache()
        check("G3 未单独缓存 AAAA（A 缓存仍是唯一来源）",
              cache["a_record"] == "192.0.2.70", f"cache={cache}")

        time.sleep(2)
        rc, ans, src = dns_query("AAAA")
        check("G4 命中 A 缓存时 TTL 为 A 的剩余有效时间",
              rc == 0 and src == "cache-fresh" and ans
              and ans[0][1] == synthesise(P1, "192.0.2.70")
              and 1 <= ans[0][2] < 5, f"ans={ans} src={src}")

        # stale A is synthesized only inside its original 20s window
        fresh_until, stale_until = cache["fresh_until"], cache["stale_until"]
        set_mode("timeout")
        sleep_until(fresh_until + 0.5)
        stale_left = get_cache()["stale_until"] - time.time()
        rc, ans, src = dns_query("AAAA")
        check("G5 过期+回源失败 -> 用旧 A 合成，TTL<=剩余 stale",
              rc == 0 and src == "cache-stale" and ans
              and ans[0][1] == synthesise(P1, "192.0.2.70")
              and ans[0][2] <= stale_left + 0.5
              and ans[0][2] <= 20, f"ans={ans} src={src} stale_left={stale_left:.1f}")
        sleep_until(stale_until + 1)
        rc, ans, src = dns_query("AAAA")
        check("G6 超过原 20s 窗口不再合成 -> SERVFAIL",
              rc == 2 and not ans and src == "none", f"rcode={rc} ans={ans}")

        # fresh NXDOMAIN is passed through verbatim
        set_mode("nxdomain")
        rc, ans, src = dns_query("AAAA")
        check("G7 新鲜 NXDOMAIN 原样返回",
              rc == 3 and not ans and src == "upstream", f"rcode={rc} ans={ans}")
        rc, ans, src = dns_query("AAAA")
        check("G8 命中新鲜 NXDOMAIN 缓存", rc == 3 and not ans and src == "cache-fresh",
              f"rcode={rc} src={src}")

        # prefix updates: invalid input and failed writes keep the old prefix
        status, res = post_json("/api/dns64", {"prefix": "not-a-prefix"})
        check("G9 非法前缀被拒绝且原设置保留",
              status == 400 and not res["ok"]
              and res["prefix"] == "64:ff9b::/96", f"res={res}")
        status, res = post_json("/api/dns64", {"prefix": "2001:db8::/64"})
        check("G10 非 /96 前缀被拒绝", status == 400 and not res["ok"]
              and res["prefix"] == "64:ff9b::/96", f"res={res}")

        set_mode("a", "192.0.2.80")
        clear_cache()
        rc, ans, src = dns_query("A")
        assert rc == 0 and src == "upstream", f"setup failed: {rc} {src}"

        status, res = post_json("/api/dns64", {"prefix": P2})
        check("G11 更新前缀成功", status == 200 and res["ok"]
              and res["prefix"] == "2001:db8:64::/96", f"res={res}")
        rc, ans, src = dns_query("AAAA")
        check("G12 更新后 AAAA 立即使用新前缀",
              rc == 0 and ans and ans[0][1] == synthesise(P2, "192.0.2.80")
              and ans[0][2] <= 5 and src == "cache-fresh",
              f"ans={ans} src={src}")

        # concurrent queries during an update: no AAAA built after a successful
        # update may carry the old prefix
        stop_flag = threading.Event()
        violations: list[str] = []
        accepted: list[tuple[float, str]] = []

        def hammer() -> None:
            while not stop_flag.is_set():
                try:
                    _rc, got, _src = dns_query("AAAA")
                except Exception:
                    continue
                if got:
                    accepted.append((time.time(), got[0][1]))

        threads = [threading.Thread(target=hammer, daemon=True) for _ in range(3)]
        for t in threads:
            t.start()
        time.sleep(0.4)
        t_commit = time.time()
        status, res = post_json("/api/dns64", {"prefix": P1})
        committed_at = time.time()
        time.sleep(0.6)
        stop_flag.set()
        for t in threads:
            t.join(5)
        old = synthesise(P2, "192.0.2.80")
        # Anything that came back after the commit was already acknowledged
        # must use the new prefix; allow only in-flight replies that returned
        # before the commit finished.
        for ts, aaaa in accepted:
            if aaaa == old and ts > committed_at + 0.2:
                violations.append(f"{aaaa} at +{ts - committed_at:.2f}s")
        check("G13 更新成功后无旧前缀 AAAA（含并发查询）",
              status == 200 and not violations and len(accepted) > 0,
              f"committed={res.get('prefix')} violations={violations[:3]} "
              f"old_seen={sum(1 for _, a in accepted if a == old)}/"
              f"{len(accepted)}")

        # persistence: committed prefix survives a resolver restart
        stop("resolver")
        time.sleep(1)
        start("resolver", "app.resolver")
        assert wait_resolver_ready(), "resolver did not come back"
        set_mode("a", "192.0.2.90")
        clear_cache()
        rc, ans, src = dns_query("AAAA")
        check("G14 重启后仍使用已提交前缀",
              rc == 0 and len(ans) == 1 and ans[0][1] == synthesise(P1, "192.0.2.90")
              and 1 <= ans[0][2] <= 5, f"ans={ans} src={src}")
        rc, ans, src = dns_query("A")
        check("G15 A 查询保持原规则", rc == 0 and ans and ans[0][0] == "A"
              and ans[0][1] == "192.0.2.90"
              and src in ("upstream", "cache-fresh"), f"ans={ans} src={src}")
    finally:
        for name in list(procs):
            stop(name)
        print(f"[selftest] logs in {TMP}", flush=True)

    print(f"\n{'=' * 60}\n结果: {len(FAILS)} 项失败" if FAILS
          else f"\n{'=' * 60}\n结果: 全部通过", flush=True)
    return 1 if FAILS else 0


def get_control_mode() -> str:
    conn = sqlite3.connect(DB, timeout=15)
    mode = conn.execute("SELECT mode FROM control WHERE id = 1").fetchone()[0]
    conn.close()
    return mode


if __name__ == "__main__":
    sys.exit(main())
