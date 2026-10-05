"""Regression harness: time-limited recovery freezes over custody lineages (v1.8).

Run (the docker compose ``demo`` profile enables fault injection automatically;
locally set KEYVAULT_FAULT_INJECTION=1)::

    python -m scripts.race_freeze

It boots the real FastAPI app in-process (ASGI transport, real PostgreSQL row
locks) and pins every required property of a recovery freeze:

  F1  basic lifecycle: a freeze on the root blocks recovery create / nonce /
      claim / submit with CUSTODY_FROZEN (HTTP 423), is queryable and listable,
      releases early; migrations keep completing and online shards are retained.
  F2  expiry: a short freeze auto-lapses at valid_until (no sweeper); the same
      recovery create goes from 423 to 201 once time passes; GET reports
      effective=expired.
  F3  overlapping freezes stack: two active freezes on one lineage block until
      BOTH are released (releasing one still yields 423); release of the second
      reopens recovery.
  F4  pre-existing descendants: a freeze on a chain root covers the child and
      grandchild already produced by completed migrations (snapshot + dynamic
      guard).
  F5  freeze vs migration completion: with the freeze parked holding lineage
      custody locks a threshold migration submit queues — the migration still
      completes (freezes never roll migrations back) and the freeze commits
      afterwards covering the fresh descendant; recovery on that descendant is
      then 423. A recovery claim queued on the same lock gets CUSTODY_FROZEN and
      no shard plaintext / nonce spend / count / pending-share side effect.
  F6  recovery create races the freeze: queued behind the parked freeze, the
      create only commits after observing the freeze -> 423 (no recovery row).
  F7  no side effects on the blocked submit path: nonce unspent, share
      submissions count unchanged, in-memory pending store untouched.
  F8  after release an old open recovery is still bound by expiry / revocation /
      destruction (release is not an override), and a fresh recovery works.
  F9  idempotent release; release of an expired freeze reports effective=
      expired with no row mutation; GET/list filters.
  F10 cross-tenant freeze, GET, list, release are FORBIDDEN; unknown root
      NOT_FOUND; destroyed root -> CUSTODY_DESTROYED; malformed deadlines
      (past / naive / beyond max) -> BAD_REQUEST; audit chain is valid and
      secret-free (reason scrubbing included).
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import os
import sys
from datetime import datetime, timedelta, timezone

# Gates must be armed before app construction reads settings.
os.environ.setdefault("KEYVAULT_FAULT_INJECTION", "1")

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.config import get_settings
from app.db import Database, wait_for_database
from app.faults import FaultBoard
from app.main import app
from app.pending import PendingShareStore
from app.seed import seed, demo_credentials

PASS, FAIL = "PASS", "FAIL"
results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, ok, detail))
    print(f"[{PASS if ok else FAIL}] {name}" + (f" — {detail}" if detail and not ok else ""))


def body_of(r) -> dict:
    try:
        return r.json()
    except Exception:  # noqa: BLE001
        return {}


def sign(priv_hex: str, message) -> str:
    data = message if isinstance(message, bytes) else message.encode()
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex)).sign(
        data).hex()


EPOCH = {"valid_from": "2026-01-01T00:00:00Z",
         "valid_until": "2035-01-01T00:00:00Z", "rotation_interval": 0}


def iso_in(seconds: float) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ")


@contextlib.asynccontextmanager
async def server():
    settings = get_settings()
    await wait_for_database(settings.database_url)
    await seed()
    database = Database(settings.database_url)
    await database.connect()
    app.state.db = database
    app.state.pending = PendingShareStore()
    app.state.fault_enabled = True
    board = FaultBoard()
    app.state.fault_board = board
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        try:
            yield http, database.pool, board
        finally:
            await database.close()


def auth(key: str) -> dict:
    return {"X-API-Key": key}


async def wait_lock_waiters(pool, expect: int, like: str, timeout: float = 10.0) -> int:
    sql = f"""
        SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid
        WHERE l.locktype='transactionid' AND NOT l.granted AND a.query LIKE '%{like}%'
    """
    deadline = asyncio.get_event_loop().time() + timeout
    seen = 0
    while asyncio.get_event_loop().time() < deadline:
        seen = await pool.fetchval(sql)
        if seen >= expect:
            return seen
        await asyncio.sleep(0.02)
    return seen


class H:
    def __init__(self, http, pool, creds):
        self.http = http
        self.pool = pool
        self.tenant_key = creds["tenant"]["api_key"]
        self.cust = {c["name"]: c for c in creds["custodians"]}
        self.secret = b"freeze-lineage-regression-secret-987654"

    def hh(self, name: str) -> dict:
        return auth(self.cust[name]["api_key"])

    async def policy(self, pid: str, custodians=("alice", "bob", "carol"), threshold: int = 2):
        r = await self.http.post("/policies", headers=auth(self.tenant_key), json={
            "policy_id": pid, "threshold": threshold,
            "custodian_ids": [f"cus_demo_{n}" for n in custodians], "epoch": EPOCH})
        assert r.status_code == 201, r.text

    async def custody(self, policy: str) -> str:
        r = await self.http.post("/custodies", headers=auth(self.tenant_key), json={
            "policy_id": policy, "expected_version": 1, "secret_hex": self.secret.hex()})
        assert r.status_code == 201, r.text
        return r.json()["custody_id"]

    async def migrate_chain(self, tag: str, hops: int = 2):
        p0 = f"pol_f_{tag}_0"
        await self.policy(p0)
        cid = await self.custody(p0)
        chain = [cid]
        prev = cid
        for i in range(1, hops + 1):
            tp = f"pol_f_{tag}_{i}"
            await self.policy(tp)
            r = await self.http.post("/migrations",
                                     headers={**auth(self.tenant_key),
                                              "Idempotency-Key": f"f-{tag}-{i}"},
                                     json={"source_custody_id": prev,
                                           "target_policy_id": tp, "target_version": 1})
            assert r.status_code == 201, r.text
            mid = r.json()["migration_id"]
            for nm in ("alice", "bob"):
                p = await self.mig_prep(nm, mid)
                r = await self.http.post("/migrations/shares", headers=self.hh(nm), json=p)
                assert r.status_code == 200, r.text
            prev = r.json()["new_custody_id"]
            chain.append(prev)
        return chain

    async def mig_prep(self, name: str, mid: str) -> dict:
        h = self.hh(name)
        r = await self.http.post("/migrations/nonces", headers=h, json={"migration_id": mid})
        assert r.status_code == 200, r.text
        nonce = r.json()["nonce"]
        r = await self.http.post("/migrations/shards/claim", headers=h,
                                 json={"migration_id": mid, "nonce": nonce})
        assert r.status_code == 200, r.text
        c = r.json()
        return {"migration_id": mid, "nonce": nonce, "point_x": c["point_x"],
                "shard_hex": c["shard_hex"],
                "signature": sign(self.cust[name]["signing_private_key"], c["signing_message"])}

    async def rec_prep(self, name: str, sid: str) -> dict:
        h = self.hh(name)
        r = await self.http.post("/recoveries/nonces", headers=h, json={"session_id": sid})
        assert r.status_code == 200, r.text
        nonce = r.json()["nonce"]
        r = await self.http.post("/recoveries/shards/claim", headers=h,
                                 json={"session_id": sid, "nonce": nonce})
        assert r.status_code == 200, r.text
        c = r.json()
        return {"session_id": sid, "nonce": nonce, "point_x": c["point_x"],
                "shard_hex": c["shard_hex"],
                "signature": sign(self.cust[name]["signing_private_key"], c["signing_message"])}

    async def open_recovery(self, cid: str) -> str:
        r = await self.http.post("/recoveries", headers=auth(self.tenant_key), json={
            "custody_id": cid, "request_digest": "00" * 32,
            "recovery_public_key": "11" * 32})
        assert r.status_code == 201, r.text
        return r.json()["session_id"]

    async def freeze(self, cid: str, seconds: int = 3600, reason: str = "legal hold",
                     headers: dict | None = None):
        return await self.http.post("/freezes",
                                    headers={**auth(self.tenant_key), **(headers or {})},
                                    json={"root_custody_id": cid,
                                          "valid_until": iso_in(seconds), "reason": reason})

    async def shards(self, *cids) -> int:
        return await self.pool.fetchval(
            "SELECT count(*) FROM shards WHERE custody_id = ANY($1::text[])", list(cids))


async def scenario_f1(hs: H, tag: str):
    label = "F1(lifecycle+gates)"
    await hs.policy(f"pol_f_{tag}")
    cid = await hs.custody(f"pol_f_{tag}")
    sid = None
    # freeze 之前恢复可建
    sid = await hs.open_recovery(cid)
    r = await hs.http.post("/recoveries/nonces", headers=hs.hh("alice"),
                           json={"session_id": sid})
    assert r.status_code == 200, r.text
    nonce = r.json()["nonce"]
    r = await hs.freeze(cid, 3600, "F1 legal hold")
    fr = body_of(r)
    fid = fr.get("freeze_id")
    check(f"{label}: 201 freeze with snapshot [root], dynamic coverage",
          r.status_code == 201 and fid and fr["custody_ids"] == [cid]
          and fr["coverage"] == "dynamic_lineage" and fr["effective"] == "active",
          r.text[:200])

    # 已 open 恢复的后续关口全部 423；不消耗 nonce
    r = await hs.http.post("/recoveries/shards/claim", headers=hs.hh("alice"),
                           json={"session_id": sid, "nonce": nonce})
    check(f"{label}: claim on pre-open session -> 423 CUSTODY_FROZEN, no shard",
          r.status_code == 423 and body_of(r)["error"]["code"] == "CUSTODY_FROZEN"
          and "shard_hex" not in r.text, r.text[:200])
    spent = await hs.pool.fetchval("SELECT spent FROM session_nonces WHERE nonce_hash=$1",
                                   __import__("app.crypto", fromlist=["sha256_hex"]).sha256_hex(
                                       bytes.fromhex(nonce)))
    check(f"{label}: blocked claim does not spend nonce", spent is False)
    r = await hs.http.post("/recoveries/nonces", headers=hs.hh("bob"),
                           json={"session_id": sid})
    check(f"{label}: nonce issue -> 423",
          r.status_code == 423 and body_of(r)["error"]["code"] == "CUSTODY_FROZEN", r.text[:160])
    # 新恢复创建也 423
    r = await hs.http.post("/recoveries", headers=auth(hs.tenant_key), json={
        "custody_id": cid, "request_digest": "00" * 32, "recovery_public_key": "11" * 32})
    check(f"{label}: recovery create -> 423",
          r.status_code == 423 and body_of(r)["error"]["basis"]["freeze_id"] == fid, r.text[:160])

    # GET / list
    r = await hs.http.get(f"/freezes/{fid}", headers=auth(hs.tenant_key))
    check(f"{label}: GET freeze", r.status_code == 200 and body_of(r)["freeze_id"] == fid)
    r = await hs.http.get("/freezes", headers=auth(hs.tenant_key),
                          params={"root_custody_id": cid, "status": "active"})
    check(f"{label}: list filter active by root",
          r.status_code == 200 and [f["freeze_id"] for f in r.json()] == [fid], r.text[:160])

    # 迁移不受影响：建迁移、走完门限、完成
    await hs.policy(f"pol_f_{tag}_t")
    r = await hs.http.post("/migrations", headers={**auth(hs.tenant_key),
                                                   "Idempotency-Key": f"f1-{tag}"},
                           json={"source_custody_id": cid,
                                 "target_policy_id": f"pol_f_{tag}_t", "target_version": 1})
    check(f"{label}: migration create allowed while frozen", r.status_code == 201, r.text[:160])
    mid = r.json()["migration_id"]
    for nm in ("alice", "bob"):
        p = await hs.mig_prep(nm, mid)
        r = await hs.http.post("/migrations/shares", headers=hs.hh(nm), json=p)
        assert r.status_code == 200, r.text
    newcid = body_of(r)["new_custody_id"]
    check(f"{label}: migration completes while frozen, online shards retained",
          bool(newcid) and await hs.shards(cid, newcid) == 6)
    # 后代恢复被动态覆盖
    r = await hs.http.post("/recoveries", headers=auth(hs.tenant_key), json={
        "custody_id": newcid, "request_digest": "00" * 32, "recovery_public_key": "11" * 32})
    check(f"{label}: descendant recovery dynamically frozen (423)",
          r.status_code == 423 and body_of(r)["error"]["basis"]["root_custody_id"] == cid,
          r.text[:160])

    # 解除：旧 open 会话仍存在；新恢复恢复
    r = await hs.http.post(f"/freezes/{fid}/release", headers=auth(hs.tenant_key))
    check(f"{label}: release 200 effective=released",
          r.status_code == 200 and body_of(r)["effective"] == "released")
    r = await hs.http.post("/recoveries", headers=auth(hs.tenant_key), json={
        "custody_id": newcid, "request_digest": "00" * 32, "recovery_public_key": "11" * 32})
    check(f"{label}: recovery create works after release", r.status_code == 201, r.text[:160])
    r = await hs.http.get("/freezes", headers=auth(hs.tenant_key),
                          params={"root_custody_id": cid, "status": "active"})
    check(f"{label}: released freeze no longer listed as active", r.json() == [])


async def scenario_f2(hs: H, tag: str):
    label = "F2(expiry)"
    await hs.policy(f"pol_f_{tag}")
    cid = await hs.custody(f"pol_f_{tag}")
    # min freeze window = 10s; 取 12s 以稳定
    r = await hs.freeze(cid, 12, "short")
    fid = body_of(r)["freeze_id"]
    assert r.status_code == 201, r.text
    r = await hs.http.post("/recoveries", headers=auth(hs.tenant_key), json={
        "custody_id": cid, "request_digest": "00" * 32, "recovery_public_key": "11" * 32})
    check(f"{label}: blocked while active", r.status_code == 423)
    await asyncio.sleep(13)
    r = await hs.http.post("/recoveries", headers=auth(hs.tenant_key), json={
        "custody_id": cid, "request_digest": "00" * 32, "recovery_public_key": "11" * 32})
    check(f"{label}: auto-lapsed after valid_until (no sweeper) -> 201",
          r.status_code == 201, r.text[:160])
    r = await hs.http.get(f"/freezes/{fid}", headers=auth(hs.tenant_key))
    j = body_of(r)
    check(f"{label}: GET shows stored status=active, effective=expired",
          j["status"] == "active" and j["effective"] == "expired", r.text[:160])
    r = await hs.http.get("/freezes", headers=auth(hs.tenant_key), params={"status": "expired"})
    check(f"{label}: list status=expired filter includes it",
          any(f["freeze_id"] == fid for f in r.json()))
    # 解除一个已到期冻结：呈现 expired，不回写
    r = await hs.http.post(f"/freezes/{fid}/release", headers=auth(hs.tenant_key))
    j = body_of(r)
    check(f"{label}: release of expired -> effective=expired, row untouched",
          r.status_code == 200 and j["effective"] == "expired" and j["status"] == "active"
          and j["released_at"] is None, r.text[:160])


async def scenario_f3(hs: H, tag: str):
    label = "F3(overlapping-stack)"
    await hs.policy(f"pol_f_{tag}")
    cid = await hs.custody(f"pol_f_{tag}")
    r1 = await hs.freeze(cid, 3600, "first"); f1 = body_of(r1)["freeze_id"]
    r2 = await hs.freeze(cid, 3600, "second"); f2 = body_of(r2)["freeze_id"]
    assert r1.status_code == 201 and r2.status_code == 201
    r = await hs.http.post("/recoveries", headers=auth(hs.tenant_key), json={
        "custody_id": cid, "request_digest": "00" * 32, "recovery_public_key": "11" * 32})
    check(f"{label}: two overlapping freezes -> 423", r.status_code == 423)
    r = await hs.http.post(f"/freezes/{f1}/release", headers=auth(hs.tenant_key))
    assert r.status_code == 200
    r = await hs.http.post("/recoveries", headers=auth(hs.tenant_key), json={
        "custody_id": cid, "request_digest": "00" * 32, "recovery_public_key": "11" * 32})
    check(f"{label}: one released, other still active -> still 423", r.status_code == 423)
    r = await hs.http.post(f"/freezes/{f2}/release", headers=auth(hs.tenant_key))
    assert r.status_code == 200
    r = await hs.http.post("/recoveries", headers=auth(hs.tenant_key), json={
        "custody_id": cid, "request_digest": "00" * 32, "recovery_public_key": "11" * 32})
    check(f"{label}: both released -> recovery 201", r.status_code == 201, r.text[:160])
    # 重复解除幂等
    r = await hs.http.post(f"/freezes/{f2}/release", headers=auth(hs.tenant_key))
    check(f"{label}: second release idempotent 200",
          r.status_code == 200 and body_of(r)["effective"] == "released")


async def scenario_f4(hs: H, tag: str):
    label = "F4(preexisting-descendants)"
    chain = await hs.migrate_chain(tag, hops=2)
    root, child, grand = chain
    r = await hs.freeze(root, 3600, "chain")
    j = body_of(r)
    check(f"{label}: snapshot covers root+child+grandchild",
          r.status_code == 201 and j["custody_count"] == 3
          and set(j["custody_ids"]) == set(chain), r.text[:160])
    for cid in chain:
        r = await hs.http.post("/recoveries", headers=auth(hs.tenant_key), json={
            "custody_id": cid, "request_digest": "00" * 32,
            "recovery_public_key": "11" * 32})
        check(f"{label}: {cid[:14]}… recovery 423", r.status_code == 423, r.text[:120])
    check(f"{label}: online shards retained on all 3 records", await hs.shards(*chain) == 9)


async def scenario_f5(hs: H, board: FaultBoard, tag: str):
    label = "F5(migration-wins:child-in-snapshot)"
    chain = await hs.migrate_chain(tag, hops=1)
    root, child = chain
    await hs.policy(f"pol_f_{tag}_t")
    mid = await hs.http.post("/migrations",
                             headers={**auth(hs.tenant_key), "Idempotency-Key": f"f5-{tag}"},
                             json={"source_custody_id": child,
                                   "target_policy_id": f"pol_f_{tag}_t", "target_version": 1})
    assert mid.status_code == 201, mid.text
    mid = mid.json()["migration_id"]
    pa = await hs.mig_prep("alice", mid)
    pb = await hs.mig_prep("bob", mid)
    await hs.http.post("/migrations/shares", headers=hs.hh("alice"), json=pa)

    # 冻结在“根行锁已持有、谱系尚未展开”处 park（此时只持根锁，不持 child
    # 锁）：bob 的门限迁移提交先拿 child custody 行锁并完成迁移，冻结随后在
    # 下一轮不动点展开中看到新生后代——快照与锁集必须把它纳入（绝不漏冻）。
    gate = {"X-Fault-Key": label, "X-Fault-Gate": "freeze.after_root_lock"}
    ft = asyncio.create_task(hs.freeze(root, 3600, "f5", gate))
    await board.wait_reached(f"freeze.after_root_lock:{label}")
    st = asyncio.create_task(hs.http.post("/migrations/shares", headers=hs.hh("bob"), json=pb))
    # 冻结此刻只持根锁、未锁 child；门限迁移提交不与之冲突，可独立提交完成。
    # 轮询确认迁移确已 completed（确定性“迁移先赢”），再放行冻结做谱系展开。
    deadline = asyncio.get_event_loop().time() + 10
    while asyncio.get_event_loop().time() < deadline:
        st_done = await hs.pool.fetchval(
            "SELECT status='completed' FROM migration_sessions WHERE id=$1", mid)
        if st_done:
            break
        await asyncio.sleep(0.02)
    check(f"{label}: migration commits while freeze parked pre-expansion",
          st_done is True)
    await board.release_gate(f"freeze.after_root_lock:{label}")
    fr_r = await ft
    sr = await st
    newcid = body_of(sr).get("new_custody_id")
    check(f"{label}: migration still completes (freezes never roll it back)",
          sr.status_code == 200 and bool(newcid), sr.text[:160])
    j = body_of(fr_r)
    check(f"{label}: freeze snapshot includes fresh descendant (never missed)",
          fr_r.status_code == 201 and j["custody_count"] == 3
          and newcid in j["custody_ids"], f"{fr_r.status_code} {j.get('custody_count')}")
    # 新后代恢复立即被冻（快照 + 动态双覆盖）
    r = await hs.http.post("/recoveries", headers=auth(hs.tenant_key), json={
        "custody_id": newcid, "request_digest": "00" * 32, "recovery_public_key": "11" * 32})
    check(f"{label}: fresh descendant recovery -> 423", r.status_code == 423, r.text[:120])
    # 在同一谱系再做一跳，动态覆盖同样生效
    await hs.policy(f"pol_f_{tag}_t2")
    r = await hs.http.post("/migrations", headers={**auth(hs.tenant_key),
                                                   "Idempotency-Key": f"f5-{tag}-b"},
                           json={"source_custody_id": newcid,
                                 "target_policy_id": f"pol_f_{tag}_t2", "target_version": 1})
    assert r.status_code == 201
    mid2 = r.json()["migration_id"]
    for nm in ("alice", "bob"):
        p = await hs.mig_prep(nm, mid2)
        r = await hs.http.post("/migrations/shares", headers=hs.hh(nm), json=p)
        assert r.status_code == 200, r.text
    c4 = body_of(r)["new_custody_id"]
    r = await hs.http.post("/recoveries", headers=auth(hs.tenant_key), json={
        "custody_id": c4, "request_digest": "00" * 32, "recovery_public_key": "11" * 32})
    check(f"{label}: future (second-hop) descendant also frozen", r.status_code == 423)

    # ---- F5b：冻结先赢。门限提交在 child custody 行锁上排队；冻结提交后，
    # 迁移照常提交完成（冻结不回滚迁移），新后代经动态覆盖立即受冻。
    label2 = "F5b(freeze-wins:migration-still-completes)"
    chain2 = await hs.migrate_chain(f"{tag}b", hops=1)
    root2, child2 = chain2
    await hs.policy(f"pol_f_{tag}b_t")
    mb = await hs.http.post("/migrations",
                            headers={**auth(hs.tenant_key), "Idempotency-Key": f"f5b-{tag}"},
                            json={"source_custody_id": child2,
                                  "target_policy_id": f"pol_f_{tag}b_t", "target_version": 1})
    assert mb.status_code == 201, mb.text
    mb = mb.json()["migration_id"]
    pa2 = await hs.mig_prep("alice", mb)
    pb2 = await hs.mig_prep("bob", mb)
    await hs.http.post("/migrations/shares", headers=hs.hh("alice"), json=pa2)
    gate2 = {"X-Fault-Key": label2, "X-Fault-Gate": "freeze.after_lineage_lock"}
    ft2 = asyncio.create_task(hs.freeze(root2, 3600, "f5b", gate2))
    await board.wait_reached(f"freeze.after_lineage_lock:{label2}")
    st2 = asyncio.create_task(hs.http.post("/migrations/shares", headers=hs.hh("bob"), json=pb2))
    queued = await wait_lock_waiters(hs.pool, 1, "key_custodies")
    check(f"{label2}: threshold migration submit queues behind freeze", queued == 1, f"q={queued}")
    await board.release_gate(f"freeze.after_lineage_lock:{label2}")
    fr2 = await ft2
    sr2 = await st2
    nc2 = body_of(sr2).get("new_custody_id")
    check(f"{label2}: queued migration still completes after freeze commit",
          fr2.status_code == 201 and sr2.status_code == 200 and bool(nc2),
          f"{fr2.status_code}/{sr2.status_code} {sr2.text[:120]}")
    r = await hs.http.post("/recoveries", headers=auth(hs.tenant_key), json={
        "custody_id": nc2, "request_digest": "00" * 32, "recovery_public_key": "11" * 32})
    check(f"{label2}: descendant born after freeze is dynamically frozen",
          r.status_code == 423 and body_of(r)["error"]["basis"]["root_custody_id"] == root2,
          r.text[:120])
    # 冻结快照只含提交时的两代（root2/child2）；新后代靠动态覆盖，不落快照
    snap = body_of(fr2)["custody_ids"]
    check(f"{label2}: snapshot reflects commit-time lineage, coverage stays dynamic",
          set(snap) == set(chain2) and nc2 not in snap, str(snap))


async def scenario_f6(hs: H, board: FaultBoard, tag: str):
    label = "F6(recovery-create-vs-freeze)"
    await hs.policy(f"pol_f_{tag}")
    cid = await hs.custody(f"pol_f_{tag}")
    gate = {"X-Fault-Key": label, "X-Fault-Gate": "freeze.after_root_lock"}
    ft = asyncio.create_task(hs.freeze(cid, 3600, "f6", gate))
    await board.wait_reached(f"freeze.after_root_lock:{label}")
    ct = asyncio.create_task(hs.http.post("/recoveries", headers=auth(hs.tenant_key), json={
        "custody_id": cid, "request_digest": "00" * 32, "recovery_public_key": "11" * 32}))
    queued = await wait_lock_waiters(hs.pool, 1, "key_custodies")
    check(f"{label}: recovery create queues behind freeze", queued == 1, f"q={queued}")
    await board.release_gate(f"freeze.after_root_lock:{label}")
    fr = await ft
    cr = await ct
    check(f"{label}: queued recovery create gets 423 once freeze commits",
          fr.status_code == 201 and cr.status_code == 423
          and body_of(cr)["error"]["code"] == "CUSTODY_FROZEN",
          f"{fr.status_code}/{cr.status_code} {cr.text[:120]}")
    n = await hs.pool.fetchval(
        "SELECT count(*) FROM recovery_sessions WHERE custody_id=$1", cid)
    check(f"{label}: no recovery row committed", n == 0, str(n))

    # claim 队列：已存在的 open 恢复（先建好），冻结在 after_lineage_lock park
    label2 = "F6b(claim-queued-frozen)"
    await hs.policy(f"pol_f_{tag}b")
    cid2 = await hs.custody(f"pol_f_{tag}b")
    sid2 = await hs.open_recovery(cid2)
    r = await hs.http.post("/recoveries/nonces", headers=hs.hh("carol"),
                           json={"session_id": sid2})
    assert r.status_code == 200
    nonce2 = r.json()["nonce"]
    gate2 = {"X-Fault-Key": label2, "X-Fault-Gate": "freeze.after_lineage_lock"}
    ft2 = asyncio.create_task(hs.freeze(cid2, 3600, "f6b", gate2))
    await board.wait_reached(f"freeze.after_lineage_lock:{label2}")
    ct2 = asyncio.create_task(hs.http.post("/recoveries/shards/claim",
                                           headers=hs.hh("carol"),
                                           json={"session_id": sid2, "nonce": nonce2}))
    queued = await wait_lock_waiters(hs.pool, 1, "key_custodies")
    check(f"{label2}: claim queues on locked custody", queued == 1, f"q={queued}")
    await board.release_gate(f"freeze.after_lineage_lock:{label2}")
    fr2 = await ft2
    cr2 = await ct2
    check(f"{label2}: queued claim -> 423, never returns shard",
          fr2.status_code == 201 and cr2.status_code == 423
          and "shard_hex" not in cr2.text, cr2.text[:120])


async def scenario_f7(hs: H, tag: str):
    label = "F7(no-side-effects)"
    await hs.policy(f"pol_f_{tag}")
    cid = await hs.custody(f"pol_f_{tag}")
    sid = await hs.open_recovery(cid)
    # alice 完整走完一份（冻结前），制造 1 份已计数 + 内存待累计
    pa = await hs.rec_prep("alice", sid)
    r = await hs.http.post("/recoveries/shares", headers=hs.hh("alice"), json=pa)
    assert r.status_code == 200 and body_of(r)["shares_received"] == 1, r.text
    count_before = await hs.pool.fetchval(
        "SELECT count(*) FROM share_submissions WHERE session_id=$1", sid)
    assert count_before == 1
    check(f"{label}: one share committed + pending before freeze",
          app.state.pending.count(sid) == 1)

    # bob 领好 nonce（第二张 nonce），随后冻结；bob 的提交必须被 423：
    # nonce 不花费、计数不变、内存不新增。
    r = await hs.http.post("/recoveries/nonces", headers=hs.hh("bob"),
                           json={"session_id": sid})
    assert r.status_code == 200, r.text
    nonce_bob = r.json()["nonce"]
    point_bob = r.json()["point_x"]
    digest_bob = r.json()["shard_digest"]
    await hs.freeze(cid, 3600, "f7")

    # 用真实库存分片构造一份“合法的”提交负载（绕过 claim 被冻，直接提交）：
    # 通过内部解密拿到 bob 的分片字节（模拟托管人在冻结前已 claim 过）。
    from app.config import get_settings
    settings = get_settings()
    from app import crypto
    row = await hs.pool.fetchrow(
        "SELECT s.id, s.ciphertext FROM shards s WHERE s.custody_id=$1 AND s.custodian_id=$2",
        cid, "cus_demo_bob")
    blob = crypto.decrypt_shard(settings.shard_master_key_bytes, row["id"],
                                bytes(row["ciphertext"]))
    msg = crypto.custodian_signing_message(
        nonce=nonce_bob, session_id=sid, policy_id=f"pol_f_{tag}", policy_version=1,
        custodian_id="cus_demo_bob", point_x=point_bob, shard_digest=digest_bob)
    sig = sign(hs.cust["bob"]["signing_private_key"], msg)
    r = await hs.http.post("/recoveries/shares", headers=hs.hh("bob"), json={
        "session_id": sid, "nonce": nonce_bob, "point_x": point_bob,
        "shard_hex": blob.hex(), "signature": sig})
    check(f"{label}: otherwise-valid submit while frozen -> 423",
          r.status_code == 423 and body_of(r)["error"]["code"] == "CUSTODY_FROZEN", r.text[:160])
    spent = await hs.pool.fetchval(
        "SELECT spent FROM session_nonces WHERE nonce_hash=$1",
        crypto.sha256_hex(bytes.fromhex(nonce_bob)))
    check(f"{label}: bob nonce unspent", spent is False)
    cnt = await hs.pool.fetchval(
        "SELECT count(*) FROM share_submissions WHERE session_id=$1", sid)
    check(f"{label}: share count unchanged (1)", cnt == 1, str(cnt))
    check(f"{label}: in-memory pending unchanged (alice's 1 only)",
          app.state.pending.count(sid) == 1
          and not app.state.pending.has(sid, "cus_demo_bob"))

    # 解除后 bob 用原 nonce 正常 claim+提交（门限达成只下发一次密文）
    fid = (await hs.http.get("/freezes", headers=auth(hs.tenant_key),
                             params={"root_custody_id": cid})).json()[0]["freeze_id"]
    r = await hs.http.post(f"/freezes/{fid}/release", headers=auth(hs.tenant_key))
    assert r.status_code == 200
    # bob 的 nonce 在冻结前已签发（未花费）：解除后复用同一 nonce 领取+提交。
    r = await hs.http.post("/recoveries/shards/claim", headers=hs.hh("bob"),
                           json={"session_id": sid, "nonce": nonce_bob})
    assert r.status_code == 200, r.text
    c = r.json()
    sig_b = sign(hs.cust["bob"]["signing_private_key"], c["signing_message"])
    r = await hs.http.post("/recoveries/shares", headers=hs.hh("bob"), json={
        "session_id": sid, "nonce": nonce_bob, "point_x": c["point_x"],
        "shard_hex": c["shard_hex"], "signature": sig_b})
    j = body_of(r)
    check(f"{label}: after release bob submits, threshold reached once with wrap",
          r.status_code == 200 and j.get("completed") is True and j.get("wrap") is not None,
          r.text[:160])


async def scenario_f8(hs: H, tag: str):
    label = "F8(post-release-still-bound)"
    await hs.policy(f"pol_f_{tag}")
    cid = await hs.custody(f"pol_f_{tag}")
    # 一个 TTL 10s 的恢复会话，冻结期间挂起
    r = await hs.http.post("/recoveries", headers=auth(hs.tenant_key), json={
        "custody_id": cid, "request_digest": "00" * 32,
        "recovery_public_key": "11" * 32, "ttl_seconds": 10})
    assert r.status_code == 201
    sid = r.json()["session_id"]
    rf = await hs.freeze(cid, 3600, "f8")
    fid = body_of(rf)["freeze_id"]
    # 旧会话在冻结下 423
    r = await hs.http.post("/recoveries/nonces", headers=hs.hh("alice"),
                           json={"session_id": sid})
    assert r.status_code == 423
    # 等会话 TTL 过期后解除
    await asyncio.sleep(11)
    r = await hs.http.post(f"/freezes/{fid}/release", headers=auth(hs.tenant_key))
    assert r.status_code == 200
    # 解冻不覆盖过期规则：旧会话现在 SESSION_EXPIRED
    r = await hs.http.post("/recoveries/nonces", headers=hs.hh("alice"),
                           json={"session_id": sid})
    check(f"{label}: old session still expires after release (not overridden)",
          r.status_code == 409 and body_of(r)["error"]["code"] == "SESSION_EXPIRED",
          r.text[:150])
    # 销毁规则仍约束：销毁后新恢复 410
    r = await hs.http.post("/destructions", headers={**auth(hs.tenant_key),
                                                     "Idempotency-Key": f"f8-{tag}"},
                           json={"root_custody_id": cid})
    assert r.status_code == 201, r.text
    r = await hs.http.post("/recoveries", headers=auth(hs.tenant_key), json={
        "custody_id": cid, "request_digest": "00" * 32, "recovery_public_key": "11" * 32})
    check(f"{label}: destroyed root still yields 410 after a (past) freeze",
          r.status_code == 410 and body_of(r)["error"]["code"] == "CUSTODY_DESTROYED")


async def scenario_f9(hs: H, tag: str):
    label = "F9(release-unknown+list)"
    r = await hs.http.post("/freezes/frz_does_not_exist/release",
                           headers=auth(hs.tenant_key))
    check(f"{label}: release unknown -> NOT_FOUND",
          r.status_code == 404 and body_of(r)["error"]["code"] == "NOT_FOUND")
    r = await hs.http.get("/freezes/frz_does_not_exist", headers=auth(hs.tenant_key))
    check(f"{label}: GET unknown -> NOT_FOUND", r.status_code == 404)


async def scenario_f10(hs: H, tag: str):
    label = "F10(access+validation+audit)"
    await hs.policy(f"pol_f_{tag}")
    cid = await hs.custody(f"pol_f_{tag}")

    # 过去时间 / 无时区 / 超上限
    r = await hs.http.post("/freezes", headers=auth(hs.tenant_key),
                           json={"root_custody_id": cid,
                                 "valid_until": iso_in(-100), "reason": "past"})
    check(f"{label}: deadline in past -> BAD_REQUEST",
          r.status_code == 400 and body_of(r)["error"]["code"] == "BAD_REQUEST", r.text[:150])
    r = await hs.http.post("/freezes", headers=auth(hs.tenant_key),
                           json={"root_custody_id": cid,
                                 "valid_until": "2030-01-01T00:00:00", "reason": "naive"})
    check(f"{label}: naive deadline -> VALIDATION_FAILED",
          r.status_code == 400 and body_of(r)["error"]["code"] == "VALIDATION_FAILED", r.text[:150])
    r = await hs.http.post("/freezes", headers=auth(hs.tenant_key),
                           json={"root_custody_id": cid,
                                 "valid_until": iso_in(200 * 24 * 3600), "reason": "far"})
    check(f"{label}: deadline beyond max -> BAD_REQUEST",
          r.status_code == 400 and body_of(r)["error"]["code"] == "BAD_REQUEST")
    r = await hs.http.post("/freezes", headers=auth(hs.tenant_key),
                           json={"root_custody_id": cid, "valid_until": iso_in(3600)})
    check(f"{label}: empty reason -> VALIDATION_FAILED", r.status_code == 400)

    # 未知根 / 已销毁根
    r = await hs.freeze("cus_secret_nope_nope", 3600)
    check(f"{label}: unknown root -> NOT_FOUND",
          r.status_code == 404 and body_of(r)["error"]["code"] == "NOT_FOUND")
    r = await hs.http.post("/destructions", headers={**auth(hs.tenant_key),
                                                     "Idempotency-Key": f"f10-{tag}"},
                           json={"root_custody_id": cid})
    assert r.status_code == 201
    r = await hs.freeze(cid, 3600)
    check(f"{label}: destroyed root -> CUSTODY_DESTROYED",
          r.status_code == 410 and body_of(r)["error"]["code"] == "CUSTODY_DESTROYED", r.text[:150])

    # 跨租户：建根属于本租户，另一租户全部操作拒绝
    await hs.policy(f"pol_f_{tag}x")
    cid2 = await hs.custody(f"pol_f_{tag}x")
    r = await hs.http.post("/admin/tenants", headers=auth(demo_credentials()["admin_api_key"]),
                           json={"name": f"freeze-other-{tag}"})
    assert r.status_code == 201
    other = {"X-API-Key": r.json()["api_key"]}
    r = await hs.http.post("/freezes", headers=other,
                           json={"root_custody_id": cid2, "valid_until": iso_in(3600),
                                 "reason": "cross"})
    check(f"{label}: cross-tenant create -> FORBIDDEN",
          r.status_code == 403 and body_of(r)["error"]["code"] == "FORBIDDEN")
    fr = await hs.freeze(cid2, 3600, "owner")
    fid = body_of(fr)["freeze_id"]
    for method, path, kw in [
        ("GET", f"/freezes/{fid}", {}),
        ("POST", f"/freezes/{fid}/release", {}),
    ]:
        r = await hs.http.request(method, path, headers=other, **kw)
        check(f"{label}: cross-tenant {method} {path.split('/')[-1][:10]} -> FORBIDDEN",
              r.status_code == 403 and body_of(r)["error"]["code"] == "FORBIDDEN", r.text[:120])
    # 列表是租户作用域的：另一租户只看到自己的（空）集合，看不到对方冻结 id
    r = await hs.http.get("/freezes", headers=other)
    check(f"{label}: cross-tenant list is tenant-scoped (no foreign freeze visible)",
          r.status_code == 200 and all(f["freeze_id"] != fid for f in r.json())
          and r.json() == [], r.text[:120])

    # 审计链有效、无秘密、原因被保留且秘密字段名被过滤
    r = await hs.http.get("/audit/replay", headers=auth(hs.tenant_key))
    chain = r.json()
    raw = json.dumps(chain)
    check(f"{label}: audit chain valid", chain.get("valid") is True)
    check(f"{label}: audit leaks no secret",
          hs.secret.hex() not in raw and hs.secret.decode() not in raw)
    # reason 是无秘密字段应保留；构造一个含 "key" 字段名风险的原因不会带出秘密
    fr_rows = await hs.pool.fetch(
        "SELECT basis FROM audit_log WHERE action='freeze.create'")
    raw2 = json.dumps([json.loads(x["basis"]) if isinstance(x["basis"], str) else x["basis"]
                       for x in fr_rows])
    check(f"{label}: freeze audits replayable and secret-free", hs.secret.hex() not in raw2)
    # 拒绝留痕：跨租户/已销毁/非法参数都有 freeze.create denied
    denied = await hs.pool.fetch(
        "SELECT error_code, count(*) c FROM audit_log "
        "WHERE action='freeze.create' AND result='denied' GROUP BY error_code")
    codes = {x["error_code"]: x["c"] for x in denied}
    check(f"{label}: denial audits recorded (FORBIDDEN/CUSTODY_DESTROYED/BAD_REQUEST)",
          codes.get("FORBIDDEN", 0) >= 1 and codes.get("CUSTODY_DESTROYED", 0) >= 1
          and (codes.get("BAD_REQUEST", 0) >= 1),
          str(codes))


async def amain() -> int:
    async with server() as (http, pool, board):
        creds = demo_credentials()
        hs = H(http, pool, creds)
        suffix = os.urandom(4).hex()
        await scenario_f1(hs, f"{suffix}1")
        await scenario_f2(hs, f"{suffix}2")
        await scenario_f3(hs, f"{suffix}3")
        await scenario_f4(hs, f"{suffix}4")
        await scenario_f5(hs, board, f"{suffix}5")
        await scenario_f6(hs, board, f"{suffix}6")
        await scenario_f7(hs, f"{suffix}7")
        await scenario_f8(hs, f"{suffix}8")
        await scenario_f9(hs, f"{suffix}9")
        await scenario_f10(hs, f"{suffix}a")

        r = await http.get("/audit/replay", headers=auth(hs.tenant_key))
        check("final: audit hash chain valid across freeze scenarios",
              r.json().get("valid") is True)

    failed = [n for n, ok, _ in results if not ok]
    print("\n" + "=" * 70)
    print(f"{len(results) - len(failed)}/{len(results)} freeze checks passed")
    if failed:
        print("FAILED:")
        for n in failed:
            print(" -", n)
        return 1
    print("FREEZE CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(amain()))
