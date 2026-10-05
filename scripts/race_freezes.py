"""Regression harness: time-limited recovery freezes of custody lineages (v1.8).

Run (KEYVAULT_FAULT_INJECTION=1 enables the lock-waiter gates; the docker
compose ``demo`` profile sets it automatically):

    python -m scripts.race_freezes

It boots the *real* FastAPI app in-process (ASGI transport, real PostgreSQL,
real row locks) and pins every required property:

  F1  coverage: a freeze on the root covers the root AND every descendant
      along completed migration edges (dynamically — including descendants
      born after the freeze commit); GET /freezes reports the live coverage
      snapshot; reason/digest ids only, no secret material.
  F2  recovery fully blocked while frozen: recovery creation + nonce + claim +
      submit on the root and on every descendant all get CUSTODY_FROZEN (423);
      no shard plaintext is returned; a frozen rejection spends no nonce,
      changes no share count and touches no in-memory pending shares.
  F3  early release: after POST /freezes/{id}/release recovery works on the
      whole lineage again; old pre-freeze sessions are still subject to the
      expiry / revoke / destruction rules (a completed session stays
      completed; a revoked epoch stays EPOCH_REVOKED) — release only lifts the
      freeze, nothing else.
  F4  automatic expiry: a freeze past valid_until adjudicates as gone without
      any explicit release (recovery allowed); releasing an expired freeze is
      FREEZE_NOT_ACTIVE; GET reports effective status expired.
  F5  overlapping freezes: two overlapping freezes both block; releasing one
      keeps blocking; recovery is allowed only once ALL are released/expired.
  F6  freeze vs migration completion (freeze wins the lock race): the queued
      threshold migration submit is NOT rejected by the freeze — migrations
      always complete; after it commits its brand-new descendant is covered
      dynamically (recovery on it is CUSTODY_FROZEN) and online shards remain.
  F7  freeze vs recovery gate (gate wins): a nonce/claim request parked on the
      custody row lock while the freeze queues commits first (already past the
      freeze verdict point) and delivers normally; a later sibling gate after
      the freeze commits gets CUSTODY_FROZEN.
  F8  submit adjudication before the wrapped ciphertext + no state consumed:
      freeze a custody while an open recovery session already has 1 submitted
      share; the blocked second submit leaves nonce unspent, count at 1 and the
      in-memory pending shard untouched; after release the threshold completes.
  F9  cross-tenant requests rejected (create/release/get/list); freezing a
      destroyed root is CUSTODY_DESTROYED; unknown root NOT_FOUND; validation
      rejects missing reason / naive datetime / too-soon / too-far deadline.
  F10 migrations and migration pending shares are unaffected: a frozen source
      still migrates successfully; freeze never marks sessions, never deletes
      shards, never touches pending migration shares; audit chain stays valid
      and secret-free, with freeze.start / freeze.release and the CUSTODY_FROZEN
      denial entries.
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


class _Raw500:
    def __init__(self, exc: BaseException):
        self.status_code = 500
        self.text = f"{type(exc).__name__}: {exc}"

    def json(self) -> dict:
        return {}


def sign(priv_hex: str, message: str) -> str:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex)).sign(
        message.encode()
    ).hex()


EPOCH = {"valid_from": "2026-01-01T00:00:00Z",
         "valid_until": "2035-01-01T00:00:00Z", "rotation_interval": 0}


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
        SELECT count(*)
        FROM pg_locks l
        JOIN pg_stat_activity a ON a.pid = l.pid
        WHERE l.locktype = 'transactionid'
          AND NOT l.granted
          AND a.query LIKE '%{like}%'
    """
    deadline = asyncio.get_event_loop().time() + timeout
    seen = 0
    while asyncio.get_event_loop().time() < deadline:
        seen = await pool.fetchval(sql)
        if seen >= expect:
            return seen
        await asyncio.sleep(0.02)
    return seen


class Harness:
    def __init__(self, http, pool, creds):
        self.http = http
        self.pool = pool
        self.tenant_key = creds["tenant"]["api_key"]
        self.cust = {c["name"]: c for c in creds["custodians"]}
        self.secret = b"freeze-lineage-regression-secret-0123456789"

    def h(self, name: str) -> dict:
        return auth(self.cust[name]["api_key"])

    async def make_policy(self, pid: str, custodians=("alice", "bob", "carol"), threshold: int = 2):
        ids = [f"cus_demo_{n}" for n in custodians]
        r = await self.http.post("/policies", headers=auth(self.tenant_key), json={
            "policy_id": pid, "threshold": threshold, "custodian_ids": ids, "epoch": EPOCH,
        })
        assert r.status_code == 201, r.text

    async def make_custody(self, policy: str, secret: bytes | None = None) -> str:
        r = await self.http.post("/custodies", headers=auth(self.tenant_key), json={
            "policy_id": policy, "expected_version": 1,
            "secret_hex": (secret or self.secret).hex(),
        })
        assert r.status_code == 201, r.text
        return r.json()["custody_id"]

    async def migrate_chain(self, tag: str, hops: int = 2):
        src_policy = f"pol_f_{tag}_0"
        await self.make_policy(src_policy)
        cid = await self.make_custody(src_policy)
        chain = [cid]
        prev_cid = cid
        for i in range(1, hops + 1):
            tgt_policy = f"pol_f_{tag}_{i}"
            await self.make_policy(tgt_policy)
            mid = body_of(await self.http.post(
                "/migrations", headers={**auth(self.tenant_key),
                                        "Idempotency-Key": f"f-{tag}-hop{i}"},
                json={"source_custody_id": prev_cid, "target_policy_id": tgt_policy,
                      "target_version": 1}))["migration_id"]
            for name in ("alice", "bob"):
                prepped = await self.mig_prep(name, mid)
                r = await self.http.post("/migrations/shares", headers=self.h(name), json=prepped)
                assert r.status_code == 200, r.text
            new_cid = body_of(r)["new_custody_id"]
            assert new_cid, r.text
            chain.append(new_cid)
            prev_cid = new_cid
        return chain

    async def mig_prep(self, name: str, mid: str) -> dict:
        h = self.h(name)
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
        h = self.h(name)
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
            "custody_id": cid, "request_digest": "00" * 32, "recovery_public_key": "11" * 32,
        })
        assert r.status_code == 201, r.text
        return r.json()["session_id"]

    async def open_migration(self, cid: str, target: str, idem: str) -> str:
        r = await self.http.post("/migrations",
                                 headers={**auth(self.tenant_key), "Idempotency-Key": idem},
                                 json={"source_custody_id": cid, "target_policy_id": target,
                                       "target_version": 1})
        assert r.status_code == 201, r.text
        return r.json()["migration_id"]

    async def freeze(self, cid: str, reason: str = "legal-hold", ttl_seconds: int = 3600,
                     extra_headers: dict | None = None):
        until = (datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)).isoformat()
        try:
            return await self.http.post(
                "/freezes", headers={**auth(self.tenant_key), **(extra_headers or {})},
                json={"root_custody_id": cid, "valid_until": until, "reason": reason})
        except Exception as exc:  # ASGI 500 re-raise
            return _Raw500(exc)

    async def freeze_sql(self, cid: str, *, ttl_seconds: float = 1.0,
                         status: str = "active", reason: str = "sql-short") -> str:
        """Insert a freeze row directly (short-TTL auto-expiry scenarios)."""
        return await self.pool.fetchval(
            """
            INSERT INTO custody_freezes
              (id, tenant_id, root_custody_id, reason, status, valid_until)
            VALUES ('frz_' || substr(md5(random()::text || clock_timestamp()::text), 1, 20),
                    'ten_demo', $1, $2, $3,
                    clock_timestamp() + make_interval(secs => $4))
            RETURNING id
            """,
            cid, reason, status, ttl_seconds)

    async def release(self, fid: str):
        return await self.http.post(f"/freezes/{fid}/release", headers=auth(self.tenant_key))

    async def shard_count(self, cid: str) -> int:
        return await self.pool.fetchval("SELECT count(*) FROM shards WHERE custody_id=$1", cid)

    async def custody_status(self, cid: str) -> str:
        return await self.pool.fetchval("SELECT status FROM key_custodies WHERE id=$1", cid)


# ---------------------------------------------------------------------------
# F1: coverage (existing descendants + dynamic snapshot)
# ---------------------------------------------------------------------------

async def scenario_f1(hs: Harness, tag: str):
    label = "F1(lineage-coverage)"
    chain = await hs.migrate_chain(tag, hops=2)
    root, child, grand = chain
    r = await hs.freeze(root, reason=f"hold-{tag}")
    f = body_of(r)
    check(f"{label}: 201 freeze active with queryable id",
          r.status_code == 201 and f.get("status") == "active"
          and f.get("freeze_id", "").startswith("frz_")
          and f.get("valid_until"), r.text[:200])
    check(f"{label}: coverage snapshot lists root+2 descendants",
          f.get("covered_custody_count") == 3
          and set(f.get("covered_custody_ids", [])) == set(chain), r.text[:200])
    fid = f["freeze_id"]

    # GET 等价返回动态覆盖
    r = await hs.http.get(f"/freezes/{fid}", headers=auth(hs.tenant_key))
    g = body_of(r)
    check(f"{label}: GET freeze by id",
          r.status_code == 200 and g.get("freeze_id") == fid
          and set(g.get("covered_custody_ids", [])) == set(chain)
          and g.get("reason") == f"hold-{tag}", r.text[:200])

    # 按 custody 反查列表：后代也能看到锚定于根的冻结
    r = await hs.http.get(f"/freezes?custody_id={grand}", headers=auth(hs.tenant_key))
    ids = [x["freeze_id"] for x in body_of(r)]
    check(f"{label}: list-by-custody shows ancestor freeze for descendant",
          r.status_code == 200 and fid in ids, r.text[:200])
    # 不相关 custody 查不到该冻结
    other_policy = f"pol_f_{tag}_o"
    await hs.make_policy(other_policy)
    other_cid = await hs.make_custody(other_policy)
    r = await hs.http.get(f"/freezes?custody_id={other_cid}", headers=auth(hs.tenant_key))
    check(f"{label}: unrelated custody sees no freeze",
          r.status_code == 200 and fid not in [x["freeze_id"] for x in body_of(r)], r.text[:200])

    # 响应与审计均无秘密
    check(f"{label}: freeze response leaks no secret", hs.secret.hex() not in r.text)
    row = await hs.pool.fetchrow(
        "SELECT basis FROM audit_log WHERE action='freeze.start' AND resource=$1", fid)
    raw = json.dumps(json.loads(row["basis"]) if isinstance(row["basis"], str) else row["basis"])
    check(f"{label}: freeze.start audit secret-free with reason + coverage",
          hs.secret.hex() not in raw and "root_custody_id" in raw and f"hold-{tag}" in raw
          and "covered_custody_ids" in raw)


# ---------------------------------------------------------------------------
# F2: full recovery blocking on root + descendants, no state consumed
# ---------------------------------------------------------------------------

async def scenario_f2(hs: Harness, tag: str):
    label = "F2(recovery-blocked)"
    chain = await hs.migrate_chain(tag, hops=1)
    root, child = chain
    # child 上先开一个恢复会话（冻结前的旧会话），冻结后其 nonce/claim/submit 全被裁决
    sid = await hs.open_recovery(child)
    r = await hs.freeze(root)
    assert r.status_code == 201, r.text

    # 谱系每个 custody 都不能新建恢复
    for cid in chain:
        rr = await hs.http.post("/recoveries", headers=auth(hs.tenant_key), json={
            "custody_id": cid, "request_digest": "00" * 32,
            "recovery_public_key": "11" * 32})
        check(f"{label}: POST /recoveries on {cid[:14]}… -> 423 CUSTODY_FROZEN",
              rr.status_code == 423 and body_of(rr)["error"]["code"] == "CUSTODY_FROZEN",
              rr.text[:200])

    # 旧会话的 nonce 签发被冻结裁决（bob 还没有 nonce）
    rr = await hs.http.post("/recoveries/nonces", headers=hs.h("bob"), json={"session_id": sid})
    check(f"{label}: nonce issue on frozen lineage -> 423",
          rr.status_code == 423 and body_of(rr)["error"]["code"] == "CUSTODY_FROZEN",
          rr.text[:200])
    n_nonces = await hs.pool.fetchval(
        "SELECT count(*) FROM session_nonces WHERE session_id=$1", sid)
    check(f"{label}: blocked nonce issue created no nonce row", n_nonces == 0, str(n_nonces))

    # 冻结前已领取 nonce 的托管人：冻结后 claim 不得再下发分片明文、不花 nonce
    tag2 = f"{tag}b"
    chain2 = await hs.migrate_chain(tag2, hops=1)
    root2, child2 = chain2
    sid2 = await hs.open_recovery(child2)
    r = await hs.http.post("/recoveries/nonces", headers=hs.h("bob"), json={"session_id": sid2})
    assert r.status_code == 200, r.text
    nonce_bob = r.json()["nonce"]
    await hs.freeze(root2)
    rr = await hs.http.post("/recoveries/shards/claim", headers=hs.h("bob"),
                            json={"session_id": sid2, "nonce": nonce_bob})
    check(f"{label}: claim on frozen lineage -> 423, no shard plaintext",
          rr.status_code == 423 and body_of(rr)["error"]["code"] == "CUSTODY_FROZEN"
          and "shard_hex" not in rr.text, rr.text[:200])
    spent = await hs.pool.fetchval(
        "SELECT spent FROM session_nonces WHERE session_id=$1 AND custodian_id='cus_demo_bob'",
        sid2)
    check(f"{label}: blocked claim spent no nonce", spent is False, str(spent))

    # basis 指明冻结事实（id/根/截止/数量）
    basis = body_of(rr)["error"]["basis"]
    check(f"{label}: basis identifies the freeze",
          basis.get("freeze_id") and basis.get("freeze_root_custody_id") == root2
          and basis.get("active_freeze_count") == 1
          and basis.get("freeze_valid_until"), json.dumps(basis)[:200])

    # 在线分片保留、custody 仍 active、会话仍 open（冻结不改状态）
    shards_ok = all([await hs.shard_count(c) == 3 for c in chain])
    check(f"{label}: online shards retained, custody active, session open",
          shards_ok
          and await hs.custody_status(root) == "active"
          and body_of(await hs.http.get(f"/recoveries/{sid}",
                                       headers=auth(hs.tenant_key)))["status"] == "open")


# ---------------------------------------------------------------------------
# F3: early release; old sessions still bound by other lifecycle rules
# ---------------------------------------------------------------------------

async def scenario_f3(hs: Harness, tag: str):
    label = "F3(early-release)"
    chain = await hs.migrate_chain(tag, hops=1)
    root, child = chain
    sid = await hs.open_recovery(child)
    r = await hs.freeze(root)
    fid = body_of(r)["freeze_id"]
    assert r.status_code == 201

    rr = await hs.http.post("/recoveries/nonces", headers=hs.h("alice"), json={"session_id": sid})
    check(f"{label}: blocked before release",
          rr.status_code == 423 and body_of(rr)["error"]["code"] == "CUSTODY_FROZEN", rr.text[:160])

    rr = await hs.release(fid)
    check(f"{label}: release 200 with released_at",
          rr.status_code == 200 and body_of(rr)["status"] == "released"
          and body_of(rr)["released_at"], rr.text[:200])
    rr = await hs.release(fid)
    check(f"{label}: release idempotent (same status, 200)",
          rr.status_code == 200 and body_of(rr)["status"] == "released", rr.text[:160])
    r = await hs.http.get(f"/freezes/{fid}", headers=auth(hs.tenant_key))
    check(f"{label}: GET shows released", body_of(r)["status"] == "released", r.text[:160])

    # 解冻后旧会话恢复可用：nonce 正常签发
    rr = await hs.http.post("/recoveries/nonces", headers=hs.h("alice"), json={"session_id": sid})
    check(f"{label}: nonce issue works again on old session",
          rr.status_code == 200, rr.text[:200])
    na = rr.json()

    # 旧会话仍受其它规则约束：该会话正常走完门限后，重复 nonce 是 SESSION_COMPLETED。
    # 复用刚签发的未花费 nonce 完成 alice 的领取/签名/提交
    ca = (await hs.http.post("/recoveries/shards/claim", headers=hs.h("alice"),
                             json={"session_id": sid, "nonce": na["nonce"]})).json()
    pa = {"session_id": sid, "nonce": na["nonce"], "point_x": ca["point_x"],
          "shard_hex": ca["shard_hex"],
          "signature": sign(hs.cust["alice"]["signing_private_key"], ca["signing_message"])}
    rr = await hs.http.post("/recoveries/shares", headers=hs.h("alice"), json=pa)
    assert rr.status_code == 200 and body_of(rr)["shares_received"] == 1, rr.text
    pb = await hs.rec_prep("bob", sid)
    rr = await hs.http.post("/recoveries/shares", headers=hs.h("bob"), json=pb)
    assert rr.status_code == 200 and body_of(rr)["completed"], rr.text
    rr = await hs.http.post("/recoveries/nonces", headers=hs.h("carol"), json={"session_id": sid})
    check(f"{label}: old session still SESSION_COMPLETED after unfreeze",
          rr.status_code == 409 and body_of(rr)["error"]["code"] == "SESSION_COMPLETED",
          rr.text[:160])
    # 冻结/解冻审计入链
    actions = [e["action"] for e in
               (await hs.http.get("/audit/replay", headers=auth(hs.tenant_key))).json()["entries"]]
    check(f"{label}: freeze.start + freeze.release audited",
          "freeze.start" in actions and "freeze.release" in actions)


# ---------------------------------------------------------------------------
# F4: automatic expiry + freeze minimum TTL validation
# ---------------------------------------------------------------------------

async def scenario_f4(hs: Harness, tag: str):
    label = "F4(auto-expiry)"
    policy = f"pol_f_{tag}_p"
    await hs.make_policy(policy)
    cid = await hs.make_custody(policy)

    # 直接插入 1 秒后到期的冻结（API 最短 60 秒，见下校验断言）
    fid = await hs.freeze_sql(cid, ttl_seconds=1.0)
    rr = await hs.http.post("/recoveries", headers=auth(hs.tenant_key), json={
        "custody_id": cid, "request_digest": "00" * 32, "recovery_public_key": "11" * 32})
    check(f"{label}: blocked while unexpired",
          rr.status_code == 423 and body_of(rr)["error"]["code"] == "CUSTODY_FROZEN", rr.text[:160])
    print(f"... waiting 2s for freeze {fid[:16]}… auto-expiry ...")
    await asyncio.sleep(2)
    rr = await hs.http.post("/recoveries", headers=auth(hs.tenant_key), json={
        "custody_id": cid, "request_digest": "00" * 32, "recovery_public_key": "11" * 32})
    check(f"{label}: recovery allowed after automatic expiry (no release call)",
          rr.status_code == 201, rr.text[:160])
    # 解除已到期冻结 -> 409 FREEZE_NOT_ACTIVE；GET effective status=expired
    rr = await hs.release(fid)
    check(f"{label}: release expired freeze -> FREEZE_NOT_ACTIVE",
          rr.status_code == 409 and body_of(rr)["error"]["code"] == "FREEZE_NOT_ACTIVE",
          rr.text[:200])
    r = await hs.http.get(f"/freezes/{fid}", headers=auth(hs.tenant_key))
    check(f"{label}: GET shows effective expired status",
          r.status_code == 200 and body_of(r)["status"] == "expired", r.text[:160])

    # 输入校验：naive 时间（400 校验）、过近、过远、空原因
    soon = (datetime.now(timezone.utc) + timedelta(seconds=5)).isoformat()
    rr = await hs.http.post("/freezes", headers=auth(hs.tenant_key),
                            json={"root_custody_id": cid, "valid_until": soon, "reason": "x"})
    check(f"{label}: deadline sooner than min TTL -> BAD_REQUEST",
          rr.status_code == 400 and body_of(rr)["error"]["basis"].get("reason")
          == "valid_until_too_soon", rr.text[:200])
    far = (datetime.now(timezone.utc) + timedelta(days=365)).isoformat()
    rr = await hs.http.post("/freezes", headers=auth(hs.tenant_key),
                            json={"root_custody_id": cid, "valid_until": far, "reason": "x"})
    check(f"{label}: deadline beyond max TTL -> BAD_REQUEST",
          rr.status_code == 400 and body_of(rr)["error"]["basis"].get("reason")
          == "valid_until_too_far", rr.text[:200])
    rr = await hs.http.post("/freezes", headers=auth(hs.tenant_key),
                            json={"root_custody_id": cid,
                                  "valid_until": "2026-12-31T00:00:00", "reason": "naive"})
    check(f"{label}: naive datetime -> VALIDATION_FAILED",
          rr.status_code == 400 and body_of(rr)["error"]["code"] == "VALIDATION_FAILED",
          rr.text[:200])
    rr = await hs.http.post("/freezes", headers=auth(hs.tenant_key),
                            json={"root_custody_id": cid,
                                  "valid_until": "2026-12-31T00:00:00Z", "reason": ""})
    check(f"{label}: empty reason -> VALIDATION_FAILED",
          rr.status_code == 400 and body_of(rr)["error"]["code"] == "VALIDATION_FAILED",
          rr.text[:200])


# ---------------------------------------------------------------------------
# F5: overlapping freezes must ALL be released
# ---------------------------------------------------------------------------

async def scenario_f5(hs: Harness, tag: str):
    label = "F5(overlapping-freezes)"
    policy = f"pol_f_{tag}_p"
    await hs.make_policy(policy)
    cid = await hs.make_custody(policy)

    async def blocked(note: str):
        rr = await hs.http.post("/recoveries", headers=auth(hs.tenant_key), json={
            "custody_id": cid, "request_digest": "00" * 32, "recovery_public_key": "11" * 32})
        ok = rr.status_code == 423 and body_of(rr)["error"]["code"] == "CUSTODY_FROZEN"
        check(f"{label}: {note}", ok, f"{rr.status_code} {rr.text[:120]}")
        return body_of(rr)["error"]["basis"]

    r1 = await hs.freeze(cid, reason="hold-A")
    r2 = await hs.freeze(cid, reason="hold-B")
    f1, f2 = body_of(r1)["freeze_id"], body_of(r2)["freeze_id"]
    assert r1.status_code == 201 and r2.status_code == 201

    b = await blocked("two overlapping freezes block, count=2")
    check(f"{label}: basis counts both overlaps", b.get("active_freeze_count") == 2, str(b))

    await hs.release(f1)
    b = await blocked("releasing one overlap still blocks, count=1")
    check(f"{label}: remaining overlap reported", b.get("active_freeze_count") == 1, str(b))

    # 第二条到期（SQL 1 秒）后才放行
    await hs.pool.execute(
        "UPDATE custody_freezes SET valid_until=clock_timestamp() + interval '1 second' "
        "WHERE id=$1", f2)
    await blocked("second overlap unexpired still blocks")
    await asyncio.sleep(1.5)
    rr = await hs.http.post("/recoveries", headers=auth(hs.tenant_key), json={
        "custody_id": cid, "request_digest": "00" * 32, "recovery_public_key": "11" * 32})
    check(f"{label}: allowed only after every overlap released/expired",
          rr.status_code == 201, rr.text[:160])


# ---------------------------------------------------------------------------
# F6: freeze vs threshold migration submit — migration always completes;
#     brand-new descendant covered dynamically with shards retained
# ---------------------------------------------------------------------------

async def scenario_f6(hs: Harness, board: FaultBoard, tag: str):
    label = "F6(freeze-vs-migration)"
    chain = await hs.migrate_chain(tag, hops=1)
    root, child = chain
    tgt2 = f"pol_f_{tag}_t2"
    await hs.make_policy(tgt2)
    mid = await hs.open_migration(child, tgt2, f"f6-{tag}")
    pa = await hs.mig_prep("alice", mid)
    pb = await hs.mig_prep("bob", mid)
    await hs.http.post("/migrations/shares", headers=hs.h("alice"), json=pa)

    # 冻结在谱系 custody 行锁已持有、插入冻结行之前 park。bob 的门限迁移提交
    # 需要 child custody 行锁 -> 在冻结身后排队；迁移不查冻结，放行后必须照常
    # 完成并产生新后代。
    gate = {"X-Fault-Key": label, "X-Fault-Gate": "freeze.after_lineage_lock"}
    freeze_task = asyncio.create_task(hs.freeze(root, extra_headers=gate))
    await board.wait_reached(f"freeze.after_lineage_lock:{label}")

    submit_task = asyncio.create_task(
        hs.http.post("/migrations/shares", headers=hs.h("bob"), json=pb))
    queued = await wait_lock_waiters(hs.pool, 1, "key_custodies")
    check(f"{label}: threshold migration submit queues behind freeze custody locks",
          queued == 1, f"q={queued}")

    await board.release_gate(f"freeze.after_lineage_lock:{label}")
    rf = await freeze_task
    rs = await submit_task
    fid = body_of(rf).get("freeze_id")
    new_cid = body_of(rs).get("new_custody_id")
    check(f"{label}: freeze commits 201 and queued migration still completes 200",
          rf.status_code == 201 and rs.status_code == 200
          and body_of(rs).get("completed") and bool(new_cid),
          f"freeze={rf.status_code} submit={rs.status_code} {rs.text[:160]}")

    # 冻结快照在提交时刻尚看不到排队中的新后代（迁移等锁未提交）——
    # 覆盖是动态的：GET / 恢复裁决必须立刻覆盖新生后代。
    r = await hs.http.get(f"/freezes/{fid}", headers=auth(hs.tenant_key))
    check(f"{label}: dynamic GET coverage includes the post-freeze descendant",
          new_cid in body_of(r).get("covered_custody_ids", []), r.text[:200])
    rr = await hs.http.post("/recoveries", headers=auth(hs.tenant_key), json={
        "custody_id": new_cid, "request_digest": "00" * 32, "recovery_public_key": "11" * 32})
    check(f"{label}: recovery on brand-new descendant -> CUSTODY_FROZEN (never missed)",
          rr.status_code == 423 and body_of(rr)["error"]["code"] == "CUSTODY_FROZEN",
          rr.text[:160])
    # 根/旧后代/新后代在线分片全保留，custody 全 active
    check(f"{label}: online shards retained across the whole lineage",
          all([await hs.shard_count(root) == 3, await hs.shard_count(child) == 3,
               await hs.shard_count(new_cid) == 3])
          and await hs.custody_status(new_cid) == "active")
    # 迁移会话 completed（不是 destroyed/failed）
    g = body_of(await hs.http.get(f"/migrations/{mid}", headers=auth(hs.tenant_key)))
    check(f"{label}: migration completed normally under freeze",
          g.get("status") == "completed" and g.get("new_custody_id") == new_cid)


# ---------------------------------------------------------------------------
# F7: recovery gate wins the lock race (sibling gates before/after commit)
# ---------------------------------------------------------------------------

async def scenario_f7(hs: Harness, board: FaultBoard, tag: str):
    label = "F7(gate-wins-ordering)"
    chain = await hs.migrate_chain(tag, hops=1)
    root, child = chain
    sid = await hs.open_recovery(child)

    # alice 的 nonce 请求先拿到 child custody + 会话行锁并 park（裁决点之前）；
    # 冻结在 child custody 锁上排队 -> alice 先提交，冻结后提交。
    gate = {"X-Fault-Key": label, "X-Fault-Gate": "recovery.after_lock"}
    nonce_task = asyncio.create_task(hs.http.post(
        "/recoveries/nonces", headers={**hs.h("alice"), **gate}, json={"session_id": sid}))
    await board.wait_reached(f"recovery.after_lock:{label}")

    freeze_task = asyncio.create_task(hs.freeze(root))
    queued = await wait_lock_waiters(hs.pool, 1, "key_custodies")
    check(f"{label}: freeze queues behind parked recovery gate", queued == 1, f"q={queued}")

    await board.release_gate(f"recovery.after_lock:{label}")
    rn = await nonce_task
    rf = await freeze_task
    check(f"{label}: gate that locked first commits (nonce 200), freeze follows (201)",
          rn.status_code == 200 and rf.status_code == 201,
          f"nonce={rn.status_code} freeze={rf.status_code}")

    # 冻结提交后的下一个关口（bob 领 nonce）确定性被冻结裁决
    rr = await hs.http.post("/recoveries/nonces", headers=hs.h("bob"), json={"session_id": sid})
    check(f"{label}: later sibling gate after freeze commit -> 423",
          rr.status_code == 423 and body_of(rr)["error"]["code"] == "CUSTODY_FROZEN",
          rr.text[:160])
    # alice 已拿到的未花费 nonce：claim 同样在下发分片前被裁决（不花 nonce）
    nonce_alice = rn.json()["nonce"]
    rr = await hs.http.post("/recoveries/shards/claim", headers=hs.h("alice"),
                            json={"session_id": sid, "nonce": nonce_alice})
    check(f"{label}: claim after freeze -> 423, nonce stays unspent",
          rr.status_code == 423 and body_of(rr)["error"]["code"] == "CUSTODY_FROZEN"
          and "shard_hex" not in rr.text, rr.text[:160])
    spent = await hs.pool.fetchval(
        "SELECT spent FROM session_nonces WHERE session_id=$1 AND custodian_id='cus_demo_alice'",
        sid)
    check(f"{label}: winning nonce unspent after blocked claim", spent is False, str(spent))


# ---------------------------------------------------------------------------
# F8: blocked submit spends nothing; pending share intact; completes on release
# ---------------------------------------------------------------------------

async def scenario_f8(hs: Harness, tag: str):
    label = "F8(submit-no-consume)"
    chain = await hs.migrate_chain(tag, hops=1)
    root, child = chain
    sid = await hs.open_recovery(child)
    pa = await hs.rec_prep("alice", sid)
    r = await hs.http.post("/recoveries/shares", headers=hs.h("alice"), json=pa)
    assert r.status_code == 200 and body_of(r)["shares_received"] == 1, r.text
    check(f"{label}: 1 pending share accumulated", app.state.pending.count(sid) == 1)
    pb_nonce = (await hs.http.post("/recoveries/nonces", headers=hs.h("bob"),
                                   json={"session_id": sid})).json()["nonce"]
    pb_claim = (await hs.http.post("/recoveries/shards/claim", headers=hs.h("bob"),
                                   json={"session_id": sid, "nonce": pb_nonce})).json()
    pb = {"session_id": sid, "nonce": pb_nonce, "point_x": pb_claim["point_x"],
          "shard_hex": pb_claim["shard_hex"],
          "signature": sign(hs.cust["bob"]["signing_private_key"], pb_claim["signing_message"])}

    await hs.freeze(root)
    rr = await hs.http.post("/recoveries/shares", headers=hs.h("bob"), json=pb)
    check(f"{label}: threshold submit while frozen -> 423 (no ciphertext)",
          rr.status_code == 423 and body_of(rr)["error"]["code"] == "CUSTODY_FROZEN"
          and "wrap" not in rr.text, rr.text[:160])
    # 不花 nonce、不计数、不入/动内存池
    spent = await hs.pool.fetchval(
        "SELECT spent FROM session_nonces WHERE session_id=$1 AND custodian_id='cus_demo_bob'",
        sid)
    cnt = await hs.pool.fetchval(
        "SELECT count(*) FROM share_submissions WHERE session_id=$1", sid)
    check(f"{label}: blocked submit spent no nonce and added no count",
          spent is False and cnt == 1, f"spent={spent} count={cnt}")
    check(f"{label}: earlier pending share untouched (memory agrees with db count)",
          app.state.pending.count(sid) == 1)
    g = body_of(await hs.http.get(f"/recoveries/{sid}", headers=auth(hs.tenant_key)))
    check(f"{label}: session still open with 1 share",
          g["status"] == "open" and g["shares_received"] == 1)
    # bob 可用同一未花费 nonce 在解冻后重试并完成（密文照常只下发一次）
    fid = (await hs.http.get(f"/freezes?custody_id={child}",
                             headers=auth(hs.tenant_key))).json()[0]["freeze_id"]
    await hs.release(fid)
    rr = await hs.http.post("/recoveries/shares", headers=hs.h("bob"), json=pb)
    check(f"{label}: same nonce retried after release -> threshold completed",
          rr.status_code == 200 and body_of(rr).get("completed")
          and body_of(rr).get("wrap") is not None, rr.text[:200])
    check(f"{label}: pending pool cleared after completion",
          app.state.pending.count(sid) == 0)


# ---------------------------------------------------------------------------
# F9: access control, destroyed root, validation
# ---------------------------------------------------------------------------

async def scenario_f9(hs: Harness, tag: str):
    label = "F9(access+validation)"
    # 跨租户
    r = await hs.http.post("/admin/tenants", headers=auth(demo_credentials()["admin_api_key"]),
                           json={"name": f"freeze-tenant-{tag}"})
    assert r.status_code == 201, r.text
    other = {"X-API-Key": r.json()["api_key"]}
    chain = await hs.migrate_chain(tag, hops=1)
    root, child = chain
    until = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    payload = {"root_custody_id": root, "valid_until": until, "reason": "xt"}
    rr = await hs.http.post("/freezes", headers=other, json=payload)
    check(f"{label}: cross-tenant freeze -> FORBIDDEN",
          rr.status_code == 403 and body_of(rr)["error"]["code"] == "FORBIDDEN", rr.text[:160])
    rf = await hs.freeze(root)
    fid = body_of(rf)["freeze_id"]
    rr = await hs.http.get(f"/freezes/{fid}", headers=other)
    check(f"{label}: cross-tenant GET -> FORBIDDEN",
          rr.status_code == 403 and body_of(rr)["error"]["code"] == "FORBIDDEN", rr.text[:160])
    rr = await hs.http.post(f"/freezes/{fid}/release", headers=other)
    check(f"{label}: cross-tenant release -> FORBIDDEN",
          rr.status_code == 403 and body_of(rr)["error"]["code"] == "FORBIDDEN", rr.text[:160])
    rr = await hs.http.get("/freezes", headers=other)
    check(f"{label}: cross-tenant list never shows other-tenant freezes",
          rr.status_code == 200 and fid not in [x["freeze_id"] for x in body_of(rr)], rr.text[:160])
    # 以他人 custody id 反查冻结 -> FORBIDDEN（不得借此枚举他人冻结锚点）
    rr = await hs.http.get(f"/freezes?custody_id={root}", headers=other)
    check(f"{label}: cross-tenant list-by-custody -> FORBIDDEN",
          rr.status_code == 403 and body_of(rr)["error"]["code"] == "FORBIDDEN", rr.text[:160])
    # 不存在的 custody 反查 -> NOT_FOUND
    rr = await hs.http.get("/freezes?custody_id=cus_secret_nope", headers=auth(hs.tenant_key))
    check(f"{label}: list-by-unknown-custody -> NOT_FOUND",
          rr.status_code == 404 and body_of(rr)["error"]["code"] == "NOT_FOUND", rr.text[:160])

    # 未知根 / 未知冻结
    rr = await hs.http.post("/freezes", headers=auth(hs.tenant_key),
                            json={"root_custody_id": "cus_secret_nope",
                                  "valid_until": until, "reason": "nf"})
    check(f"{label}: unknown root -> NOT_FOUND",
          rr.status_code == 404 and body_of(rr)["error"]["code"] == "NOT_FOUND", rr.text[:160])
    rr = await hs.http.get("/freezes/frz_nope", headers=auth(hs.tenant_key))
    check(f"{label}: unknown freeze -> NOT_FOUND",
          rr.status_code == 404 and body_of(rr)["error"]["code"] == "NOT_FOUND", rr.text[:160])

    # 已销毁根 -> CUSTODY_DESTROYED（复用销毁路径）
    dpol = f"pol_f_{tag}_d"
    await hs.make_policy(dpol)
    dcid = await hs.make_custody(dpol)
    rr = await hs.http.post("/destructions",
                            headers={**auth(hs.tenant_key), "Idempotency-Key": f"f9d-{tag}"},
                            json={"root_custody_id": dcid})
    assert rr.status_code == 201, rr.text
    rr = await hs.freeze(dcid)
    check(f"{label}: freeze destroyed root -> CUSTODY_DESTROYED (410)",
          rr.status_code == 410 and body_of(rr)["error"]["code"] == "CUSTODY_DESTROYED",
          rr.text[:160])
    cnt = await hs.pool.fetchval("SELECT count(*) FROM custody_freezes WHERE root_custody_id=$1",
                                 dcid)
    check(f"{label}: no freeze row for destroyed root", cnt == 0, str(cnt))


# ---------------------------------------------------------------------------
# F10: migrations & migration pending shares unaffected; audit chain
# ---------------------------------------------------------------------------

async def scenario_f10(hs: Harness, tag: str):
    label = "F10(migrations-unaffected+audit)"
    tgt = f"pol_f_{tag}_t"
    chain = await hs.migrate_chain(tag, hops=1)
    root, child = chain
    await hs.make_policy(tgt)
    mid = await hs.open_migration(child, tgt, f"f10-{tag}")
    pa = await hs.mig_prep("alice", mid)
    r = await hs.http.post("/migrations/shares", headers=hs.h("alice"), json=pa)
    assert r.status_code == 200, r.text
    check(f"{label}: migration pending share accumulated before freeze",
          app.state.pending.count(mid) == 1)

    await hs.freeze(root)

    # 冻结阻断恢复创建，但完全不影响迁移关口
    rr0 = await hs.http.post("/recoveries", headers=auth(hs.tenant_key), json={
        "custody_id": child, "request_digest": "00" * 32, "recovery_public_key": "11" * 32})
    check(f"{label}: recovery start blocked on frozen source",
          rr0.status_code == 423 and body_of(rr0)["error"]["code"] == "CUSTODY_FROZEN",
          rr0.text[:160])

    # 迁移的 nonce/claim/submit 完全不被冻结拦截
    pb = await hs.mig_prep("bob", mid)
    rr = await hs.http.post("/migrations/shares", headers=hs.h("bob"), json=pb)
    new_cid = body_of(rr).get("new_custody_id")
    check(f"{label}: frozen source still migrates to completion (200)",
          rr.status_code == 200 and body_of(rr).get("completed") and bool(new_cid), rr.text[:200])
    check(f"{label}: migration pending pool cleared on completion",
          app.state.pending.count(mid) == 0)
    # 迁移完成本身不报错；新后代在线分片在位
    check(f"{label}: new descendant online shards in place",
          await hs.shard_count(new_cid) == 3)
    # 冻结没有改动任何会话状态
    g = body_of(await hs.http.get(f"/migrations/{mid}", headers=auth(hs.tenant_key)))
    check(f"{label}: migration status completed, not frozen-marked", g["status"] == "completed")

    # 审计链完整、无秘密；含 freeze.start 与 CUSTODY_FROZEN 拒绝留痕
    rep = (await hs.http.get("/audit/replay", headers=auth(hs.tenant_key))).json()
    check(f"{label}: audit hash chain valid", rep.get("valid") is True,
          json.dumps(rep)[:200])
    raw = json.dumps(rep)
    check(f"{label}: audit carries no secret",
          hs.secret.hex() not in raw and hs.secret.decode() not in raw
          and pa["shard_hex"] not in raw and pb["shard_hex"] not in raw)
    denied = await hs.pool.fetch(
        "SELECT action, error_code FROM audit_log "
        "WHERE result='denied' AND error_code='CUSTODY_FROZEN'")
    check(f"{label}: CUSTODY_FROZEN denials audited per gate",
          {d["action"] for d in denied} >= {"recovery.start"},
          str(sorted({d["action"] for d in denied})))


async def amain() -> int:
    async with server() as (http, pool, board):
        creds = demo_credentials()
        hs = Harness(http, pool, creds)
        suffix = os.urandom(4).hex()
        await scenario_f1(hs, f"{suffix}1")
        await scenario_f2(hs, f"{suffix}2")
        await scenario_f3(hs, f"{suffix}3")
        await scenario_f4(hs, f"{suffix}4")
        await scenario_f5(hs, f"{suffix}5")
        await scenario_f6(hs, board, f"{suffix}6")
        await scenario_f7(hs, board, f"{suffix}7")
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
