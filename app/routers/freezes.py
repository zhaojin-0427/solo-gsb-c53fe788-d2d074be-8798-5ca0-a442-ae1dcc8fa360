"""Time-limited recovery freezes over a custody lineage (v1.8).

A tenant submits a **root** custody record, a **future** ``valid_until``
deadline and a free-text ``reason``; the service persists the freeze in one
transaction and returns a queryable ``freeze_id``.

Coverage semantics
------------------
A freeze covers the root, every descendant already produced by completed
migrations, **and every descendant a future migration produces** — migrations
are never blocked by a freeze and always complete normally; online encrypted
shards are always retained. Coverage is evaluated *dynamically* by walking the
completed-migration edges (``migration_sessions.new_custody_id``) at
adjudication time, so no materialized descendant mapping is needed and a
migration-produced child can never escape the freeze. The freeze record also
keeps a ``custody_ids`` snapshot of the lineage locked at commit time, purely
for query/display.

Enforcement
-----------
Recovery creation, nonce issue, shard claim and share submit all adjudicate an
active freeze **before** issuing a nonce, handing out shard plaintext or
producing the one-time wrapped ciphertext (``repo.freeze_active_or_raise``),
while holding the same custody-before-session row locks used everywhere else.
A blocked request returns ``CUSTODY_FROZEN`` (HTTP 423) with **no side
effects**: the nonce is not spent, no share is counted and no in-memory pending
share is inserted (the check runs before every one of those writes).

Transaction ordering / lock discipline
--------------------------------------
Freeze creation reuses destruction's fixed-point lineage expansion (custody
rows locked by id before any session row), so freeze commit versus migration
completion has a deterministic order with no lock-order inversion: if a
migration commits first, the freeze's next expansion round reaches its new
descendant and the snapshot/locks include it; if the freeze locks the lineage
first, recovery gates queue behind the custody lock and, once it commits, only
observe the freeze. Freezes never roll a migration back and never delete or
rewrite any custody, shard or migration row.

Lifecycle
---------
Freezes can be **released early** (``POST /freezes/{id}/release``); an
already-expired freeze at release is reported ``effective=expired`` without
mutation. Expiry otherwise needs no sweeper — every gate judges
``valid_until > clock_timestamp()`` and GET presents stale ``active`` rows as
``effective=expired``. **Overlapping** freezes on the same lineage stack: a
custody stays frozen until *every* covering freeze is released or has expired.
After release/expiry, old sessions remain bound by the usual expiry, revocation
and destruction rules (those guards are unaffected). Cross-tenant callers and
already-destroyed roots are rejected; audit rows never contain secrets.
"""
from __future__ import annotations

import json

from fastapi import APIRouter, Query, Request

from .. import audit, deps, faults, repo
from ..config import get_settings
from ..errors import ApiError, E_BAD_REQUEST, E_FORBIDDEN, E_NOT_FOUND
from ..schemas import FreezeOut, FreezeReleaseOut, FreezeStartIn

router = APIRouter(tags=["freezes"])


def _custody_ids(row) -> list[str]:
    ids = row["custody_ids"]
    if isinstance(ids, str):
        ids = json.loads(ids)
    return list(ids or [])


def _effective(row, now) -> str:
    if row["status"] == "released":
        return "released"
    return "active" if now < row["valid_until"] else "expired"


def _freeze_out(row, now) -> FreezeOut:
    return FreezeOut(
        freeze_id=row["id"],
        root_custody_id=row["root_custody_id"],
        status=row["status"],
        effective=_effective(row, now),
        reason=row["reason"],
        valid_until=row["valid_until"],
        created_at=row["created_at"],
        released_at=row["released_at"],
        custody_ids=_custody_ids(row),
        custody_count=len(_custody_ids(row)),
    )


@router.post("/freezes", response_model=FreezeOut, status_code=201)
async def create_freeze(body: FreezeStartIn, request: Request, tenant=deps.Tenant) -> FreezeOut:
    settings = get_settings()
    pool = request.app.state.db.pool
    async with pool.acquire() as conn:
        try:
            async with conn.transaction():
                # 截止时间以核对时刻新取的实时时间判定（绝不信任请求解析阶段
                # 的墙上时钟），且必须落在 [min, max] 时长窗口内。
                now = await conn.fetchval("SELECT clock_timestamp()")
                window = body.valid_until - now
                window_seconds = int(window.total_seconds())
                if window_seconds < settings.freeze_min_seconds:
                    raise ApiError(
                        E_BAD_REQUEST,
                        basis={"reason": "valid_until_not_far_enough_in_future",
                               "min_seconds": settings.freeze_min_seconds,
                               "valid_until": body.valid_until.isoformat(),
                               "now": now.isoformat()},
                    )
                if window_seconds > settings.freeze_max_seconds:
                    raise ApiError(
                        E_BAD_REQUEST,
                        basis={"reason": "valid_until_too_far_in_future",
                               "max_seconds": settings.freeze_max_seconds,
                               "valid_until": body.valid_until.isoformat()},
                    )

                # ① 根托管记录行锁：跨租户/未知根/已销毁根都在锁内裁决。
                root = await conn.fetchrow(
                    "SELECT * FROM key_custodies WHERE id = $1 FOR UPDATE", body.root_custody_id
                )
                if root is None:
                    raise ApiError(E_NOT_FOUND, basis={"custody_id": body.root_custody_id})
                if root["tenant_id"] != tenant["id"]:
                    raise ApiError(E_FORBIDDEN,
                                   basis={"reason": "custody_belongs_to_other_tenant"})
                # 已逻辑销毁的墓碑（在线分片已删除）没有可冻结的在线恢复面，
                # 冻结它没有意义且会与销毁语义混淆，确定性拒绝。
                if root["status"] == "destroyed":
                    from ..errors import E_CUSTODY_DESTROYED

                    raise ApiError(
                        E_CUSTODY_DESTROYED,
                        basis={"custody_id": root["id"], "custody_status": root["status"],
                               "reason": "cannot_freeze_destroyed_custody"},
                    )

                # 回归闸门：根行锁已持有、谱系展开之前（仅测试构建启用）。
                # 钉住“谱系上一次迁移正在提交临界区”的交错——迁移先提交则
                # 下一轮展开必须把新生后代纳入，绝不漏冻。
                await faults.maybe_park(request, "freeze.after_root_lock")
                await faults.maybe_raise(request, "freeze.after_root_lock")

                # ② 谱系展开 + 锁定（与逻辑销毁同一不动点、同一全局锁序：
                #    custody 行按 id 先于会话行）。冻结不改写/不删除任何行，
                #    这些锁只用于与迁移完成、恢复创建裁决确定先后：迁移先
                #    提交的后代在新一轮展开中必被纳入（绝不漏冻）。
                lineage = await repo.lock_lineage_forward(conn, root["id"])

                # 回归闸门：谱系 custody 行锁全部持有、冻结行尚未写入。
                await faults.maybe_park(request, "freeze.after_lineage_lock")
                await faults.maybe_raise(request, "freeze.after_lineage_lock")

                freeze_id = deps.new_id("frz")
                await conn.execute(
                    """
                    INSERT INTO custody_freezes
                      (id, tenant_id, root_custody_id, reason, valid_until,
                       status, custody_ids)
                    VALUES ($1,$2,$3,$4,$5,'active',$6::jsonb)
                    """,
                    freeze_id, tenant["id"], root["id"], body.reason,
                    body.valid_until, json.dumps(lineage),
                )

                # 可重放审计：只有 ID/截止时间/原因/谱系 id，绝无秘密；
                # reason 还会经 append_audit 的秘密字段名二次过滤。
                await audit.append_audit(
                    conn, tenant_id=tenant["id"], actor_type="tenant",
                    actor_id=tenant["id"],
                    action="freeze.create", resource=freeze_id, result="ok",
                    basis={
                        "freeze_id": freeze_id,
                        "root_custody_id": root["id"],
                        "valid_until": body.valid_until.isoformat(),
                        "custody_count": len(lineage),
                        "custody_ids": lineage,
                        "coverage": "dynamic_lineage",
                        "reason": body.reason,
                    },
                )
                row = await conn.fetchrow("SELECT * FROM custody_freezes WHERE id=$1", freeze_id)
                now2 = await conn.fetchval("SELECT clock_timestamp()")
        except ApiError as exc:
            await repo.audit_denied(
                pool, tenant_id=tenant["id"], actor_type="tenant", actor_id=tenant["id"],
                action="freeze.create", resource=body.root_custody_id,
                error_code=exc.code, basis=exc.basis,
            )
            raise
    return _freeze_out(row, now2)


@router.get("/freezes", response_model=list[FreezeOut])
async def list_freezes(
    request: Request,
    root_custody_id: str | None = Query(default=None, max_length=128),
    status: str | None = Query(default=None, pattern="^(active|released|expired)$"),
    tenant=deps.Tenant,
) -> list[FreezeOut]:
    pool = request.app.state.db.pool
    async with pool.acquire() as conn:
        now = await conn.fetchval("SELECT clock_timestamp()")
        rows = await conn.fetch(
            "SELECT * FROM custody_freezes WHERE tenant_id=$1 ORDER BY created_at DESC, id",
            tenant["id"],
        )
        out = [_freeze_out(r, now) for r in rows]
    if root_custody_id is not None:
        out = [f for f in out if f.root_custody_id == root_custody_id]
    if status is not None:
        # expired 是查询时刻派生状态（active 行过了 valid_until）。
        out = [f for f in out if f.effective == status]
    return out


@router.get("/freezes/{freeze_id}", response_model=FreezeOut)
async def get_freeze(freeze_id: str, request: Request, tenant=deps.Tenant) -> FreezeOut:
    pool = request.app.state.db.pool
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM custody_freezes WHERE id=$1", freeze_id)
        if row is None:
            raise ApiError(E_NOT_FOUND, basis={"freeze_id": freeze_id})
        if row["tenant_id"] != tenant["id"]:
            raise ApiError(E_FORBIDDEN, basis={"reason": "freeze_belongs_to_other_tenant"})
        now = await conn.fetchval("SELECT clock_timestamp()")
    return _freeze_out(row, now)


@router.post("/freezes/{freeze_id}/release", response_model=FreezeReleaseOut)
async def release_freeze(freeze_id: str, request: Request, tenant=deps.Tenant) -> FreezeReleaseOut:
    pool = request.app.state.db.pool
    async with pool.acquire() as conn:
        try:
            async with conn.transaction():
                # 冻结行自身 FOR UPDATE：并发解除彼此串行，状态转换只发生一次。
                row = await conn.fetchrow(
                    "SELECT * FROM custody_freezes WHERE id=$1 FOR UPDATE", freeze_id
                )
                if row is None:
                    raise ApiError(E_NOT_FOUND, basis={"freeze_id": freeze_id})
                if row["tenant_id"] != tenant["id"]:
                    raise ApiError(E_FORBIDDEN, basis={"reason": "freeze_belongs_to_other_tenant"})
                now = await conn.fetchval("SELECT clock_timestamp()")
                ids = _custody_ids(row)

                # 已解除：幂等返回当前形态（不重复留痕）。
                if row["status"] == "released":
                    result_row, effective = row, "released"
                elif now >= row["valid_until"]:
                    # 已到期：不回写 released，呈现 expired；放行本就已生效。
                    result_row, effective = row, "expired"
                else:
                    updated = await conn.fetchrow(
                        "UPDATE custody_freezes SET status='released', released_at=now() "
                        "WHERE id=$1 RETURNING *",
                        freeze_id,
                    )
                    await audit.append_audit(
                        conn, tenant_id=tenant["id"], actor_type="tenant",
                        actor_id=tenant["id"],
                        action="freeze.release", resource=freeze_id, result="ok",
                        basis={
                            "freeze_id": freeze_id,
                            "root_custody_id": row["root_custody_id"],
                            "valid_until": row["valid_until"].isoformat(),
                            "custody_count": len(ids),
                            "custody_ids": ids,
                        },
                    )
                    now = await conn.fetchval("SELECT clock_timestamp()")
                    result_row, effective = updated, "released"
        except ApiError as exc:
            await repo.audit_denied(
                pool, tenant_id=tenant["id"], actor_type="tenant", actor_id=tenant["id"],
                action="freeze.release", resource=freeze_id,
                error_code=exc.code, basis=exc.basis,
            )
            raise

    return FreezeReleaseOut(
        freeze_id=result_row["id"],
        root_custody_id=result_row["root_custody_id"],
        status=result_row["status"],
        effective=effective,
        reason=result_row["reason"],
        valid_until=result_row["valid_until"],
        created_at=result_row["created_at"],
        released_at=result_row["released_at"],
        custody_ids=ids,
        custody_count=len(ids),
    )
