"""HTTP API for time-limited custody-lineage recovery freezes (v1.8).

Endpoints (tenant-authenticated):

* ``POST /freezes``            — submit a freeze: root custody id, a future
  ``valid_until`` and a reason; returns a queryable ``freeze_id``.
* ``GET  /freezes/{id}``       — query one freeze (effective status + the
  dynamically computed coverage snapshot).
* ``GET  /freezes?custody_id=`` — list the tenant's freezes (optionally those
  anchoring a lineage covering the named custody).
* ``POST /freezes/{id}/release`` — release a freeze early (idempotent).

Freeze creation fixpoint-locks the existing lineage (custody rows in id order,
the global custody-before-session order shared with destruction and every
recovery/migration gate), then inserts the freeze row in the same transaction.
Migrations are not touched by freezes; only recovery gates consult them.
Audit entries carry ids / reason / counts only — never secret material.
"""
from __future__ import annotations

from datetime import timezone

from fastapi import APIRouter, Request

from .. import audit, deps, freezing, repo
from ..config import get_settings
from ..errors import (
    ApiError,
    E_BAD_REQUEST,
    E_CUSTODY_DESTROYED,
    E_FORBIDDEN,
    E_FREEZE_NOT_ACTIVE,
    E_NOT_FOUND,
)
from ..schemas import FreezeCreateIn, FreezeOut, FreezeReleaseOut

router = APIRouter(tags=["freezes"])


async def _effective_status(conn, row, now=None) -> str:
    """Live status: a past valid_until means 'expired' even before lazy flip."""
    if row["status"] == "active":
        if now is None:
            now = await conn.fetchval("SELECT clock_timestamp()")
        if now >= row["valid_until"]:
            return "expired"
    return row["status"]


async def _lazily_expire(conn, row, now) -> bool:
    """Flip one past-deadline active freeze row to expired. Returns True when expired."""
    if row["status"] == "active" and now >= row["valid_until"]:
        await conn.execute(
            "UPDATE custody_freezes SET status='expired' WHERE id=$1 AND status='active'",
            row["id"],
        )
        return True
    return False


async def _freeze_out(conn, row, now) -> FreezeOut:
    status = await _effective_status(conn, row, now)
    covered = await freezing.list_forward_lineage(conn, row["root_custody_id"])
    return FreezeOut(
        freeze_id=row["id"],
        tenant_id=row["tenant_id"],
        root_custody_id=row["root_custody_id"],
        reason=row["reason"],
        status=status,
        valid_until=row["valid_until"],
        created_at=row["created_at"],
        released_at=row["released_at"],
        covered_custody_count=len(covered),
        covered_custody_ids=covered,
    )


@router.post("/freezes", response_model=FreezeOut, status_code=201)
async def create_freeze(body: FreezeCreateIn, request: Request, tenant=deps.Tenant) -> FreezeOut:
    settings = get_settings()
    pool = request.app.state.db.pool
    # 以语句执行时刻（而非事务快照时间）裁决截止时刻：行锁等待期间也不能放行
    # 一个实际上已经到期的冻结。
    async with pool.acquire() as conn:
        try:
            async with conn.transaction():
                # ① 根行锁先于一切：跨租户/不存在/已销毁根在这里裁决；与恢复
                # 创建、销毁、迁移创建同一全局锁序。
                root = await conn.fetchrow(
                    "SELECT * FROM key_custodies WHERE id = $1 FOR UPDATE",
                    body.root_custody_id,
                )
                if root is None:
                    raise ApiError(E_NOT_FOUND, basis={"custody_id": body.root_custody_id})
                if root["tenant_id"] != tenant["id"]:
                    raise ApiError(E_FORBIDDEN,
                                   basis={"reason": "custody_belongs_to_other_tenant"})
                if root["status"] == "destroyed":
                    # 已逻辑销毁的墓碑没有可冻结的恢复面（其恢复请求本就 410）。
                    raise ApiError(
                        E_CUSTODY_DESTROYED,
                        basis={"custody_id": root["id"], "custody_status": root["status"]},
                    )

                # ② 不动点锁定全部已有谱系 custody（id 序，死锁安全）。冻结
                # 不改变任何 custody/shard/session 状态：持锁只为让与恢复关口
                # 的先后确定——本事务提交前排队的恢复请求拿锁后必能看到冻结。
                lineage = await freezing.lock_forward_lineage(conn, root["id"])
                await freezing.gate_after_lineage_lock(request, lineage)

                # ③ 截止时刻以**谱系锁全部持有之后**新取的 clock_timestamp()
                # 裁决：在根行锁/谱系锁上等待过的请求不得用等待前的旧时间把
                # 一个已短于下限（或已过期）的冻结放行入库。
                now = await conn.fetchval("SELECT clock_timestamp()")
                deadline = body.valid_until.astimezone(timezone.utc)
                ttl = (deadline - now).total_seconds()
                if ttl < settings.freeze_min_ttl:
                    raise ApiError(
                        E_BAD_REQUEST,
                        basis={"reason": "valid_until_too_soon",
                               "min_ttl_seconds": settings.freeze_min_ttl,
                               "ttl_seconds": int(ttl)},
                    )
                if ttl > settings.freeze_max_ttl:
                    raise ApiError(
                        E_BAD_REQUEST,
                        basis={"reason": "valid_until_too_far",
                               "max_ttl_seconds": settings.freeze_max_ttl,
                               "ttl_seconds": int(ttl)},
                    )

                freeze_id = deps.new_id("frz")
                await conn.execute(
                    """
                    INSERT INTO custody_freezes
                      (id, tenant_id, root_custody_id, reason, status, valid_until)
                    VALUES ($1, $2, $3, $4, 'active', $5::timestamptz)
                    """,
                    freeze_id, tenant["id"], root["id"], body.reason, deadline,
                )

                # ③ 无明文审计：仅记录 ID/原因/截止/覆盖快照（不含任何分片或秘密）。
                await audit.append_audit(
                    conn, tenant_id=tenant["id"], actor_type="tenant",
                    actor_id=tenant["id"],
                    action="freeze.start", resource=freeze_id, result="ok",
                    basis={
                        "freeze_id": freeze_id,
                        "root_custody_id": root["id"],
                        "reason": body.reason,
                        "valid_until": deadline.isoformat(),
                        "ttl_seconds": int(ttl),
                        "covered_custody_count": len(lineage),
                        "covered_custody_ids": sorted(lineage),
                    },
                )
                row = await conn.fetchrow("SELECT * FROM custody_freezes WHERE id=$1", freeze_id)
                out = await _freeze_out(conn, row, now)
        except ApiError as exc:
            await repo.audit_denied(
                pool, tenant_id=tenant["id"], actor_type="tenant", actor_id=tenant["id"],
                action="freeze.start", resource=body.root_custody_id,
                error_code=exc.code, basis=exc.basis,
            )
            raise
    return out


@router.get("/freezes", response_model=list[FreezeOut])
async def list_freezes(request: Request, custody_id: str | None = None,
                       tenant=deps.Tenant) -> list[FreezeOut]:
    pool = request.app.state.db.pool
    async with pool.acquire() as conn:
        now = await conn.fetchval("SELECT clock_timestamp()")
        if custody_id is None:
            rows = await conn.fetch(
                "SELECT * FROM custody_freezes WHERE tenant_id=$1 ORDER BY created_at DESC, id",
                tenant["id"],
            )
        else:
            # 按 custody 反查：先确认该 custody 属于本租户（再沿祖先链找冻结根），
            # 杜绝以他人 custody id 枚举别人谱系的冻结锚点。
            owner = await conn.fetchval(
                "SELECT tenant_id FROM key_custodies WHERE id=$1", custody_id
            )
            if owner is None:
                raise ApiError(E_NOT_FOUND, basis={"custody_id": custody_id})
            if owner != tenant["id"]:
                raise ApiError(E_FORBIDDEN,
                               basis={"reason": "custody_belongs_to_other_tenant"})
            rows = await conn.fetch(
                """
                WITH RECURSIVE ancestors(id, depth) AS (
                    SELECT $2::text, 0
                    UNION
                    SELECT m.source_custody_id, a.depth + 1
                    FROM migration_sessions m
                    JOIN ancestors a ON m.new_custody_id = a.id
                    WHERE m.new_custody_id IS NOT NULL AND a.depth < 10000
                )
                SELECT f.* FROM custody_freezes f
                JOIN ancestors a ON a.id = f.root_custody_id
                WHERE f.tenant_id=$1
                ORDER BY f.created_at DESC, f.id
                """,
                tenant["id"], custody_id,
            )
        return [await _freeze_out(conn, r, now) for r in rows]


@router.get("/freezes/{freeze_id}", response_model=FreezeOut)
async def get_freeze(freeze_id: str, request: Request, tenant=deps.Tenant) -> FreezeOut:
    pool = request.app.state.db.pool
    async with pool.acquire() as conn:
        now = await conn.fetchval("SELECT clock_timestamp()")
        row = await conn.fetchrow("SELECT * FROM custody_freezes WHERE id=$1", freeze_id)
        if row is None:
            raise ApiError(E_NOT_FOUND, basis={"freeze_id": freeze_id})
        if row["tenant_id"] != tenant["id"]:
            raise ApiError(E_FORBIDDEN, basis={"reason": "freeze_belongs_to_other_tenant"})
        # 查询顺带惰性翻转到期状态（纯运维便利，裁决始终以时间实时判定）。
        await _lazily_expire(conn, row, now)
        row = await conn.fetchrow("SELECT * FROM custody_freezes WHERE id=$1", freeze_id)
        return await _freeze_out(conn, row, now)


@router.post("/freezes/{freeze_id}/release", response_model=FreezeReleaseOut)
async def release_freeze(freeze_id: str, request: Request, tenant=deps.Tenant) -> FreezeReleaseOut:
    """Release a freeze early.

    Idempotent for an already-released freeze (200, the same released_at); an
    expired freeze cannot be released (``FREEZE_NOT_ACTIVE`` 409). Overlapping
    freezes are independent: every one must be released or expire before
    recovery is allowed again.
    """
    pool = request.app.state.db.pool
    async with pool.acquire() as conn:
        try:
            async with conn.transaction():
                row = await conn.fetchrow(
                    "SELECT * FROM custody_freezes WHERE id=$1 FOR UPDATE", freeze_id
                )
                if row is None:
                    raise ApiError(E_NOT_FOUND, basis={"freeze_id": freeze_id})
                if row["tenant_id"] != tenant["id"]:
                    raise ApiError(E_FORBIDDEN, basis={"reason": "freeze_belongs_to_other_tenant"})
                now = await conn.fetchval("SELECT clock_timestamp()")
                if row["status"] == "released":
                    # 幂等：重复解除直接返回同一份结果，不重复留痕。
                    return FreezeReleaseOut(
                        freeze_id=row["id"], status="released",
                        root_custody_id=row["root_custody_id"],
                        valid_until=row["valid_until"], created_at=row["created_at"],
                        released_at=row["released_at"],
                    )
                if row["status"] == "expired" or now >= row["valid_until"]:
                    # 已到期（无论惰性翻转是否已发生）均不可解除，随事务回滚；
                    # 状态翻转由 GET 等路径惰性持久化，裁决本身始终按
                    # clock_timestamp() 实时判定，回滚不影响“已到期”的事实。
                    raise ApiError(
                        E_FREEZE_NOT_ACTIVE,
                        basis={"freeze_id": freeze_id, "reason": "freeze_expired",
                               "valid_until": str(row["valid_until"]), "now": str(now)},
                    )
                await conn.execute(
                    "UPDATE custody_freezes SET status='released', released_at=$2 "
                    "WHERE id=$1",
                    freeze_id, now,
                )
                await audit.append_audit(
                    conn, tenant_id=tenant["id"], actor_type="tenant",
                    actor_id=tenant["id"],
                    action="freeze.release", resource=freeze_id, result="ok",
                    basis={"freeze_id": freeze_id,
                           "root_custody_id": row["root_custody_id"],
                           "valid_until": str(row["valid_until"]),
                           "released_at": str(now)},
                )
                final = await conn.fetchrow(
                    "SELECT * FROM custody_freezes WHERE id=$1", freeze_id
                )
        except ApiError as exc:
            await repo.audit_denied(
                pool, tenant_id=tenant["id"], actor_type="tenant", actor_id=tenant["id"],
                action="freeze.release", resource=freeze_id,
                error_code=exc.code, basis=exc.basis,
            )
            raise
    return FreezeReleaseOut(
        freeze_id=final["id"], status="released",
        root_custody_id=final["root_custody_id"],
        valid_until=final["valid_until"], created_at=final["created_at"],
        released_at=final["released_at"],
    )
