from __future__ import annotations

from typing import Any

import asyncpg

from . import audit
from .errors import ApiError, E_CUSTODY_FROZEN


async def audit_denied(
    pool: asyncpg.Pool,
    *,
    tenant_id: str | None,
    actor_type: str,
    actor_id: str | None,
    action: str,
    resource: str | None,
    error_code: str,
    basis: dict[str, Any],
) -> None:
    """Record a rejected action in its own transaction (never blocks the rollback)."""
    try:
        async with pool.acquire() as conn:
            async with conn.transaction():
                await audit.append_audit(
                    conn,
                    tenant_id=tenant_id,
                    actor_type=actor_type,
                    actor_id=actor_id,
                    action=action,
                    resource=resource,
                    result="denied",
                    error_code=error_code,
                    basis=basis,
                )
    except Exception:  # auditing failure must not mask the original error
        pass


async def resolve_custodian_ids(conn: asyncpg.Connection, ids: list[str]) -> None:
    rows = await conn.fetch("SELECT id FROM custodians WHERE id = ANY($1::text[])", ids)
    found = {r["id"] for r in rows}
    missing = sorted(set(ids) - found)
    if missing or len(ids) != len(set(ids)):
        from .errors import ApiError, E_BAD_REQUEST

        raise ApiError(
            E_BAD_REQUEST,
            basis={"unknown_custodian_ids": missing, "duplicate": len(ids) != len(set(ids))},
        )


async def get_policy_version(
    conn: asyncpg.Connection, policy_id: str, version: int
) -> asyncpg.Record | None:
    return await conn.fetchrow("SELECT * FROM policies WHERE id = $1 AND version = $2", policy_id, version)


async def get_head_version(conn: asyncpg.Connection, policy_id: str) -> int | None:
    row = await conn.fetchrow("SELECT current_version FROM policy_heads WHERE policy_id = $1", policy_id)
    return row["current_version"] if row else None


# ---------------------------------------------------------------------------
# Time-limited recovery freezes (v1.8)
# ---------------------------------------------------------------------------

async def lock_lineage_forward(conn: asyncpg.Connection, root_custody_id: str) -> list[str]:
    """Lock a root and every descendant reachable via completed migration edges.

    Mirrors the fixed-point expansion used by logical destruction: each round
    ``SELECT … FOR UPDATE`` locks the newly discovered descendant custody rows
    in id order before following their outgoing completed migration edges,
    until the set converges. This shares the single global lock order
    (**custody rows by id, before session rows by id**) with migration
    completion, shard claim and share submission, so a freeze commit versus a
    concurrent migration can never deadlock:

    * a migration completing first commits its new custody before the freeze's
      next expansion round, which then reaches and locks the fresh descendant
      (the freeze therefore always *covers* every migration-produced child);
    * a freeze holding the lineage locks first merely blocks — it never rolls
      a migration back; once the freeze commits, later recovery gates on the
      new descendant observe the freeze via the dynamic ancestor lookup.
    """
    lineage: list[str] = []
    frontier = [root_custody_id]
    locked: set[str] = set()
    while frontier:
        frontier = sorted(set(frontier) - locked)
        if not frontier:
            break
        rows = await conn.fetch(
            "SELECT id FROM key_custodies WHERE id = ANY($1::text[]) ORDER BY id FOR UPDATE",
            frontier,
        )
        got = [r["id"] for r in rows]
        locked.update(got)
        lineage.extend(got)
        children = await conn.fetch(
            "SELECT new_custody_id AS cid FROM migration_sessions "
            "WHERE source_custody_id = ANY($1::text[]) AND new_custody_id IS NOT NULL",
            got,
        )
        frontier = [r["cid"] for r in children if r["cid"] not in locked]
    return lineage


async def find_active_freeze(
    conn: asyncpg.Connection,
    *,
    tenant_id: str,
    custody_id: str,
    now: Any,
    lock: str = "none",
) -> asyncpg.Record | None:
    """Return an active, unexpired freeze covering ``custody_id`` or ``None``.

    Coverage is evaluated **dynamically** against the committed completed
    migration graph — a custody is covered when it is the freeze root itself or
    any of its forward descendants — so descendants produced by migrations that
    complete after the freeze commit are covered without a stored mapping.

    ``lock`` is ``"none"`` for read-only gates (recovery create / nonce / claim
    / submit, which already hold the target custody ``FOR UPDATE``) or
    ``"update"`` when the caller is about to release the freeze row.
    """
    suffix = " FOR UPDATE" if lock == "update" else ""
    return await conn.fetchrow(
        f"""
        SELECT f.*
        FROM custody_freezes f
        WHERE f.tenant_id = $1
          AND f.status = 'active'
          AND f.valid_until > $2
          AND (
                f.root_custody_id = $3
             OR EXISTS (
                    WITH RECURSIVE anc(cid) AS (
                        SELECT $3
                        UNION ALL
                        SELECT m.source_custody_id
                        FROM migration_sessions m
                        JOIN anc a ON m.new_custody_id = a.cid
                        WHERE m.new_custody_id IS NOT NULL
                    )
                    CYCLE cid SET is_cycle USING path
                    SELECT 1 FROM anc WHERE cid = f.root_custody_id
                )
          )
        ORDER BY f.created_at DESC, f.id
        LIMIT 1{suffix}
        """,
        tenant_id, now, custody_id,
    )


async def freeze_active_or_raise(
    conn: asyncpg.Connection,
    *,
    tenant_id: str,
    custody_id: str,
    now: Any,
    session_id: str | None = None,
    migration_id: str | None = None,
) -> None:
    """Adjudicate a recovery gate: raise CUSTODY_FROZEN before any shard/ciphertext.

    Called by recovery creation, nonce issue, shard claim and share submit
    while the custody row lock (and, for gates, the session row lock) are held.
    A committed freeze is therefore always observed here; a freeze committing
    afterwards waits on those same locks and sees only transactions that have
    not yet emitted a shard or the one-time ciphertext.
    """
    fz = await find_active_freeze(conn, tenant_id=tenant_id, custody_id=custody_id, now=now)
    if fz is not None:
        raise ApiError(
            E_CUSTODY_FROZEN,
            basis={
                "freeze_id": fz["id"],
                "root_custody_id": fz["root_custody_id"],
                "custody_id": custody_id,
                "valid_until": fz["valid_until"].isoformat(),
                **({"session_id": session_id} if session_id is not None else {}),
                **({"migration_id": migration_id} if migration_id is not None else {}),
                "reason": "active_recovery_freeze",
            },
        )
