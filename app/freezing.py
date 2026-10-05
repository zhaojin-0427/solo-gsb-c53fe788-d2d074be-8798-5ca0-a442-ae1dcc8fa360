"""Time-limited recovery freezes over custody-record lineages (v1.8).

A tenant freezes the **recovery surface** of one root custody record until a
future deadline: the freeze covers the root and **every descendant reachable
along completed migration edges** — both the descendants that already exist
and those produced by migrations completing later. Freezes never block
migrations: a migration still completes normally and its online shards stay in
place. What the freeze adjudicates is recovery — ``POST /recoveries``, nonce
issue, shard claim and share submit each hold the target custody row lock and
call :func:`ensure_not_frozen` **before** issuing a nonce, handing out shard
plaintext or producing the one-time wrapped ciphertext. A blocking freeze
yields a deterministic ``CUSTODY_FROZEN`` (HTTP 423): no nonce is spent, no
share counted, no pending in-memory shard touched.

Lineage coverage is resolved **dynamically** (no per-descendant membership
table): a custody ``c`` is covered iff an active, unexpired freeze is anchored
at ``c`` itself or at any ancestor found by walking completed migration edges
backwards (``migration_sessions.new_custody_id`` → ``source_custody_id``).
That makes a descendant born after the freeze commit covered automatically —
there is no membership row a racing migration could miss.

Transaction ordering follows the single global order already used by logical
destruction and every recovery/migration gate — **custody rows (id order)
before session rows** — and adds no new lock (freeze rows are never taken
before custody rows):

* Freeze creation fixpoint-locks the *currently existing* forward lineage
  exactly like destruction (each round locks newly discovered descendants
  ``ORDER BY id FOR UPDATE`` before following their outgoing edges), then
  inserts the freeze row. A recovery gate therefore either commits before the
  freeze (its verdict and effects are already durable and valid when it ran)
  or queues on the custody lock and, once released, observes the committed
  freeze via :func:`ensure_not_frozen` — a shard/ciphertext can never be
  adjudicated after the freeze without seeing it.
* A migration completing behind a queued freeze is never rejected (migrations
  do not consult freezes): it commits as soon as the freeze releases the
  source lock, and the freeze's next expansion round (or the next dynamic
  gate query) includes the freshly created descendant — no descendant can
  escape the freeze.
* Multiple overlapping freezes simply all match; recovery is allowed only
  once every overlapping freeze is released or expired.

Expiry is automatic (a live verdict uses ``clock_timestamp() < valid_until``);
rows may be flipped to the ``expired`` state lazily on query/release.
"""
from __future__ import annotations

import asyncpg

from . import faults
from .errors import ApiError, E_CUSTODY_FROZEN

#: Recursive-CTE depth cap. Migration lineages are linear chains (one
#: completed out-edge per custody), so this only guards against pathological
#: data far beyond any real deployment.
_MAX_LINEAGE_DEPTH = 10_000


async def lock_forward_lineage(conn: asyncpg.Connection, root_custody_id: str) -> list[str]:
    """Lock the root and every existing completed-migration descendant.

    Fixpoint expansion in the same global order used by logical destruction:
    each round locks the newly discovered custody rows ``ORDER BY id FOR
    UPDATE`` and only then follows their outgoing completed edges. The
    returned list is in discovery order (the caller sorts it when presenting a
    receipt, so output never depends on hash/insertion accidents).

    A migration threshold-submit that commits while we wait on one of these
    row locks is visible to the next expansion round — its new descendant is
    locked before the fixpoint converges, so a freeze committed here can never
    miss a descendant born in the interleaving.
    """
    lineage: list[str] = []
    frontier = [root_custody_id]
    locked: set[str] = set()
    while frontier:
        frontier = sorted(set(frontier) - locked)
        if not frontier:
            break
        rows = await conn.fetch(
            "SELECT id FROM key_custodies WHERE id = ANY($1::text[]) "
            "ORDER BY id FOR UPDATE",
            frontier,
        )
        got = [r["id"] for r in rows]
        locked.update(got)
        lineage.extend(got)
        children = await conn.fetch(
            "SELECT new_custody_id AS cid FROM migration_sessions "
            "WHERE source_custody_id = ANY($1::text[]) "
            "AND new_custody_id IS NOT NULL",
            got,
        )
        frontier = [r["cid"] for r in children if r["cid"] not in locked]
    return lineage


async def list_forward_lineage(conn: asyncpg.Connection, root_custody_id: str) -> list[str]:
    """Dynamic coverage snapshot: root plus all completed-migration descendants."""
    rows = await conn.fetch(
        """
        WITH RECURSIVE lineage(id, depth) AS (
            SELECT $1::text, 0
            UNION
            SELECT m.new_custody_id, l.depth + 1
            FROM migration_sessions m
            JOIN lineage l ON m.source_custody_id = l.id
            WHERE m.new_custody_id IS NOT NULL AND l.depth < $2
        )
        SELECT id FROM lineage ORDER BY depth, id
        """,
        root_custody_id, _MAX_LINEAGE_DEPTH,
    )
    return [r["id"] for r in rows]


async def blocking_freezes(
    conn: asyncpg.Connection, custody_id: str, now
) -> list[asyncpg.Record]:
    """Active, unexpired freezes whose root is ``custody_id`` or any ancestor.

    Ancestry walks *backwards* over completed migration edges: freeze roots
    sitting on any generation of the lineage (root, intermediate record or a
    later descendant that itself became a migration source) cover this
    custody. Rows whose ``valid_until`` has passed are ignored regardless of
    the lazily-maintained ``status`` column, so expiry is always automatic.
    """
    return await conn.fetch(
        """
        WITH RECURSIVE ancestors(id, depth) AS (
            SELECT $2::text, 0
            UNION
            SELECT m.source_custody_id, a.depth + 1
            FROM migration_sessions m
            JOIN ancestors a ON m.new_custody_id = a.id
            WHERE m.new_custody_id IS NOT NULL AND a.depth < $3
        )
        SELECT f.*
        FROM custody_freezes f
        JOIN ancestors a ON a.id = f.root_custody_id
        WHERE f.status = 'active' AND $1::timestamptz < f.valid_until
        ORDER BY f.valid_until ASC, f.id ASC
        """,
        now, custody_id, _MAX_LINEAGE_DEPTH,
    )


async def ensure_not_frozen(
    conn: asyncpg.Connection,
    custody_id: str,
    *,
    now,
    resource_id: str,
    resource_kind: str,
) -> None:
    """Raise ``CUSTODY_FROZEN`` while holding the target custody row lock.

    Must be called inside the gate's own transaction **after** the
    ``key_custodies`` row lock is taken and before any nonce is spent, shard
    plaintext returned or wrapped ciphertext produced. The row lock is what
    orders this verdict against freeze creation: a freeze fixpoint that
    committed first has this custody's lock, so a queued gate cannot reach
    here until the freeze row is visible, and a gate that committed first ran
    before the freeze existed — the only two allowed, deterministic outcomes.
    """
    active = await blocking_freezes(conn, custody_id, now)
    if not active:
        return
    earliest = active[0]
    raise ApiError(
        E_CUSTODY_FROZEN,
        basis={
            "reason": "custody_lineage_frozen",
            "resource_kind": resource_kind,
            "resource_id": resource_id,
            "custody_id": custody_id,
            "freeze_id": earliest["id"],
            "freeze_root_custody_id": earliest["root_custody_id"],
            "freeze_valid_until": str(earliest["valid_until"]),
            # 重叠冻结须全部解除或到期才放行；此处给出仍在生效的覆盖数量。
            "active_freeze_count": len(active),
        },
    )


async def gate_after_lineage_lock(request, lineage: list[str]) -> None:
    """Regression gate: every existing lineage custody row is FOR UPDATE held.

    Pinning here (test builds only) interleaves freeze creation with queued
    recovery gates (which block on the held custody locks) and with a
    threshold migration submit (which blocks on the held source custody lock
    and still completes after the freeze, its new descendant then covered
    dynamically).
    """
    await faults.maybe_park(request, "freeze.after_lineage_lock")
    await faults.maybe_raise(request, "freeze.after_lineage_lock")
