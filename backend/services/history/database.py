"""
SQLite scan history using aiosqlite.

Tables:
  scans    — one row per scan
  signals  — RiskSignal rows (FK → scans.scan_id)
"""
from __future__ import annotations

import json
import os
from typing import Optional

import aiosqlite

_DB_PATH = os.getenv("DB_PATH", "inspector.db")


async def _get_db() -> aiosqlite.Connection:
    db = await aiosqlite.connect(_DB_PATH)
    db.row_factory = aiosqlite.Row
    return db


async def init_db() -> None:
    """Create tables if they don't exist."""
    async with aiosqlite.connect(_DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                scan_id      TEXT PRIMARY KEY,
                created_at   TEXT NOT NULL,
                input_type   TEXT NOT NULL,
                source_name  TEXT,
                domain       TEXT,
                threat_index REAL NOT NULL,
                risk_level   TEXT NOT NULL,
                signal_count INTEGER DEFAULT 0,
                full_result  TEXT   -- JSON blob of full ScanResponse
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS signals (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id    TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
                category   TEXT NOT NULL,
                severity   TEXT NOT NULL,
                score      INTEGER NOT NULL,
                evidence   TEXT,
                explanation TEXT
            )
        """)
        await db.execute("CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC)")
        await db.commit()


async def save_scan(scan_id: str, created_at: str, input_type: str,
                    source_name: Optional[str], domain: Optional[str],
                    threat_index: float, risk_level: str,
                    signals: list[dict], full_result: dict) -> None:
    async with aiosqlite.connect(_DB_PATH) as db:
        await db.execute(
            """INSERT OR REPLACE INTO scans
               (scan_id, created_at, input_type, source_name, domain,
                threat_index, risk_level, signal_count, full_result)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (scan_id, created_at, input_type, source_name, domain,
             threat_index, risk_level, len(signals), json.dumps(full_result))
        )
        for sig in signals:
            await db.execute(
                """INSERT INTO signals (scan_id, category, severity, score, evidence, explanation)
                   VALUES (?,?,?,?,?,?)""",
                (scan_id, sig.get("category"), sig.get("severity"),
                 sig.get("score_contribution", 0), sig.get("evidence"), sig.get("explanation"))
            )
        await db.commit()


async def list_scans(limit: int = 50) -> list[dict]:
    async with aiosqlite.connect(_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            """SELECT scan_id, created_at, input_type, source_name, domain,
                      threat_index, risk_level, signal_count
               FROM scans ORDER BY created_at DESC LIMIT ?""",
            (limit,)
        )
        rows = await cur.fetchall()
        return [dict(r) for r in rows]


async def get_scan(scan_id: str) -> Optional[dict]:
    async with aiosqlite.connect(_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT full_result FROM scans WHERE scan_id = ?", (scan_id,))
        row = await cur.fetchone()
        if not row:
            return None
        return json.loads(row["full_result"])


async def delete_scan(scan_id: str) -> bool:
    async with aiosqlite.connect(_DB_PATH) as db:
        cur = await db.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
        await db.commit()
        return cur.rowcount > 0
