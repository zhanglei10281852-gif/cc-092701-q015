from __future__ import annotations

import json
import sqlite3

from app.repositories.base import rows_dict


class ArchiveRepository:
    """封装资料封存记录的 SQLite 读写。封存记录只插入、不更新、不删除。"""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection

    def by_id(self, archive_id: int) -> sqlite3.Row | None:
        return self.connection.execute("SELECT * FROM archive_snapshots WHERE id=?", (archive_id,)).fetchone()

    def sealed_by_request_key(self, request_key: str) -> sqlite3.Row | None:
        return self.connection.execute(
            "SELECT * FROM archive_snapshots WHERE request_key=? AND status='sealed'", (request_key,)
        ).fetchone()

    def next_version(self, scope_key: str) -> int:
        row = self.connection.execute("SELECT COALESCE(MAX(version),0)+1 FROM archive_snapshots WHERE scope_key=?", (scope_key,)).fetchone()
        return int(row[0])

    def lineage(self, scope_key: str) -> list[dict]:
        rows = self.connection.execute("SELECT * FROM archive_snapshots WHERE scope_key=? ORDER BY id", (scope_key,)).fetchall()
        return rows_dict(rows)

    def list(self, *, status: str | None, limit: int, offset: int) -> list[dict]:
        where = " WHERE status=?" if status else ""
        params: list = [status] if status else []
        params.extend([limit, offset])
        return rows_dict(self.connection.execute(
            "SELECT * FROM archive_snapshots" + where + " ORDER BY id DESC LIMIT ? OFFSET ?", tuple(params)
        ).fetchall())

    def count(self, *, status: str | None) -> int:
        where = " WHERE status=?" if status else ""
        params: tuple = (status,) if status else ()
        return int(self.connection.execute("SELECT COUNT(*) FROM archive_snapshots" + where, params).fetchone()[0])

    def insert_sealed(
        self,
        *,
        scope_key: str,
        request_key: str,
        version: int,
        scope: dict,
        cutoff_at: str,
        policy: dict,
        reason: str,
        payload: dict,
        content_digest: str,
        sources: list[dict],
        stats: dict,
        actor: str,
        actor_user_id: int | None,
        now: str,
    ) -> sqlite3.Row:
        cursor = self.connection.execute(
            "INSERT INTO archive_snapshots(scope_key,request_key,version,scope_json,cutoff_at,policy_json,status,reason,"
            "payload_json,content_digest,sources_json,stats_json,created_by,created_by_user_id,created_at,sealed_at) "
            "VALUES(?,?,?,?,?,?,'sealed',?,?,?,?,?,?,?,?,?)",
            (
                scope_key,
                request_key,
                version,
                json.dumps(scope, ensure_ascii=False, sort_keys=True),
                cutoff_at,
                json.dumps(policy, ensure_ascii=False, sort_keys=True),
                reason,
                json.dumps(payload, ensure_ascii=False, sort_keys=True),
                content_digest,
                json.dumps(sources, ensure_ascii=False, sort_keys=True),
                json.dumps(stats, ensure_ascii=False, sort_keys=True),
                actor,
                actor_user_id,
                now,
                now,
            ),
        )
        return self.by_id(int(cursor.lastrowid))

    def insert_failed(
        self,
        *,
        scope_key: str,
        request_key: str,
        scope: dict,
        cutoff_at: str,
        policy: dict,
        reason: str,
        failure_reason: str,
        actor: str,
        actor_user_id: int | None,
        now: str,
    ) -> sqlite3.Row:
        cursor = self.connection.execute(
            "INSERT INTO archive_snapshots(scope_key,request_key,version,scope_json,cutoff_at,policy_json,status,reason,"
            "failure_reason,created_by,created_by_user_id,created_at) VALUES(?,?,NULL,?,?,?,'failed',?,?,?,?,?)",
            (
                scope_key,
                request_key,
                json.dumps(scope, ensure_ascii=False, sort_keys=True),
                cutoff_at,
                json.dumps(policy, ensure_ascii=False, sort_keys=True),
                reason,
                failure_reason,
                actor,
                actor_user_id,
                now,
            ),
        )
        return self.by_id(int(cursor.lastrowid))
