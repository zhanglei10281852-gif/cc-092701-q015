from __future__ import annotations

import json
import sqlite3
from typing import Any

MASKED_COLUMNS_SQL = "id,source_table,source_id,revision,source_created_at,payload_json,item_digest,frozen_at"

# 与封存写入顺序保持一致，保证内容摘要逐字节可复现。
SOURCE_ORDER_SQL = (
    "CASE source_table WHEN 'compute_templates' THEN 0 WHEN 'compute_tasks' THEN 1 "
    "WHEN 'compute_results' THEN 2 WHEN 'compute_interventions' THEN 3 WHEN 'users' THEN 4 ELSE 5 END"
)


class ArchiveRepository:
    """封存元数据与冻结副本的 SQLite 读写。"""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection

    def insert_archive(
        self,
        *,
        archive_code: str,
        scope: str,
        scope_value: str | None,
        cutoff_at: str,
        masking_policy: str,
        rule_version: int,
        request_fingerprint: str,
        status: str,
        label: str,
        requested_by_user_id: int | None,
        requested_by_name: str,
        caller_permissions: list[str],
        now: str,
    ) -> int:
        cursor = self.connection.execute(
            "INSERT INTO archives(archive_code,scope,scope_value,cutoff_at,masking_policy,rule_version,"
            "request_fingerprint,status,label,requested_by_user_id,requested_by_name,caller_permissions_json,"
            "created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                archive_code, scope, scope_value, cutoff_at, masking_policy, rule_version,
                request_fingerprint, status, label, requested_by_user_id, requested_by_name,
                json.dumps(caller_permissions, ensure_ascii=False), now, now,
            ),
        )
        return int(cursor.lastrowid)

    def by_id(self, archive_id: int) -> sqlite3.Row | None:
        return self.connection.execute("SELECT * FROM archives WHERE id=?", (archive_id,)).fetchone()

    def require(self, archive_id: int) -> sqlite3.Row:
        row = self.by_id(archive_id)
        if row is None:
            from app.core.errors import NotFoundError

            raise NotFoundError("资料封存不存在")
        return row

    def sealed_by_fingerprint(self, fingerprint: str) -> sqlite3.Row | None:
        return self.connection.execute(
            "SELECT * FROM archives WHERE request_fingerprint=? AND status='sealed'",
            (fingerprint,),
        ).fetchone()

    def latest_failed(self, fingerprint: str) -> sqlite3.Row | None:
        return self.connection.execute(
            "SELECT * FROM archives WHERE request_fingerprint=? AND status='failed' ORDER BY id DESC LIMIT 1",
            (fingerprint,),
        ).fetchone()

    def list_archives(self, *, scope: str | None, status: str | None, limit: int, offset: int) -> list[sqlite3.Row]:
        clauses: list[str] = []
        params: list[Any] = []
        if scope:
            clauses.append("scope=?")
            params.append(scope)
        if status:
            clauses.append("status=?")
            params.append(status)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        params.extend([limit, offset])
        return self.connection.execute(
            "SELECT * FROM archives" + where + " ORDER BY id DESC LIMIT ? OFFSET ?",
            tuple(params),
        ).fetchall()

    def count_archives(self, *, scope: str | None, status: str | None) -> int:
        clauses: list[str] = []
        params: list[Any] = []
        if scope:
            clauses.append("scope=?")
            params.append(scope)
        if status:
            clauses.append("status=?")
            params.append(status)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        return int(self.connection.execute("SELECT COUNT(*) FROM archives" + where, tuple(params)).fetchone()[0])

    def sibling_versions(self, scope: str, scope_value: str | None, masking_policy: str) -> list[sqlite3.Row]:
        """同一逻辑范围（忽略截止时刻与规则版本）的全部封存，用于解释边界版本。"""
        clauses = ["scope=?", "masking_policy=?"]
        params: list[Any] = [scope, masking_policy]
        if scope_value is None:
            clauses.append("scope_value IS NULL")
        else:
            clauses.append("scope_value=?")
            params.append(scope_value)
        return self.connection.execute(
            "SELECT * FROM archives WHERE " + " AND ".join(clauses) + " ORDER BY cutoff_at,rule_version,id",
            tuple(params),
        ).fetchall()

    def insert_item(
        self,
        *,
        archive_id: int,
        source_table: str,
        source_id: str,
        source_created_at: str | None,
        payload: dict[str, Any],
        item_digest: str,
        frozen_at: str,
    ) -> None:
        self.connection.execute(
            "INSERT INTO archive_items(archive_id,source_table,source_id,revision,source_created_at,"
            "payload_json,item_digest,frozen_at) VALUES(?,?,?,1,?,?,?,?)",
            (
                archive_id, source_table, str(source_id), source_created_at,
                json.dumps(payload, ensure_ascii=False, sort_keys=True), item_digest, frozen_at,
            ),
        )

    def items_of(self, archive_id: int) -> list[sqlite3.Row]:
        return self.connection.execute(
            f"SELECT {MASKED_COLUMNS_SQL} FROM archive_items WHERE archive_id=? "
            f"ORDER BY {SOURCE_ORDER_SQL},id",
            (archive_id,),
        ).fetchall()

    def count_items(self, archive_id: int) -> int:
        return int(self.connection.execute(
            "SELECT COUNT(*) FROM archive_items WHERE archive_id=?", (archive_id,)
        ).fetchone()[0])

    def seal(
        self,
        archive_id: int,
        *,
        manifest: dict[str, Any],
        counts: dict[str, Any],
        content_digest: str,
        built_at: str,
    ) -> None:
        self.connection.execute(
            "UPDATE archives SET status='sealed',source_manifest_json=?,counts_json=?,content_digest=?,"
            "built_at=?,failure_code=NULL,failure_reason=NULL,failure_context_json=NULL,updated_at=? WHERE id=?",
            (
                json.dumps(manifest, ensure_ascii=False, sort_keys=True),
                json.dumps(counts, ensure_ascii=False, sort_keys=True),
                content_digest, built_at, built_at, archive_id,
            ),
        )

    def mark_failed(self, archive_id: int, *, code: str, reason: str, context: dict[str, Any], now: str) -> None:
        self.connection.execute(
            "UPDATE archives SET status='failed',failure_code=?,failure_reason=?,failure_context_json=?,"
            "content_digest=NULL,source_manifest_json=NULL,counts_json=NULL,built_at=NULL,updated_at=? WHERE id=?",
            (code, reason[:1000], json.dumps(context, ensure_ascii=False, sort_keys=True), now, archive_id),
        )

    def delete_archive(self, archive_id: int) -> None:
        self.connection.execute("DELETE FROM archives WHERE id=?", (archive_id,))
