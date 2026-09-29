from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
from typing import Any

from app.archives.masking import MaskingStrategy
from app.archives.repository import ArchiveRepository
from app.archives.schema import (
    CUTOFF_RULE,
    RULE_VERSION,
    SCOPE_TABLES,
    TABLE_TITLES,
    canonical_request,
    scope_predicate,
)
from app.core.clock import Clock, SystemClock, from_storage, to_storage
from app.core.errors import (
    ConflictError,
    DomainError,
    PermissionDeniedError,
    ValidationError,
)
from app.core.security import Principal
from app.database import get_connection, transaction
from app.services.audit import AuditContext, AuditService

# 冻结时按固定顺序抽取来源，保证同一批数据的摘要逐字节可复现。
SOURCE_ORDER = ("compute_templates", "compute_tasks", "compute_results", "compute_interventions", "users")

# 业务表中以 JSON 原文存储的列，冻结时解析为结构化值，便于脱敏与核对。
JSON_COLUMNS: dict[str, tuple[str, ...]] = {
    "compute_templates": ("parameter_schema_json", "default_parameters_json"),
    "compute_tasks": ("parameters_json",),
    "compute_results": ("result_json", "metrics_json"),
    "compute_interventions": ("before_json", "after_json"),
}

CONTENT_KEYS = {
    "compute_templates": "course_templates",
    "compute_tasks": "submissions",
    "compute_results": "grade_releases",
    "compute_interventions": "interventions",
    "users": "directory",
}

# 任何脱敏策略下都不允许进入封存的凭据字段。
NEVER_FREEZE_KEYS = {"password_hash"}


class ArchiveGenerationError(DomainError):
    status_code = 500
    code = "archive_generation_failed"


def _fingerprint(spec: dict[str, Any]) -> str:
    compact = json.dumps(canonical_request(spec), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(compact.encode()).hexdigest()


def _item_digest(source_table: str, source_id: str, payload: dict[str, Any]) -> str:
    compact = json.dumps(
        {"source_table": source_table, "source_id": str(source_id), "payload": payload},
        ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    )
    return hashlib.sha256(compact.encode()).hexdigest()


def _index_digest(spec: dict[str, Any], digest_index: list[dict[str, str]]) -> str:
    payload = {
        "rule_version": spec["rule_version"],
        "scope": spec["scope"],
        "scope_value": spec["scope_value"],
        "cutoff_at": spec["cutoff_at"],
        "masking_policy": spec["masking_policy"],
        "items": digest_index,
    }
    compact = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(compact.encode()).hexdigest()


def _parse_json_columns(source_table: str, row: sqlite3.Row) -> dict[str, Any]:
    record = dict(row)
    for column in JSON_COLUMNS.get(source_table, ()):
        raw = record.get(column)
        if isinstance(raw, str):
            try:
                record[column] = json.loads(raw)
            except json.JSONDecodeError:
                pass
    for key in NEVER_FREEZE_KEYS:
        record.pop(key, None)
    return record


class ArchiveService:
    """按范围与截止时刻生成、复用、解释和下载不可变资料封存。"""

    def __init__(self, connection: sqlite3.Connection | None = None, clock: Clock | None = None) -> None:
        self.connection = connection or get_connection()
        self.clock = clock or SystemClock()

    # ---------------------------------------------------------------- 请求

    def create_or_reuse(self, principal: Principal, payload: dict[str, Any]) -> dict[str, Any]:
        principal.require("archives.read")
        spec = self._normalize_spec(payload)
        strategy = self._resolve_strategy(principal, spec["masking_policy"])
        spec["masking_policy"] = strategy.policy
        spec["rule_version"] = RULE_VERSION
        fingerprint = _fingerprint(spec)

        with transaction(immediate=True) as connection:
            repository = ArchiveRepository(connection)
            existing = repository.sealed_by_fingerprint(fingerprint)
            if existing is not None:
                return self._detail(existing, reused=True)
            building = connection.execute(
                "SELECT id,created_at FROM archives WHERE request_fingerprint=? AND status='building' ORDER BY id LIMIT 1",
                (fingerprint,),
            ).fetchone()
            if building is not None:
                # 生成是同步短事务，building 行只可能来自进程崩溃；超过 10 分钟即收口为失败并允许重建。
                created = from_storage(building["created_at"])
                if created is None or (self.clock.now() - created).total_seconds() > 600:
                    repository.mark_failed(
                        int(building["id"]), code="interrupted",
                        reason="封存生成进程中断，未完成的半成品已作废", context={"interrupted": True},
                        now=to_storage(self.clock.now()),
                    )
                else:
                    raise ConflictError("相同范围的封存正在生成中，请稍后通过状态接口查询")
            archive_id = self._insert_building(connection, principal, spec, fingerprint)

        # 生成过程独立事务：任何异常都整体回滚，副本不会留下半成品。
        try:
            with transaction(immediate=True) as connection:
                repository = ArchiveRepository(connection)
                manifest, counts, digest_index = self._freeze(connection, archive_id, spec, strategy)
                content_digest = _index_digest(spec, digest_index)
                built_at = to_storage(self.clock.now())
                repository.seal(
                    archive_id, manifest=manifest, counts=counts,
                    content_digest=content_digest, built_at=built_at,
                )
                AuditService(connection, self.clock).record(
                    AuditContext(principal.user_id, principal.display_name),
                    action="archive.seal", resource_type="archive", resource_id=archive_id,
                    after={"scope": spec["scope"], "cutoff_at": spec["cutoff_at"], "content_digest": content_digest},
                )
        except sqlite3.IntegrityError as exc:
            # 并发请求抢先封存时部分唯一索引会阻止第二个 sealed 版本：
            # 删除本方 building 行后直接复用先完成的版本；找不到赢家说明是
            # 其他完整性问题，按生成失败收口，而不是误报成版本冲突。
            winner = ArchiveRepository(self.connection).sealed_by_fingerprint(fingerprint)
            if winner is not None:
                self._discard_building(archive_id)
                return self._detail(winner, reused=True)
            self._fail_building(principal, archive_id, exc)
            raise ArchiveGenerationError(
                "资料封存生成失败，可通过封存状态接口查询失败原因",
                context={"archive_id": archive_id, "reason": str(exc)[:500]},
            ) from exc
        except Exception as exc:  # noqa: BLE001 - 失败也要可解释：回滚后把 building 行收口为失败诊断。
            self._fail_building(principal, archive_id, exc)
            if isinstance(exc, DomainError):
                raise
            raise ArchiveGenerationError(
                "资料封存生成失败，可通过封存状态接口查询失败原因",
                context={"archive_id": archive_id, "reason": str(exc)[:500]},
            ) from exc

        return self._detail(ArchiveRepository(self.connection).require(archive_id), reused=False)

    def status(self, principal: Principal, archive_id: int) -> dict[str, Any]:
        principal.require("archives.read")
        return self._detail(ArchiveRepository(self.connection).require(archive_id), reused=False, explain=True)

    def list_archives(
        self, principal: Principal, *, scope: str | None, status_filter: str | None, page: int, size: int,
    ) -> dict[str, Any]:
        principal.require("archives.read")
        repository = ArchiveRepository(self.connection)
        limit, offset = size, (page - 1) * size
        rows = repository.list_archives(scope=scope, status=status_filter, limit=limit, offset=offset)
        total = repository.count_archives(scope=scope, status=status_filter)
        return {"items": [self._summary(row) for row in rows], "total": total, "page": page, "size": size}

    def download(self, principal: Principal, archive_id: int) -> dict[str, Any]:
        principal.require("archives.read")
        repository = ArchiveRepository(self.connection)
        row = repository.require(archive_id)
        if row["status"] == "failed":
            raise ConflictError(
                "封存生成失败，没有可下载内容",
                context={"failure_code": row["failure_code"], "failure_reason": row["failure_reason"]},
            )
        if row["status"] != "sealed":
            raise ConflictError("封存尚未完成，无法下载")
        # 未脱敏封存只能由持有 archives.unmask 权限的调用者下载，
        # 避免低权限账号借他人封存绕过联系方式保护。
        if row["masking_policy"] == "full":
            principal.require("archives.unmask")
        items = repository.items_of(archive_id)
        content: dict[str, Any] = {}
        digest_index: list[dict[str, str]] = []
        for item in items:  # 只允许从冻结副本重组，并逐条与冻结摘要核对。
            payload = json.loads(item["payload_json"])
            if _item_digest(item["source_table"], item["source_id"], payload) != item["item_digest"]:
                raise ConflictError(
                    "封存副本与冻结摘要不一致，拒绝下载",
                    context={"source_table": item["source_table"], "source_id": item["source_id"]},
                )
            content.setdefault(CONTENT_KEYS[item["source_table"]], []).append(payload)
            digest_index.append(
                {"source_table": item["source_table"], "source_id": item["source_id"], "item_digest": item["item_digest"]}
            )
        spec = {
            "rule_version": row["rule_version"], "scope": row["scope"], "scope_value": row["scope_value"],
            "cutoff_at": row["cutoff_at"], "masking_policy": row["masking_policy"],
        }
        if _index_digest(spec, digest_index) != row["content_digest"]:
            raise ConflictError("封存内容摘要校验失败，下载内容可能已被篡改")
        manifest = json.loads(row["source_manifest_json"])
        counts = json.loads(row["counts_json"])
        if counts.get("total_items") != len(items):
            raise ConflictError("封存数量统计与冻结副本不一致")
        AuditService(self.connection, self.clock).record(
            AuditContext(principal.user_id, principal.display_name),
            action="archive.download", resource_type="archive", resource_id=archive_id,
            metadata={"content_digest": row["content_digest"]},
        )
        return {
            "archive": self._summary(row),
            "cutoff_at": row["cutoff_at"],
            "masking_policy": row["masking_policy"],
            "masking_description": manifest.get("masking_description", ""),
            "content": content,
            "sources": manifest["sources"],
            "counts": counts,
            "content_digest": row["content_digest"],
            "digest_algorithm": row["digest_algorithm"],
            "verified": True,
        }

    # ---------------------------------------------------------------- 构建

    def _normalize_spec(self, payload: dict[str, Any]) -> dict[str, Any]:
        scope = payload["scope"]
        scope_value = (payload.get("scope_value") or "").strip() or None
        if scope != "all" and not scope_value:
            raise ValidationError(f"{scope} 范围必须提供 scope_value")
        raw_cutoff = (payload.get("cutoff_at") or "").strip()
        try:
            cutoff_dt = from_storage(raw_cutoff)
        except ValueError as exc:
            raise ValidationError("cutoff_at 必须是 ISO 8601 日期时间") from exc
        if cutoff_dt is None:
            raise ValidationError("cutoff_at 不能为空")
        cutoff = to_storage(cutoff_dt)
        if cutoff_dt > self.clock.now():
            raise ValidationError("截止时刻不能晚于当前时间")
        policy = payload.get("masking_policy") or "standard"
        if policy not in {"standard", "full"}:
            raise ValidationError("masking_policy 只能是 standard 或 full")
        return {
            "scope": scope,
            "scope_value": None if scope == "all" else scope_value,
            "cutoff_at": cutoff,
            "masking_policy": policy,
            "label": (payload.get("label") or "").strip()[:200],
        }

    def _resolve_strategy(self, principal: Principal, policy: str) -> MaskingStrategy:
        can_unmask = principal.can("archives.unmask")
        if policy == "full" and not can_unmask:
            raise PermissionDeniedError("未脱敏封存需要 archives.unmask 权限")
        return MaskingStrategy(policy, can_unmask=can_unmask)

    def _insert_building(
        self, connection: sqlite3.Connection, principal: Principal, spec: dict[str, Any], fingerprint: str,
    ) -> int:
        now = to_storage(self.clock.now())
        code = f"arc-{fingerprint[:16]}-{secrets.token_hex(3)}"
        return ArchiveRepository(connection).insert_archive(
            archive_code=code, scope=spec["scope"], scope_value=spec["scope_value"],
            cutoff_at=spec["cutoff_at"], masking_policy=spec["masking_policy"],
            rule_version=spec["rule_version"], request_fingerprint=fingerprint, status="building",
            label=spec.get("label", ""), requested_by_user_id=principal.user_id,
            requested_by_name=principal.display_name,
            caller_permissions=sorted(principal.permissions), now=now,
        )

    def _discard_building(self, archive_id: int) -> None:
        with transaction(immediate=True) as connection:
            ArchiveRepository(connection).delete_archive(archive_id)

    def _fail_building(self, principal: Principal, archive_id: int, exc: Exception) -> None:
        now = to_storage(self.clock.now())
        with transaction(immediate=True) as connection:
            repository = ArchiveRepository(connection)
            repository.mark_failed(
                archive_id, code=type(exc).__name__,
                reason=str(exc)[:1000] or "生成过程抛出未知异常",
                context={"failed_at": now}, now=now,
            )
            AuditService(connection, self.clock).record(
                AuditContext(principal.user_id, principal.display_name),
                action="archive.failed", resource_type="archive", resource_id=archive_id,
                outcome="failure", metadata={"reason": str(exc)[:500]},
            )

    def _freeze(
        self, connection: sqlite3.Connection, archive_id: int, spec: dict[str, Any], strategy: MaskingStrategy,
    ) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, str]]]:
        repository = ArchiveRepository(connection)
        frozen_at = to_storage(self.clock.now())
        manifest_sources: list[dict[str, Any]] = []
        digest_index: list[dict[str, str]] = []
        by_table: dict[str, int] = {}
        for source_table in SOURCE_ORDER:
            included = source_table in SCOPE_TABLES[spec["scope"]]
            sql, params = self._source_query(source_table, spec)
            rows = connection.execute(sql, params).fetchall() if included else []
            source_hash = hashlib.sha256()
            timestamps: list[str] = []
            for row in rows:
                payload = _parse_json_columns(source_table, row)
                payload = strategy.apply(source_table, payload)
                source_id = str(row["id"])
                digest = _item_digest(source_table, source_id, payload)
                repository.insert_item(
                    archive_id=archive_id, source_table=source_table, source_id=source_id,
                    source_created_at=row["created_at"] if "created_at" in row.keys() else None,
                    payload=payload, item_digest=digest, frozen_at=frozen_at,
                )
                source_hash.update(digest.encode())
                digest_index.append(
                    {"source_table": source_table, "source_id": source_id, "item_digest": digest}
                )
                if row["created_at"]:
                    timestamps.append(row["created_at"])
            by_table[source_table] = len(rows)
            manifest_sources.append(
                self._source_manifest_entry(source_table, spec, included, len(rows), source_hash, timestamps)
            )
        manifest = {
            "rule_version": spec["rule_version"],
            "cutoff_rule": CUTOFF_RULE,
            "masking_policy": strategy.policy,
            "masking_description": strategy.description,
            "scope_predicate": scope_predicate(spec["scope"], spec["scope_value"]),
            "frozen_at": frozen_at,
            "sources": manifest_sources,
        }
        counts = {
            "total_items": sum(by_table.values()),
            "by_table": by_table,
            "masked_fields": strategy.masked_fields,
        }
        return manifest, counts, digest_index

    def _source_query(self, source_table: str, spec: dict[str, Any]) -> tuple[str, list[Any]]:
        cutoff = spec["cutoff_at"]
        scope, value = spec["scope"], spec["scope_value"]
        if source_table == "compute_templates":
            sql = "SELECT * FROM compute_templates WHERE created_at<=?"
            params: list[Any] = [cutoff]
            if scope == "template":
                sql += " AND code=?"
                params.append(value)
            return sql + " ORDER BY id", params
        if source_table == "compute_tasks":
            sql = (
                "SELECT t.*,tpl.code AS template_code,tpl.algorithm AS template_algorithm "
                "FROM compute_tasks t JOIN compute_templates tpl ON tpl.id=t.template_id "
                "WHERE t.created_at<=?"
            )
            params = [cutoff]
            if scope == "template":
                sql += " AND tpl.code=?"
                params.append(value)
            elif scope == "project":
                sql += " AND t.project_code=?"
                params.append(value)
            elif scope == "student":
                sql += " AND t.requested_by=?"
                params.append(value)
            return sql + " ORDER BY t.id", params
        if source_table in {"compute_results", "compute_interventions"}:
            sql = (
                f"SELECT x.* FROM {source_table} x "
                "JOIN compute_tasks t ON t.id=x.task_id "
                "JOIN compute_templates tpl ON tpl.id=t.template_id "
                "WHERE x.created_at<=? AND t.created_at<=?"
            )
            params = [cutoff, cutoff]
            if scope == "template":
                sql += " AND tpl.code=?"
                params.append(value)
            elif scope == "project":
                sql += " AND t.project_code=?"
                params.append(value)
            elif scope == "student":
                sql += " AND t.requested_by=?"
                params.append(value)
            return sql + " ORDER BY x.id", params
        if source_table == "users":
            return "SELECT * FROM users WHERE created_at<=? ORDER BY id", [cutoff]
        raise KeyError(f"未知封存来源：{source_table}")

    def _source_manifest_entry(
        self, source_table: str, spec: dict[str, Any], included: bool, count: int,
        source_hash: Any, timestamps: list[str],
    ) -> dict[str, Any]:
        entry: dict[str, Any] = {
            "table": source_table,
            "title": TABLE_TITLES.get(source_table, source_table),
            "included": included,
            "predicate": scope_predicate(spec["scope"], spec["scope_value"]) if included else "该范围不冻结此来源",
            "cutoff_rule": CUTOFF_RULE if included else "",
            "count": count,
            "source_digest": source_hash.hexdigest(),
        }
        if included:
            entry["boundary"] = {
                "oldest_created_at": min(timestamps) if timestamps else None,
                "newest_created_at": max(timestamps) if timestamps else None,
            }
        return entry

    # ---------------------------------------------------------------- 解释

    def _summary(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "archive_code": row["archive_code"],
            "scope": row["scope"],
            "scope_value": row["scope_value"],
            "cutoff_at": row["cutoff_at"],
            "masking_policy": row["masking_policy"],
            "rule_version": row["rule_version"],
            "status": row["status"],
            "label": row["label"],
            "requested_by_name": row["requested_by_name"],
            "content_digest": row["content_digest"],
            "digest_algorithm": row["digest_algorithm"],
            "created_at": row["created_at"],
            "built_at": row["built_at"],
        }

    def _detail(self, row: sqlite3.Row, *, reused: bool, explain: bool = False) -> dict[str, Any]:
        repository = ArchiveRepository(self.connection)
        result = self._summary(row)
        result["reused"] = reused
        result["item_count"] = repository.count_items(row["id"])
        if row["status"] == "sealed":
            manifest = json.loads(row["source_manifest_json"])
            result["sources"] = manifest["sources"]
            result["manifest_meta"] = {
                key: manifest[key]
                for key in ("rule_version", "cutoff_rule", "masking_policy", "masking_description", "scope_predicate", "frozen_at")
            }
            result["counts"] = json.loads(row["counts_json"])
        if row["status"] == "failed":
            result["failure"] = {
                "code": row["failure_code"],
                "reason": row["failure_reason"],
                "context": json.loads(row["failure_context_json"] or "{}"),
            }
        result["boundary_versions"] = self._boundary_versions(row)
        return result

    def _boundary_versions(self, row: sqlite3.Row) -> dict[str, Any]:
        """解释同一逻辑范围在不同截止时刻/规则版本上的相邻封存边界。"""
        repository = ArchiveRepository(self.connection)
        siblings = [
            item
            for item in repository.sibling_versions(row["scope"], row["scope_value"], row["masking_policy"])
            if item["status"] == "sealed"
        ]
        current_key = (row["cutoff_at"], row["rule_version"], row["id"])
        previous = None
        following = None
        for item in sorted(siblings, key=lambda edge: (edge["cutoff_at"], edge["rule_version"], edge["id"])):
            key = (item["cutoff_at"], item["rule_version"], item["id"])
            if key < current_key:
                previous = self._version_edge(item)
            elif key > current_key and following is None:
                following = self._version_edge(item)
        same_cutoff_rules = sorted({item["rule_version"] for item in siblings if item["cutoff_at"] == row["cutoff_at"]})
        return {
            "previous": previous,
            "current": self._version_edge(row),
            "next": following,
            "rule_versions_at_same_cutoff": same_cutoff_rules,
            "versioning_rule": "相同范围、截止时刻与脱敏策略复用不可变版本；仅当封存规则版本变化时才生成并存的新版本",
        }

    @staticmethod
    def _version_edge(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "archive_id": row["id"],
            "archive_code": row["archive_code"],
            "cutoff_at": row["cutoff_at"],
            "rule_version": row["rule_version"],
            "content_digest": row["content_digest"],
            "built_at": row["built_at"],
        }
