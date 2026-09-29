from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import UTC, datetime
from typing import Any

from app.archive.repository import ArchiveRepository
from app.core.clock import Clock, SystemClock, to_storage
from app.core.errors import ArchiveBuildError, ConflictError, NotFoundError, ValidationError
from app.core.pagination import Page, page_result
from app.core.privacy import mask_email, mask_phone
from app.core.security import Principal
from app.database import get_connection, transaction
from app.services.audit import AuditContext, AuditService

SCHEMA = """
CREATE TABLE IF NOT EXISTS archive_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scope_key TEXT NOT NULL,
    request_key TEXT NOT NULL,
    version INTEGER,
    scope_json TEXT NOT NULL,
    cutoff_at TEXT NOT NULL,
    policy_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('sealed','failed')),
    reason TEXT NOT NULL DEFAULT '',
    payload_json TEXT,
    content_digest TEXT,
    sources_json TEXT NOT NULL DEFAULT '[]',
    stats_json TEXT NOT NULL DEFAULT '{}',
    failure_reason TEXT,
    created_by TEXT NOT NULL,
    created_by_user_id INTEGER,
    created_at TEXT NOT NULL,
    sealed_at TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_archive_sealed_request ON archive_snapshots(request_key) WHERE status='sealed';
CREATE UNIQUE INDEX IF NOT EXISTS ux_archive_scope_version ON archive_snapshots(scope_key, version) WHERE version IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_archive_scope ON archive_snapshots(scope_key, id);
CREATE TRIGGER IF NOT EXISTS archive_snapshots_lock_update BEFORE UPDATE ON archive_snapshots
BEGIN
    SELECT RAISE(ABORT, '资料封存记录不可修改');
END;
CREATE TRIGGER IF NOT EXISTS archive_snapshots_lock_delete BEFORE DELETE ON archive_snapshots
BEGIN
    SELECT RAISE(ABORT, '资料封存记录不可删除');
END;
"""

SCOPE_FIELDS = ("project_code", "template_code", "requested_by")

MASKING_RULES = [
    {"target": "collections.teachers.email", "rule": "mask_email"},
    {"target": "collections.teachers.phone", "rule": "mask_phone"},
]


def ensure_schema() -> None:
    get_connection().executescript(SCHEMA)


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode()).hexdigest()


def _normalize_scope(raw: dict[str, Any]) -> dict[str, str]:
    scope: dict[str, str] = {}
    for field in SCOPE_FIELDS:
        value = raw.get(field)
        if value is None:
            continue
        text = str(value).strip()
        if text:
            scope[field] = text
    if not scope:
        raise ValidationError("封存范围至少需要包含项目、模板或提交人之一")
    return scope


def _policy(disclosure: str) -> dict[str, Any]:
    return {"disclosure": disclosure, "masking_rules": MASKING_RULES if disclosure == "masked" else []}


def _parse_json_fields(row: dict[str, Any], fields: dict[str, str]) -> dict[str, Any]:
    """把行内的 *_json 文本列解析为结构化字段，便于封存内容直接阅读。"""
    parsed = dict(row)
    for column, target in fields.items():
        raw = parsed.pop(column, None)
        if raw is None:
            continue
        try:
            parsed[target] = json.loads(raw)
        except (TypeError, ValueError):
            parsed[target] = raw
    return parsed


class ArchiveService:
    """按范围与截止时刻生成不可变、按权限脱敏的教学资料封存。"""

    def __init__(self, connection: sqlite3.Connection | None = None, clock: Clock | None = None) -> None:
        self.connection = connection or get_connection()
        self.clock = clock or SystemClock()
        ensure_schema()

    def create(self, payload: dict[str, Any], principal: Principal) -> dict[str, Any]:
        principal.require("archives.create")
        disclosure = payload.get("disclosure", "masked")
        if disclosure not in {"masked", "full"}:
            raise ValidationError("脱敏策略只支持 masked 或 full")
        if disclosure == "full":
            principal.require("archives.sensitive")
        scope = _normalize_scope(payload.get("scope") or {})
        if "cutoff_at" not in payload:
            raise ValidationError("缺少截止时刻")
        cutoff = self._normalize_cutoff(payload["cutoff_at"])
        policy = _policy(disclosure)
        reason = str(payload.get("reason", "")).strip()
        scope_key = _digest(scope)
        request_key = _digest({"scope": scope, "cutoff_at": cutoff, "policy": policy})

        existing = ArchiveRepository(self.connection).sealed_by_request_key(request_key)
        if existing is not None:
            self._audit(principal, "archive.create", existing["id"], "success", {"reused": True, "scope_key": scope_key})
            return self._meta(existing, reused=True)

        now = to_storage(self.clock.now())
        try:
            with transaction(immediate=True) as connection:
                repository = ArchiveRepository(connection)
                version = repository.next_version(scope_key)
                built = self._collect(connection, scope, cutoff)
                frozen = self._freeze(built, policy)
                content_digest = _digest(frozen)
                stats = self._stats(frozen)
                sources = self._sources(built)
                document = {
                    "archive": {
                        "version": version,
                        "scope": scope,
                        "cutoff_at": cutoff,
                        "policy": policy,
                        "reason": reason,
                        "sealed_at": now,
                        "sealed_by": principal.username,
                        "content_digest": content_digest,
                    },
                    "collections": frozen,
                    "stats": stats,
                    "sources": sources,
                }
                record = repository.insert_sealed(
                    scope_key=scope_key, request_key=request_key, version=version, scope=scope,
                    cutoff_at=cutoff, policy=policy, reason=reason, payload=document,
                    content_digest=content_digest, sources=sources, stats=stats,
                    actor=principal.username, actor_user_id=principal.user_id, now=now,
                )
                self._audit(principal, "archive.create", record["id"], "success", {"reused": False, "scope_key": scope_key, "version": version}, connection)
                return self._meta(record, reused=False)
        except Exception as exc:
            if isinstance(exc, sqlite3.IntegrityError):
                # 并发请求同一封存定义：唯一索引保证只有一份封存产物，落败的一方复用已封存版本。
                sealed = ArchiveRepository(get_connection()).sealed_by_request_key(request_key)
                if sealed is not None:
                    return self._meta(sealed, reused=True)
            self._record_failure(principal, scope=scope, scope_key=scope_key, request_key=request_key, cutoff=cutoff, policy=policy, reason=reason, exc=exc, now=now)
            raise ArchiveBuildError(f"资料封存生成失败：{type(exc).__name__}: {exc}", context={"scope_key": scope_key}) from exc

    def get(self, archive_id: int, principal: Principal) -> dict[str, Any]:
        principal.require("archives.read")
        row = ArchiveRepository(self.connection).by_id(archive_id)
        if row is None:
            raise NotFoundError("资料封存不存在")
        return self._meta(row)

    def list(self, principal: Principal, *, status: str | None = None, page: Page) -> dict[str, Any]:
        principal.require("archives.read")
        if status is not None and status not in {"sealed", "failed"}:
            raise ValidationError("封存状态只支持 sealed 或 failed")
        repository = ArchiveRepository(self.connection)
        rows = repository.list(status=status, limit=page.size, offset=page.offset)
        return page_result(total=repository.count(status=status), page=page, rows=[self._meta(row) for row in rows])

    def download(self, archive_id: int, principal: Principal) -> dict[str, Any]:
        principal.require("archives.read")
        row = ArchiveRepository(self.connection).by_id(archive_id)
        if row is None:
            raise NotFoundError("资料封存不存在")
        if row["status"] != "sealed":
            raise ConflictError("封存未成功完成，不能下载", context={"status": row["status"], "failure_reason": row["failure_reason"]})
        policy = json.loads(row["policy_json"])
        if policy.get("disclosure") == "full":
            principal.require("archives.sensitive")
        self._audit(principal, "archive.download", archive_id, "success", {"version": row["version"]})
        return json.loads(row["payload_json"])

    def explain(self, principal: Principal, raw_scope: dict[str, Any]) -> dict[str, Any]:
        principal.require("archives.read")
        scope = _normalize_scope(raw_scope)
        scope_key = _digest(scope)
        records = ArchiveRepository(self.connection).lineage(scope_key)
        versions = [self._meta(record) for record in records]
        sealed = [record for record in versions if record["status"] == "sealed"]
        return {
            "scope": scope,
            "scope_key": scope_key,
            "latest_sealed_version": max((record["version"] for record in sealed), default=None),
            "boundaries": [{"version": record["version"], "cutoff_at": record["cutoff_at"], "content_digest": record["content_digest"]} for record in sealed],
            "versions": versions,
        }

    def _collect(self, connection: sqlite3.Connection, scope: dict[str, str], cutoff: str) -> dict[str, Any]:
        """在生成事务内读取截止时刻之前的相关业务记录，作为冻结输入。"""
        clauses = ["t.created_at<=?"]
        params: list[Any] = [cutoff]
        if "project_code" in scope:
            clauses.append("t.project_code=?")
            params.append(scope["project_code"])
        if "requested_by" in scope:
            clauses.append("t.requested_by=?")
            params.append(scope["requested_by"])
        if "template_code" in scope:
            clauses.append("tpl.code=?")
            params.append(scope["template_code"])
        tasks = [dict(row) for row in connection.execute(
            "SELECT t.*,tpl.code AS template_code,tpl.name AS template_name FROM compute_tasks t "
            "JOIN compute_templates tpl ON tpl.id=t.template_id WHERE " + " AND ".join(clauses) + " ORDER BY t.id",
            tuple(params),
        ).fetchall()]
        task_ids = [int(task["id"]) for task in tasks]

        template_ids = sorted({int(task["template_id"]) for task in tasks})
        templates: list[dict[str, Any]] = []
        if template_ids:
            placeholders = ",".join("?" for _ in template_ids)
            templates = [dict(row) for row in connection.execute(
                f"SELECT * FROM compute_templates WHERE id IN ({placeholders}) AND created_at<=? ORDER BY id",
                (*template_ids, cutoff),
            ).fetchall()]
        if "template_code" in scope and not any(template["code"] == scope["template_code"] for template in templates):
            row = connection.execute("SELECT * FROM compute_templates WHERE code=? AND created_at<=?", (scope["template_code"], cutoff)).fetchone()
            if row is not None:
                templates.append(dict(row))
                templates.sort(key=lambda template: int(template["id"]))

        results: list[dict[str, Any]] = []
        interventions: list[dict[str, Any]] = []
        if task_ids:
            placeholders = ",".join("?" for _ in task_ids)
            results = [dict(row) for row in connection.execute(
                f"SELECT * FROM compute_results WHERE task_id IN ({placeholders}) AND created_at<=? ORDER BY task_id,version",
                (*task_ids, cutoff),
            ).fetchall()]
            interventions = [dict(row) for row in connection.execute(
                f"SELECT * FROM compute_interventions WHERE task_id IN ({placeholders}) AND created_at<=? ORDER BY id",
                (*task_ids, cutoff),
            ).fetchall()]

        teacher_names = sorted(
            {str(template["created_by"]) for template in templates}
            | {str(result["created_by"]) for result in results}
        )
        teachers: list[dict[str, Any]] = []
        user_rows: dict[str, sqlite3.Row] = {}
        if teacher_names:
            placeholders = ",".join("?" for _ in teacher_names)
            user_rows = {
                str(row["username"]): row
                for row in connection.execute(
                    f"SELECT id,username,display_name,email,phone FROM users WHERE username IN ({placeholders})",
                    tuple(teacher_names),
                ).fetchall()
            }
        for name in teacher_names:
            user = user_rows.get(name)
            appears_in: list[str] = []
            if any(template["created_by"] == name for template in templates):
                appears_in.append("templates")
            if any(result["created_by"] == name for result in results):
                appears_in.append("results")
            teachers.append({
                "username": name,
                "user_id": int(user["id"]) if user else None,
                "display_name": user["display_name"] if user else None,
                "email": user["email"] if user else None,
                "phone": user["phone"] if user else None,
                "appears_in": appears_in,
            })
        return {"templates": templates, "tasks": tasks, "results": results, "interventions": interventions, "teachers": teachers, "user_rows": user_rows}

    def _freeze(self, built: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
        """把采集到的记录整理为冻结内容，并按脱敏策略处理教师联系方式。"""
        masked = policy["disclosure"] == "masked"
        teachers = []
        for teacher in built["teachers"]:
            entry = {key: value for key, value in teacher.items()}
            if masked:
                entry["email"] = mask_email(entry.get("email"))
                entry["phone"] = mask_phone(entry.get("phone"))
            teachers.append(entry)
        return {
            "templates": [_parse_json_fields(template, {"parameter_schema_json": "parameter_schema", "default_parameters_json": "default_parameters"}) for template in built["templates"]],
            "tasks": [_parse_json_fields(task, {"parameters_json": "parameters"}) for task in built["tasks"]],
            "results": [_parse_json_fields(result, {"result_json": "result", "metrics_json": "metrics"}) for result in built["results"]],
            "interventions": [_parse_json_fields(item, {"before_json": "before", "after_json": "after"}) for item in built["interventions"]],
            "teachers": teachers,
        }

    @staticmethod
    def _stats(frozen: dict[str, Any]) -> dict[str, Any]:
        tasks_by_status: dict[str, int] = {}
        for task in frozen["tasks"]:
            tasks_by_status[str(task["status"])] = tasks_by_status.get(str(task["status"]), 0) + 1
        counts = {name: len(frozen[name]) for name in ("templates", "tasks", "results", "interventions", "teachers")}
        return {
            **counts,
            "tasks_by_status": tasks_by_status,
            "total_records": counts["templates"] + counts["tasks"] + counts["results"] + counts["interventions"],
        }

    @staticmethod
    def _sources(built: dict[str, Any]) -> list[dict[str, Any]]:
        def entry(table: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
            ids = [int(row["id"]) for row in rows]
            return {"table": table, "rows": len(rows), "first_id": min(ids) if ids else None, "last_id": max(ids) if ids else None}

        user_rows = list(built["user_rows"].values())
        return [
            entry("compute_templates", built["templates"]),
            entry("compute_tasks", built["tasks"]),
            entry("compute_results", built["results"]),
            entry("compute_interventions", built["interventions"]),
            entry("users", [dict(row) for row in user_rows]),
        ]

    def _record_failure(self, principal: Principal, *, scope: dict[str, str], scope_key: str, request_key: str, cutoff: str, policy: dict[str, Any], reason: str, exc: Exception, now: str) -> None:
        """生成失败后单独落一条失败记录，便于接口解释失败原因；记录本身失败不掩盖原始错误。"""
        failure_reason = f"{type(exc).__name__}: {exc}"[:500]
        try:
            with transaction(immediate=True) as connection:
                record = ArchiveRepository(connection).insert_failed(
                    scope_key=scope_key, request_key=request_key, scope=scope, cutoff_at=cutoff,
                    policy=policy, reason=reason, failure_reason=failure_reason,
                    actor=principal.username, actor_user_id=principal.user_id, now=now,
                )
                self._audit(principal, "archive.create", record["id"], "failure", {"scope_key": scope_key, "failure_reason": failure_reason}, connection)
        except Exception:
            pass

    def _audit(self, principal: Principal, action: str, resource_id: int | None, outcome: str, metadata: dict[str, Any], connection: sqlite3.Connection | None = None) -> None:
        service = AuditService(connection or self.connection, self.clock)
        service.record(
            AuditContext(principal.user_id, principal.display_name),
            action=action,
            resource_type="archive_snapshot",
            resource_id=resource_id,
            outcome=outcome,
            metadata=metadata,
        )

    def _normalize_cutoff(self, value: Any) -> str:
        if isinstance(value, datetime):
            moment = value
        else:
            try:
                moment = datetime.fromisoformat(str(value))
            except ValueError as exc:
                raise ValidationError("截止时刻必须是合法的 ISO-8601 时间") from exc
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=UTC)
        moment = moment.astimezone(UTC)
        if moment > self.clock.now():
            raise ValidationError("截止时刻不能晚于当前时间")
        return to_storage(moment)

    @staticmethod
    def _meta(row: sqlite3.Row | dict[str, Any], reused: bool = False) -> dict[str, Any]:
        record = dict(row)
        policy = json.loads(record["policy_json"])
        return {
            "id": record["id"],
            "version": record["version"],
            "status": record["status"],
            "reused": reused,
            "scope": json.loads(record["scope_json"]),
            "scope_key": record["scope_key"],
            "cutoff_at": record["cutoff_at"],
            "disclosure": policy.get("disclosure"),
            "policy": policy,
            "reason": record["reason"],
            "content_digest": record["content_digest"],
            "stats": json.loads(record["stats_json"]),
            "sources": json.loads(record["sources_json"]),
            "failure_reason": record["failure_reason"],
            "created_by": record["created_by"],
            "created_at": record["created_at"],
            "sealed_at": record["sealed_at"],
        }
