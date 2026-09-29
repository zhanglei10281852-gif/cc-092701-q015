from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from app.archive.service import ArchiveService
from app.compute.service import ComputeOperationsService
from app.core.clock import FrozenClock, to_storage
from app.core.security import Principal
from app.database import get_connection, init_db, transaction

TEMPLATE = {
    "code": "lesson-plan",
    "name": "课时计算模板",
    "algorithm": "lesson-plan",
    "parameter_schema": {"hours": {"type": "integer", "required": True, "minimum": 1, "maximum": 100}},
    "default_parameters": {},
    "max_runtime_seconds": 300,
    "max_attempts": 2,
}


def submit_payload(key: str, *, user: str = "student-01", project: str = "course-a") -> dict:
    return {
        "template_code": "lesson-plan",
        "project_code": project,
        "requested_by": user,
        "parameters": {"hours": 2},
        "priority": 50,
        "idempotency_key": key,
    }


def create_teacher(client, admin) -> None:
    response = client.post(
        "/api/users",
        headers=admin["headers"],
        json={
            "username": "teacher.wang",
            "password": "Teach!23456",
            "display_name": "王老师",
            "email": "wang@school.cn",
            "phone": "13800005678",
            "role_codes": [],
        },
    )
    assert response.status_code == 201, response.text


def create_template(client) -> None:
    response = client.post("/api/compute/templates?actor=teacher.wang", json=TEMPLATE)
    assert response.status_code == 201, response.text


def prepare_business(client, admin) -> dict:
    """准备一名教师、一个模板、两份学员提交，其中一份由教师发布成绩。"""
    create_teacher(client, admin)
    create_template(client)
    first = client.post("/api/compute/tasks", json=submit_payload("archive-sub-001")).json()
    second = client.post("/api/compute/tasks", json=submit_payload("archive-sub-002")).json()
    claimed = client.post("/api/compute/tasks/claim", json={"worker_id": "teacher.wang", "capabilities": ["lesson-plan"], "lease_seconds": 60})
    assert claimed.status_code == 200 and claimed.json()["task"] is not None
    task_id = claimed.json()["task"]["id"]
    completed = client.post(
        f"/api/compute/tasks/{task_id}/complete",
        json={"worker_id": "teacher.wang", "result": {"score": 92}, "metrics": {"seconds": 3}},
    )
    assert completed.status_code == 200
    return {"first": first, "second": second, "completed_id": task_id}


def archive_payload(*, cutoff: str | None = None, disclosure: str = "masked", project: str = "course-a") -> dict:
    return {
        "scope": {"project_code": project},
        "cutoff_at": cutoff or datetime.now(UTC).isoformat(),
        "disclosure": disclosure,
        "reason": "认证结束资料封存",
    }


def make_principal(**permissions: str) -> Principal:
    return Principal(
        user_id=1,
        username="admin",
        display_name="管理员",
        department_id=None,
        permissions=frozenset(permissions or {"archives.create", "archives.read", "archives.sensitive"}),
        session_id=1,
    )


def test_archive_seals_masks_and_reuses(client, admin):
    prepare_business(client, admin)
    created = client.post("/api/archives", headers=admin["headers"], json=archive_payload())
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["status"] == "sealed" and body["version"] == 1 and body["reused"] is False
    assert body["content_digest"] and body["sealed_at"]
    assert body["stats"]["tasks"] == 2
    assert body["stats"]["templates"] == 1
    assert body["stats"]["results"] == 1
    assert body["stats"]["teachers"] == 1
    assert body["stats"]["tasks_by_status"] == {"queued": 1, "succeeded": 1}
    tables = {entry["table"] for entry in body["sources"]}
    assert tables == {"compute_templates", "compute_tasks", "compute_results", "compute_interventions", "users"}

    download = client.get(f"/api/archives/{body['id']}/download", headers=admin["headers"])
    assert download.status_code == 200
    document = download.json()
    teacher = document["collections"]["teachers"][0]
    assert teacher["username"] == "teacher.wang"
    assert teacher["email"] == "w***@school.cn"
    assert teacher["phone"] == "138****5678"
    assert document["collections"]["tasks"][0]["parameters"] == {"hours": 2}
    assert document["archive"]["content_digest"] == body["content_digest"]

    again = client.post("/api/archives", headers=admin["headers"], json=archive_payload())
    assert again.status_code == 200
    assert again.json()["reused"] is True
    assert again.json()["id"] == body["id"]
    assert again.json()["version"] == 1


def test_archive_versions_on_rule_change_and_explain(client, admin):
    prepare_business(client, admin)
    cutoff_early = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    cutoff_now = datetime.now(UTC).isoformat()
    first = client.post("/api/archives", headers=admin["headers"], json=archive_payload(cutoff=cutoff_early))
    assert first.status_code == 201 and first.json()["version"] == 1
    second = client.post("/api/archives", headers=admin["headers"], json=archive_payload(cutoff=cutoff_now))
    assert second.status_code == 201, second.text
    assert second.json()["version"] == 2 and second.json()["reused"] is False
    third = client.post("/api/archives", headers=admin["headers"], json=archive_payload(cutoff=cutoff_now, disclosure="full"))
    assert third.status_code == 201, third.text
    assert third.json()["version"] == 3

    document = client.get(f"/api/archives/{third.json()['id']}/download", headers=admin["headers"]).json()
    assert document["collections"]["teachers"][0]["email"] == "wang@school.cn"
    assert document["collections"]["teachers"][0]["phone"] == "13800005678"

    explain = client.get("/api/archives/explain", headers=admin["headers"], params={"project_code": "course-a"})
    assert explain.status_code == 200, explain.text
    detail = explain.json()
    assert detail["latest_sealed_version"] == 3
    assert [entry["version"] for entry in detail["boundaries"]] == [1, 2, 3]
    assert detail["boundaries"][0]["cutoff_at"] < detail["boundaries"][1]["cutoff_at"]
    assert [entry["status"] for entry in detail["versions"]] == ["sealed", "sealed", "sealed"]
    assert {entry["disclosure"] for entry in detail["versions"]} == {"masked", "full"}


def test_archive_download_is_immutable_after_business_changes(client, admin):
    business = prepare_business(client, admin)
    created = client.post("/api/archives", headers=admin["headers"], json=archive_payload()).json()
    before = client.get(f"/api/archives/{created['id']}/download", headers=admin["headers"]).json()

    cancelled = client.post(
        f"/api/compute/tasks/{business['second']['id']}/cancel",
        json={"actor": "administrator", "reason": "课程调整"},
    )
    assert cancelled.status_code == 200

    after = client.get(f"/api/archives/{created['id']}/download", headers=admin["headers"]).json()
    assert after == before
    statuses = {task["id"]: task["status"] for task in after["collections"]["tasks"]}
    assert statuses[business["second"]["id"]] == "queued"
    assert after["collections"]["interventions"] == []

    meta = client.get(f"/api/archives/{created['id']}", headers=admin["headers"]).json()
    assert meta["content_digest"] == created["content_digest"]


def test_full_disclosure_requires_sensitive_permission(client, admin):
    prepare_business(client, admin)
    role = client.post(
        "/api/roles",
        headers=admin["headers"],
        json={"code": "archive.clerk", "name": "封存经办员", "permission_codes": ["archives.create", "archives.read"]},
    )
    assert role.status_code == 201, role.text
    user = client.post(
        "/api/users",
        headers=admin["headers"],
        json={"username": "archive.clerk", "password": "Clerk!23456", "display_name": "封存经办员", "role_codes": ["archive.clerk"]},
    )
    assert user.status_code == 201, user.text
    login = client.post("/api/auth/login", json={"username": "archive.clerk", "password": "Clerk!23456", "client_label": "tests"})
    headers = {"Authorization": f"Bearer {login.json()['token']}"}

    denied = client.post("/api/archives", headers=headers, json=archive_payload(disclosure="full"))
    assert denied.status_code == 403

    masked = client.post("/api/archives", headers=headers, json=archive_payload())
    assert masked.status_code == 201, masked.text

    full = client.post("/api/archives", headers=admin["headers"], json=archive_payload(disclosure="full"))
    assert full.status_code == 201, full.text
    forbidden_download = client.get(f"/api/archives/{full.json()['id']}/download", headers=headers)
    assert forbidden_download.status_code == 403
    readable_meta = client.get(f"/api/archives/{full.json()['id']}", headers=headers)
    assert readable_meta.status_code == 200


def test_archive_requires_authentication_and_create_permission(client, admin):
    anonymous = client.post("/api/archives", json=archive_payload())
    assert anonymous.status_code == 401

    role = client.post(
        "/api/roles",
        headers=admin["headers"],
        json={"code": "archive.viewer", "name": "封存查看员", "permission_codes": ["archives.read"]},
    )
    assert role.status_code == 201
    client.post(
        "/api/users",
        headers=admin["headers"],
        json={"username": "archive.viewer", "password": "Clerk!23456", "display_name": "封存查看员", "role_codes": ["archive.viewer"]},
    )
    login = client.post("/api/auth/login", json={"username": "archive.viewer", "password": "Clerk!23456", "client_label": "tests"})
    headers = {"Authorization": f"Bearer {login.json()['token']}"}
    denied = client.post("/api/archives", headers=headers, json=archive_payload())
    assert denied.status_code == 403
    listing = client.get("/api/archives", headers=headers)
    assert listing.status_code == 200


def test_failed_generation_leaves_no_partial_and_is_explainable(client, admin, monkeypatch):
    prepare_business(client, admin)

    def boom(self, connection, scope, cutoff):
        raise RuntimeError("采集器故障")

    monkeypatch.setattr(ArchiveService, "_collect", boom)
    failed = client.post("/api/archives", headers=admin["headers"], json=archive_payload())
    assert failed.status_code == 500
    assert failed.json()["error"]["code"] == "archive_build_failed"

    listing = client.get("/api/archives", headers=admin["headers"], params={"status": "failed"})
    assert listing.status_code == 200
    assert listing.json()["total"] == 1
    record = listing.json()["data"][0]
    assert record["status"] == "failed"
    assert record["version"] is None
    assert "采集器故障" in record["failure_reason"]

    explain = client.get("/api/archives/explain", headers=admin["headers"], params={"project_code": "course-a"}).json()
    assert explain["latest_sealed_version"] is None
    assert explain["boundaries"] == []
    assert explain["versions"][0]["failure_reason"]

    connection = get_connection()
    row = connection.execute("SELECT payload_json, content_digest FROM archive_snapshots WHERE status='failed'").fetchone()
    assert row["payload_json"] is None and row["content_digest"] is None
    assert connection.execute("SELECT COUNT(*) FROM archive_snapshots WHERE status='sealed'").fetchone()[0] == 0

    monkeypatch.undo()
    retry = client.post("/api/archives", headers=admin["headers"], json=archive_payload())
    assert retry.status_code == 201, retry.text
    assert retry.json()["status"] == "sealed" and retry.json()["version"] == 1


def test_archive_records_cannot_be_modified_or_deleted(client, admin):
    prepare_business(client, admin)
    created = client.post("/api/archives", headers=admin["headers"], json=archive_payload()).json()
    connection = get_connection()
    with pytest.raises(sqlite3.IntegrityError):
        connection.execute("UPDATE archive_snapshots SET reason='篡改' WHERE id=?", (created["id"],))
    with pytest.raises(sqlite3.IntegrityError):
        connection.execute("DELETE FROM archive_snapshots WHERE id=?", (created["id"],))
    kept = client.get(f"/api/archives/{created['id']}", headers=admin["headers"]).json()
    assert kept["reason"] == "认证结束资料封存"


def test_cutoff_and_scope_validation(client, admin):
    future = client.post(
        "/api/archives",
        headers=admin["headers"],
        json=archive_payload(cutoff=(datetime.now(UTC) + timedelta(days=1)).isoformat()),
    )
    assert future.status_code == 422
    assert future.json()["error"]["code"] == "validation_error"

    empty_scope = client.post(
        "/api/archives",
        headers=admin["headers"],
        json={"scope": {}, "cutoff_at": datetime.now(UTC).isoformat(), "reason": "认证结束资料封存"},
    )
    assert empty_scope.status_code == 422

    bad_explain = client.get("/api/archives/explain", headers=admin["headers"])
    assert bad_explain.status_code == 422

    missing = client.get("/api/archives/9999", headers=admin["headers"])
    assert missing.status_code == 404


def test_cutoff_boundary_with_frozen_clock(client, admin):
    init_db()
    clock = FrozenClock(datetime(2026, 9, 20, 8, 0, tzinfo=UTC))
    compute = ComputeOperationsService(get_connection(), clock)
    compute.create_template(TEMPLATE, "teacher.li")
    first = compute.submit(submit_payload("archive-clock-01"))
    claimed = compute.claim("teacher.li", ["lesson-plan"], 60)
    assert claimed and claimed["id"] == first["id"]
    clock.advance(hours=1)  # 09:00，成绩在截止时刻之后发布
    compute.complete(first["id"], "teacher.li", {"score": 88}, {"seconds": 1})
    clock.advance(hours=1)  # 10:00，第二份提交在截止时刻之后进入
    second = compute.submit(submit_payload("archive-clock-02", user="student-02"))

    principal = make_principal()
    service = ArchiveService(get_connection(), clock)
    cutoff = to_storage(datetime(2026, 9, 20, 8, 30, tzinfo=UTC))
    early = service.create({"scope": {"project_code": "course-a"}, "cutoff_at": cutoff, "reason": "认证结束资料封存"}, principal)
    assert early["version"] == 1
    assert early["stats"]["tasks"] == 1
    assert early["stats"]["results"] == 0

    document = service.download(early["id"], principal)
    assert [task["id"] for task in document["collections"]["tasks"]] == [first["id"]]
    assert document["collections"]["results"] == []
    assert document["collections"]["teachers"][0]["username"] == "teacher.li"
    assert document["collections"]["teachers"][0]["email"] is None

    later = service.create(
        {"scope": {"project_code": "course-a"}, "cutoff_at": to_storage(clock.now()), "reason": "认证结束资料封存"},
        principal,
    )
    assert later["version"] == 2
    assert later["stats"]["tasks"] == 2
    assert later["stats"]["results"] == 1
    full_document = service.download(later["id"], principal)
    assert {task["id"] for task in full_document["collections"]["tasks"]} == {first["id"], second["id"]}

    repeated = service.create({"scope": {"project_code": "course-a"}, "cutoff_at": cutoff, "reason": "认证结束资料封存"}, principal)
    assert repeated["reused"] is True and repeated["id"] == early["id"]


def test_service_rejects_invalid_disclosure(client, admin):
    from app.core.errors import ValidationError

    init_db()
    service = ArchiveService(get_connection(), FrozenClock(datetime(2026, 9, 20, 8, 0, tzinfo=UTC)))
    with pytest.raises(ValidationError):
        service.create(
            {"scope": {"project_code": "course-a"}, "cutoff_at": "2026-09-20T07:00:00+00:00", "disclosure": "plain", "reason": "认证结束资料封存"},
            make_principal(),
        )
