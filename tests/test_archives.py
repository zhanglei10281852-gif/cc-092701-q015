from __future__ import annotations

from datetime import UTC, datetime

from app.archives import service as archive_service_module
from app.archives.service import ArchiveService
from app.compute.service import ComputeOperationsService
from app.core.clock import FrozenClock, to_storage
from app.core.security import Principal
from app.database import get_connection, transaction

TEMPLATE = {
    "code": "course-arch",
    "name": "数控编程课程安排",
    "algorithm": "mill-cam",
    "parameter_schema": {
        "iterations": {"type": "integer", "required": True, "minimum": 1, "maximum": 10000},
        "mode": {"type": "string", "required": True, "choices": ["fast", "accurate"]},
        "note": {"type": "string", "required": False},
    },
    "default_parameters": {},
    "max_runtime_seconds": 300,
    "max_attempts": 2,
}


def submit_payload(key: str, *, project: str = "project-a", user: str = "student-01", note: str | None = None) -> dict:
    parameters = {"iterations": 100, "mode": "accurate"}
    if note is not None:
        parameters["note"] = note
    return {
        "template_code": "course-arch",
        "project_code": project,
        "requested_by": user,
        "parameters": parameters,
        "priority": 50,
        "idempotency_key": key,
    }


def super_principal() -> Principal:
    return Principal(user_id=1, username="admin", display_name="管理员", department_id=None, permissions=frozenset({"*"}), session_id=1)


def now_cutoff() -> str:
    return to_storage(datetime.now(UTC))


def create_course_data(client) -> None:
    assert client.post("/api/compute/templates?actor=admin", json=TEMPLATE).status_code == 201
    task = client.post("/api/compute/tasks", json=submit_payload("arc-task-0001", note="答疑请联系教师 13912345678")).json()
    client.post("/api/compute/tasks/claim", json={"worker_id": "grader-1", "capabilities": ["mill-cam"], "lease_seconds": 60})
    completed = client.post(
        f"/api/compute/tasks/{task['id']}/complete",
        json={"worker_id": "grader-1", "result": {"score": 92}, "metrics": {"seconds": 3}},
    )
    assert completed.status_code == 200


def create_user(client, headers, username: str, roles: list[str], phone: str | None = None) -> dict:
    response = client.post(
        "/api/users",
        headers=headers,
        json={"username": username, "password": "Reader!12345", "display_name": username, "phone": phone, "role_codes": roles},
    )
    assert response.status_code == 201, response.text
    login = client.post("/api/auth/login", json={"username": username, "password": "Reader!12345", "client_label": "tests"})
    assert login.status_code == 200, login.text
    return {"Authorization": f"Bearer {login.json()['token']}"}


# ---------------------------------------------------------------- 基本封存


def test_seal_freezes_schedule_submission_and_grades_with_summary(client, admin):
    create_course_data(client)
    payload = {"scope": "all", "cutoff_at": now_cutoff(), "label": "认证材料-9月"}
    response = client.post("/api/archives", headers=admin["headers"], json=payload)
    assert response.status_code == 200, response.text
    sealed = response.json()
    assert sealed["status"] == "sealed"
    assert sealed["reused"] is False
    assert len(sealed["content_digest"]) == 64
    counts = sealed["counts"]
    assert counts["by_table"]["compute_templates"] == 1
    assert counts["by_table"]["compute_tasks"] == 1
    assert counts["by_table"]["compute_results"] == 1
    assert counts["by_table"]["compute_interventions"] == 0
    assert counts["total_items"] >= 3

    sources = {item["table"]: item for item in sealed["sources"]}
    assert sources["compute_results"]["count"] == 1
    assert sources["compute_results"]["boundary"]["newest_created_at"] is not None
    assert sources["compute_results"]["source_digest"]
    assert "cutoff_rule" in sources["compute_tasks"]

    download = client.get(f"/api/archives/{sealed['id']}/download", headers=admin["headers"])
    assert download.status_code == 200
    body = download.json()
    assert body["verified"] is True
    assert body["content"]["course_templates"][0]["name"] == "数控编程课程安排"
    assert body["content"]["submissions"][0]["project_code"] == "project-a"
    assert body["content"]["grade_releases"][0]["result_json"]["score"] == 92


def test_identical_request_reuses_immutable_version(client, admin):
    create_course_data(client)
    payload = {"scope": "all", "cutoff_at": now_cutoff(), "masking_policy": "standard"}
    first = client.post("/api/archives", headers=admin["headers"], json=payload).json()
    second = client.post("/api/archives", headers=admin["headers"], json=payload).json()
    assert second["reused"] is True
    assert second["id"] == first["id"]
    assert second["content_digest"] == first["content_digest"]
    assert get_connection().execute("SELECT COUNT(*) FROM archives WHERE status='sealed'").fetchone()[0] == 1


def test_later_business_changes_do_not_affect_download(client, admin):
    create_course_data(client)
    sealed = client.post(
        "/api/archives", headers=admin["headers"], json={"scope": "all", "cutoff_at": now_cutoff()}
    ).json()
    # 封存之后课程表被修改、又有新的提交和成绩，下载内容必须保持封存时刻的样子。
    with transaction(immediate=True) as connection:
        connection.execute("UPDATE compute_templates SET name='更名后的课程安排' WHERE code='course-arch'")
    new_task = client.post("/api/compute/tasks", json=submit_payload("arc-task-later-9"))
    client.post("/api/compute/tasks/claim", json={"worker_id": "grader-1", "capabilities": ["mill-cam"], "lease_seconds": 60})
    client.post(
        f"/api/compute/tasks/{new_task.json()['id']}/complete",
        json={"worker_id": "grader-1", "result": {"score": 55}, "metrics": {}},
    )
    body = client.get(f"/api/archives/{sealed['id']}/download", headers=admin["headers"]).json()
    assert body["content"]["course_templates"][0]["name"] == "数控编程课程安排"
    assert len(body["content"]["submissions"]) == 1
    assert len(body["content"]["grade_releases"]) == 1


def test_cutoff_excludes_records_created_afterward(client, admin):
    _ = admin
    clock = FrozenClock(datetime(2026, 9, 20, 1, 0, tzinfo=UTC))
    compute = ComputeOperationsService(get_connection(), clock)
    compute.create_template(TEMPLATE, "admin")
    compute.submit(submit_payload("cutoff-one"))
    clock.advance(hours=1)
    compute.submit(submit_payload("cutoff-two"))

    service = ArchiveService(get_connection(), clock)
    first = service.create_or_reuse(
        super_principal(), {"scope": "all", "cutoff_at": "2026-09-20T01:00:00+00:00"}
    )
    second = service.create_or_reuse(
        super_principal(), {"scope": "all", "cutoff_at": "2026-09-20T02:00:00+00:00"}
    )
    assert first["counts"]["by_table"]["compute_tasks"] == 1
    assert second["counts"]["by_table"]["compute_tasks"] == 2
    assert first["content_digest"] != second["content_digest"]


# ---------------------------------------------------------------- 范围


def test_scoped_archives_filter_sources(client, admin):
    create_course_data(client)
    client.post(
        "/api/compute/tasks",
        json=submit_payload("arc-task-other-1", project="project-b", user="student-02"),
    )
    cutoff = now_cutoff()
    project = client.post(
        "/api/archives", headers=admin["headers"],
        json={"scope": "project", "scope_value": "project-a", "cutoff_at": cutoff},
    ).json()
    student = client.post(
        "/api/archives", headers=admin["headers"],
        json={"scope": "student", "scope_value": "student-01", "cutoff_at": cutoff},
    ).json()
    template = client.post(
        "/api/archives", headers=admin["headers"],
        json={"scope": "template", "scope_value": "course-arch", "cutoff_at": cutoff},
    ).json()

    project_body = client.get(f"/api/archives/{project['id']}/download", headers=admin["headers"]).json()
    assert {item["project_code"] for item in project_body["content"]["submissions"]} == {"project-a"}
    assert "directory" not in project_body["content"]

    student_body = client.get(f"/api/archives/{student['id']}/download", headers=admin["headers"]).json()
    assert {item["requested_by"] for item in student_body["content"]["submissions"]} == {"student-01"}

    template_body = client.get(f"/api/archives/{template['id']}/download", headers=admin["headers"]).json()
    assert template_body["content"]["course_templates"][0]["code"] == "course-arch"
    assert "directory" not in template_body["content"]
    missing = client.post(
        "/api/archives", headers=admin["headers"],
        json={"scope": "project", "cutoff_at": cutoff},
    )
    assert missing.status_code == 422


# ---------------------------------------------------------------- 脱敏


def test_standard_policy_masks_contact_details_by_permission(client, admin):
    create_course_data(client)
    create_user(client, admin["headers"], "teacher.wang", ["clerk"], phone="13912345678")
    sealed = client.post(
        "/api/archives", headers=admin["headers"],
        json={"scope": "all", "cutoff_at": now_cutoff(), "masking_policy": "standard"},
    ).json()
    body = client.get(f"/api/archives/{sealed['id']}/download", headers=admin["headers"]).json()
    teacher = next(item for item in body["content"]["directory"] if item["username"] == "teacher.wang")
    assert teacher["phone"] == "139****5678"
    assert "password_hash" not in teacher
    note = body["content"]["submissions"][0]["parameters_json"]["note"]
    assert "139****5678" in note and "13912345678" not in note
    assert sealed["counts"]["masked_fields"]


def test_full_policy_requires_unmask_permission_and_keeps_contacts(client, admin):
    create_course_data(client)
    create_user(client, admin["headers"], "teacher.li", ["clerk"], phone="13912345678")
    role = client.post(
        "/api/roles", headers=admin["headers"],
        json={"code": "archive_reader", "name": "封存查阅", "permission_codes": ["archives.read"]},
    )
    assert role.status_code == 201, role.text
    reader = create_user(client, admin["headers"], "reader.a", ["archive_reader"])

    denied = client.post(
        "/api/archives", headers=reader,
        json={"scope": "all", "cutoff_at": now_cutoff(), "masking_policy": "full"},
    )
    assert denied.status_code == 403

    sealed = client.post(
        "/api/archives", headers=admin["headers"],
        json={"scope": "all", "cutoff_at": now_cutoff(), "masking_policy": "full"},
    ).json()
    # 低权限账号即使知道封存编号，也不能下载未脱敏封存里的联系方式。
    forbidden = client.get(f"/api/archives/{sealed['id']}/download", headers=reader)
    assert forbidden.status_code == 403
    body = client.get(f"/api/archives/{sealed['id']}/download", headers=admin["headers"]).json()
    teacher = next(item for item in body["content"]["directory"] if item["username"] == "teacher.li")
    assert teacher["phone"] == "13912345678"


def test_archive_endpoints_require_authentication_and_permission(client, admin):
    assert client.post("/api/archives", json={"scope": "all", "cutoff_at": now_cutoff()}).status_code == 401
    role = client.post(
        "/api/roles", headers=admin["headers"],
        json={"code": "no_archive", "name": "无封存权限", "permission_codes": []},
    ).json()
    powerless = create_user(client, admin["headers"], "nobody.x", ["no_archive"])
    denied = client.post(
        "/api/archives", headers=powerless, json={"scope": "all", "cutoff_at": now_cutoff()}
    )
    assert denied.status_code == 403


# ---------------------------------------------------------------- 失败与边界


def test_failed_generation_leaves_no_half_baked_items_and_is_explainable(client, admin, monkeypatch):
    create_course_data(client)

    def boom(self, connection, archive_id, spec, strategy):  # noqa: ANN001
        raise RuntimeError("storage boom")

    monkeypatch.setattr(archive_service_module.ArchiveService, "_freeze", boom)
    response = client.post(
        "/api/archives", headers=admin["headers"], json={"scope": "all", "cutoff_at": now_cutoff()}
    )
    assert response.status_code == 500
    failed_id = response.json()["error"]["context"]["archive_id"]

    assert get_connection().execute(
        "SELECT COUNT(*) FROM archives WHERE status='building'"
    ).fetchone()[0] == 0
    assert get_connection().execute(
        "SELECT COUNT(*) FROM archive_items WHERE archive_id=?", (failed_id,)
    ).fetchone()[0] == 0

    status = client.get(f"/api/archives/{failed_id}/status", headers=admin["headers"]).json()
    assert status["status"] == "failed"
    assert status["failure"]["code"] == "RuntimeError"
    assert "storage boom" in status["failure"]["reason"]

    monkeypatch.undo()
    retry = client.post(
        "/api/archives", headers=admin["headers"], json={"scope": "all", "cutoff_at": now_cutoff()}
    )
    assert retry.status_code == 200
    assert retry.json()["status"] == "sealed"


def test_tampered_frozen_copy_is_rejected(client, admin):
    create_course_data(client)
    sealed = client.post(
        "/api/archives", headers=admin["headers"], json={"scope": "all", "cutoff_at": now_cutoff()}
    ).json()
    with transaction(immediate=True) as connection:
        connection.execute(
            "UPDATE archive_items SET payload_json=? WHERE archive_id=? AND source_table='compute_results'",
            ('{"score": 100}', sealed["id"]),
        )
    response = client.get(f"/api/archives/{sealed['id']}/download", headers=admin["headers"])
    assert response.status_code == 409


def test_boundary_versions_and_rule_change_creates_new_version(client, admin):
    _ = admin
    clock = FrozenClock(datetime(2026, 9, 21, 8, 0, tzinfo=UTC))
    compute = ComputeOperationsService(get_connection(), clock)
    compute.create_template(TEMPLATE, "admin")
    compute.submit(submit_payload("boundary-one"))
    clock.advance(hours=2)
    compute.submit(submit_payload("boundary-two"))

    service = ArchiveService(get_connection(), clock)
    first = service.create_or_reuse(super_principal(), {"scope": "project", "scope_value": "project-a", "cutoff_at": "2026-09-21T08:00:00+00:00"})
    second = service.create_or_reuse(super_principal(), {"scope": "project", "scope_value": "project-a", "cutoff_at": "2026-09-21T10:00:00+00:00"})

    first_status = service.status(super_principal(), first["id"])
    assert first_status["boundary_versions"]["previous"] is None
    assert first_status["boundary_versions"]["next"]["archive_id"] == second["id"]
    assert service.status(super_principal(), second["id"])["boundary_versions"]["previous"]["archive_id"] == first["id"]

    # 规则版本变化：相同范围、截止时刻与脱敏策略生成并存的新版本，而非覆盖旧版本。
    archive_service_module.RULE_VERSION = 2
    try:
        regenerated = service.create_or_reuse(
            super_principal(), {"scope": "project", "scope_value": "project-a", "cutoff_at": "2026-09-21T10:00:00+00:00"}
        )
    finally:
        archive_service_module.RULE_VERSION = 1
    assert regenerated["reused"] is False
    assert regenerated["id"] != second["id"]
    assert regenerated["rule_version"] == 2
    assert regenerated["content_digest"] != second["content_digest"]
    boundary = service.status(super_principal(), second["id"])["boundary_versions"]
    assert boundary["rule_versions_at_same_cutoff"] == [1, 2]
    assert get_connection().execute(
        "SELECT COUNT(*) FROM archives WHERE scope='project' AND status='sealed'"
    ).fetchone()[0] == 3


def test_archive_listing_reports_statuses(client, admin):
    create_course_data(client)
    client.post("/api/archives", headers=admin["headers"], json={"scope": "all", "cutoff_at": now_cutoff()})
    listing = client.get("/api/archives", headers=admin["headers"])
    assert listing.status_code == 200
    body = listing.json()
    assert body["total"] == 1
    assert body["items"][0]["status"] == "sealed"
