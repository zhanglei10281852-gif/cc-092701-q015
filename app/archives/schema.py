from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

# 封存内容的组织与脱敏规则版本：只有规则本身变化（抽取字段、过滤口径、
# 脱敏算法等）才提升该版本；相同范围与脱敏策略在旧规则下的封存保持不可变，
# 新规则下的请求会生成并存的新版本。
RULE_VERSION = 1

ScopeType = Literal["all", "template", "project", "student"]
MaskingPolicy = Literal["standard", "full"]


class ArchiveRequest(BaseModel):
    scope: ScopeType
    cutoff_at: str = Field(..., min_length=5, max_length=40, description="截止时刻，ISO 8601；仅封存该时刻之前已经落库的记录")
    scope_value: str | None = Field(default=None, max_length=120, description="template 为课程模板编码，project 为项目编码，student 为学员账号")
    masking_policy: MaskingPolicy = Field(default="standard", description="standard 按权限脱敏联系方式；full 不脱敏")
    label: str = Field(default="", max_length=200)

    def normalized_scope_value(self) -> str | None:
        if self.scope == "all":
            return None
        value = (self.scope_value or "").strip()
        return value or None


SCOPE_SOURCE_TITLES: dict[str, dict[str, str]] = {
    "all": {"table": "全部课程域", "predicate": "不限制范围"},
    "template": {"table": "课程安排（compute_templates）", "predicate": "模板编码 = {value}"},
    "project": {"table": "项目课程（compute_tasks.project_code）", "predicate": "项目编码 = {value}"},
    "student": {"table": "学员提交（compute_tasks.requested_by）", "predicate": "学员账号 = {value}"},
}

TABLE_TITLES: dict[str, str] = {
    "compute_templates": "课程安排（compute_templates）",
    "compute_tasks": "学员提交（compute_tasks）",
    "compute_results": "成绩发布（compute_results）",
    "compute_interventions": "变更轨迹（compute_interventions）",
    "users": "教师与学员通讯录（users，已剔除口令摘要）",
}

# 每个来源的纳入口径说明，随来源清单一并冻结。
CUTOFF_RULE = "仅纳入 created_at <= cutoff_at 的记录；成绩按发布时间 created_at 判定，变更轨迹按发生时间 created_at 判定"
SCOPE_TABLES: dict[str, tuple[str, ...]] = {
    "all": ("compute_templates", "compute_tasks", "compute_results", "compute_interventions", "users"),
    "template": ("compute_templates", "compute_tasks", "compute_results", "compute_interventions"),
    "project": ("compute_tasks", "compute_results", "compute_interventions"),
    "student": ("compute_tasks", "compute_results", "compute_interventions"),
}


def scope_predicate(scope: str, scope_value: str | None) -> str:
    title = SCOPE_SOURCE_TITLES[scope]["predicate"]
    if "{value}" in title:
        return title.format(value=scope_value or "")
    return title


def canonical_request(spec: dict[str, Any]) -> dict[str, Any]:
    """范围指纹的规范化输入（不含 label、调用者等易变信息）。"""
    return {
        "scope": spec["scope"],
        "scope_value": spec["scope_value"],
        "cutoff_at": spec["cutoff_at"],
        "masking_policy": spec["masking_policy"],
        "rule_version": spec["rule_version"],
    }
