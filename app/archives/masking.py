from __future__ import annotations

import re
from copy import deepcopy
from typing import Any

from app.core.errors import PermissionDeniedError
from app.core.privacy import EMAIL_RE, ID_CARD_RE, PHONE_RE, mask_email, mask_phone, sanitize_text

# 各来源在 standard 策略下需要掩码的联系方式字段；full 策略不掩码任何字段。
CONTACT_FIELDS: dict[str, tuple[str, ...]] = {
    "users": ("phone", "email"),
}

# 学员提交/成绩的自由 JSON 中也可能夹带联系方式，standard 策略下做递归掩码。
FREEFORM_JSON_SOURCES = {"compute_tasks", "compute_results", "compute_interventions"}


class MaskingStrategy:
    """依据调用者权限确定的封存脱敏策略，策略本身会写入封存元数据。"""

    def __init__(self, policy: str, *, can_unmask: bool) -> None:
        if policy == "full" and not can_unmask:
            # 由服务层在入口拦截，这里兜底避免越权导出。
            raise PermissionDeniedError("缺少 archives.unmask 权限，不能生成未脱敏封存")
        self.policy = policy
        self.can_unmask = can_unmask
        self.masked_fields: dict[str, int] = {}

    @property
    def description(self) -> str:
        if self.policy == "full":
            return "不脱敏：调用者持有 archives.unmask 权限，保留教师与学员联系方式原文"
        return "标准脱敏：教师/学员手机号、邮箱与身份证号掩码；自由文本中的联系方式同步掩码"

    def apply(self, source_table: str, record: dict[str, Any]) -> dict[str, Any]:
        if self.policy == "full":
            return deepcopy(record)
        masked = deepcopy(record)
        for field in CONTACT_FIELDS.get(source_table, ()):  # 结构化联系方式字段
            value = masked.get(field)
            if isinstance(value, str) and value:
                masked[field] = _mask_field(field, value)
                self._count(source_table, field)
        if source_table in FREEFORM_JSON_SOURCES:  # JSON/文本中夹带的联系方式
            masked, amount = _scrub_freeform(source_table, masked)
            for _ in range(amount):
                self._count(source_table, "embedded_contact")
        return masked

    def _count(self, source_table: str, field: str) -> None:
        key = f"{source_table}.{field}"
        self.masked_fields[key] = self.masked_fields.get(key, 0) + 1


def _mask_field(field: str, value: str) -> str:
    if field == "phone":
        return mask_phone(value) or value
    if field == "email":
        return mask_email(value) or value
    return value


def _scrub_value(value: Any) -> tuple[Any, int]:
    amount = 0
    if isinstance(value, str):
        hits = len(PHONE_RE.findall(value)) + len(ID_CARD_RE.findall(value))
        if hits:
            return sanitize_text(value), hits
        if re.search(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", value):
            return EMAIL_RE.sub(lambda match: mask_email(match.group(0)) or "", value), 1
        return value, 0
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            result[key], added = _scrub_value(item)
            amount += added
        return result, amount
    if isinstance(value, list):
        result_list = []
        for item in value:
            scrubbed, added = _scrub_value(item)
            result_list.append(scrubbed)
            amount += added
        return result_list, amount
    return value, 0


def _scrub_freeform(source_table: str, record: dict[str, Any]) -> tuple[dict[str, Any], int]:
    total = 0
    json_columns = {
        "compute_tasks": ("parameters_json",),
        "compute_results": ("result_json", "metrics_json"),
        "compute_interventions": ("reason", "before_json", "after_json"),
    }.get(source_table, ())
    for column in json_columns:
        value = record.get(column)
        if value is None:
            continue
        scrubbed, added = _scrub_value(value)
        record[column] = scrubbed
        total += added
    return record, total
