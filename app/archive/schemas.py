from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, model_validator


class ArchiveScope(BaseModel):
    """封存范围：至少限定项目、模板或提交人之一。"""

    project_code: str | None = Field(default=None, max_length=80)
    template_code: str | None = Field(default=None, max_length=64)
    requested_by: str | None = Field(default=None, max_length=80)

    @model_validator(mode="after")
    def at_least_one_dimension(self) -> "ArchiveScope":
        if not any([self.project_code, self.template_code, self.requested_by]):
            raise ValueError("封存范围至少需要包含项目、模板或提交人之一")
        return self


class ArchiveCreate(BaseModel):
    scope: ArchiveScope
    cutoff_at: datetime
    disclosure: Literal["masked", "full"] = "masked"
    reason: str = Field(min_length=2, max_length=500)
