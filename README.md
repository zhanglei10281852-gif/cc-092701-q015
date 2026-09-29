# 职业教学任务运营服务

这是一个面向职业院校教务团队、授课教师和课程管理员的 Python 后端服务，用于管理课程任务模板、学员提交、执行队列、教师工作者、结果版本和运营干预。服务保留登录、角色权限、会话、审计和配额等基础能力，所有业务状态与审计事件写入本地 SQLite 数据库，适合在单个应用容器中离线运行。

## 运行环境

- Python 3.11
- SQLite 3（由 Python 标准库提供）
- FastAPI 与 Uvicorn

## 安装

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

默认数据库位于 `./data/compute-operations.db`，可复制 `.env.example` 并设置 `TOWNSHIP_DATABASE_PATH` 指向其他本地路径。

## 初始化与启动

```bash
python -m app.cli init-db
python -m app.cli check-db
uvicorn app.main:app --host 0.0.0.0 --port 8432
```

健康检查：

```bash
curl -sS http://127.0.0.1:8432/api/system/health
```

课程任务运营接口使用 `/api/compute` 前缀，身份、角色、审计和系统接口分别位于 `/api/auth`、`/api/roles`、`/api/audit` 与 `/api/system`。

## 教学资料封存

认证检查结束后，可以按范围和截止时刻对课程安排、学员提交与成绩发布做资料封存，接口前缀为 `/api/archives`：

- `POST /api/archives` 生成封存。请求体包含 `scope`（项目、模板、提交人至少其一）、`cutoff_at`（截止时刻，不能晚于当前时间）、`disclosure`（`masked` 默认脱敏，`full` 需要 `archives.sensitive` 权限）和 `reason`（封存事由）。范围、截止时刻与脱敏策略完全相同的再次请求复用已封存版本（响应 200 且 `reused=true`）；任一规则变化都会在相同范围族下生成新的版本号。
- 生成在单个即时事务内完成，失败不会留下半成品；失败原因单独落库，可通过列表与解释接口查询，重试成功不影响版本连续性。
- `GET /api/archives/{id}/download` 下载封存内容。内容在封存时刻物化存储，数据库触发器禁止修改或删除封存记录，业务后续变化不会改变下载结果；未脱敏版本的下载始终要求 `archives.sensitive` 权限。
- 封存内容包含教师名录（模板作者与成绩发布人），默认脱敏邮箱与电话；元信息携带内容摘要（SHA-256）、来源清单（来源表与记录区间）和数量统计。
- `GET /api/archives/explain?project_code=...` 解释某个范围的封存状态、边界版本（各版本的截止时刻与内容摘要）与失败原因；`GET /api/archives`、`GET /api/archives/{id}` 提供分页列表与单条元信息。

封存相关权限：`archives.read`（查看）、`archives.create`（生成）、`archives.sensitive`（未脱敏）。生成、下载与失败都会写入审计事件。

## 测试与编译检查

```bash
python -m pytest
python -m compileall -q app tests
```

本地冒烟命令：

```bash
python -m app.cli smoke
python -m app.cli compute-demo
```

## 目录结构

```text
app/compute/       任务模板、配额、提交、领取、回执和人工干预
app/archive/       按范围与截止时刻生成、脱敏并冻结的资料封存
app/api/            登录、角色、审计和系统管理接口
app/core/           时钟、安全、异常和分页能力
app/repositories/   SQLite 查询与事务封装
app/services/       身份、审计和后台任务服务
app/database.py     SQLite 连接、事务、表结构和权限初始化
tests/              领域、接口、调度和身份回归测试
tools/              本地维护脚本
```

## 数据一致性

SQLite 连接启用外键、WAL 和忙等待策略。提交、领取、回执和人工干预在即时事务中完成；租约、配额与结果版本使用可注入时钟，便于复现跨日和恢复边界。会话令牌只保存摘要，审计与人工干预记录不会写入明文密码或令牌。
