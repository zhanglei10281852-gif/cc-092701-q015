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

课程任务运营接口使用 `/api/compute` 前缀，身份、角色、审计和系统接口分别位于 `/api/auth`、`/api/roles`、`/api/audit` 与 `/api/system`。认证结束后的资料封存接口位于 `/api/archives`。

## 资料封存

按范围（`all` 全部、`template` 课程模板编码、`project` 项目编码、`student` 学员账号）与截止时刻 `cutoff_at` 生成封存。封存把课程安排、学员提交、成绩发布与变更轨迹在事务内**复制冻结**到独立副本，之后业务表的增删改不会影响已封存内容。

- `POST /api/archives`：生成或复用封存（需要 `archives.read`）。`masking_policy=standard`（默认）按调用者权限掩码教师/学员手机号、邮箱及自由文本中夹带的联系方式，并始终剔除口令摘要；`full` 保留原文，生成与下载都需要 `archives.unmask`。
- `GET /api/archives/{id}/status`：封存状态、内容摘要、来源清单、数量统计、相邻边界版本与失败原因。
- `GET /api/archives/{id}/download`：只从冻结副本重组内容，并逐条校验条目摘要与封存内容摘要（SHA-256）。
- `GET /api/archives`：按范围/状态分页列出版本。

相同范围、截止时刻与脱敏策略复用同一个不可变版本（请求指纹上有部分唯一索引约束）；仅当封存规则版本提升时才并存生成新版本。生成过程在单事务内完成，失败自动回滚不留半成品副本，并把 `building` 行收口为带原因的 `failed` 版本；进程崩溃遗留的陈旧 `building` 行会在下次同范围请求时作废。

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
app/archives/       按范围与截止时刻生成的不可变资料封存
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
