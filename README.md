# 传感器校准偏差复核

Bootstrap 区间估计的真实业务分析小型项目。完整模拟客户、痛点、上下游、算法公式与一天工作剧本见 [BUSINESS.md](BUSINESS.md)。

## 模块与业务流程
数据接入（JSON/CSV、字段验证、批次指纹）→ 参数化分析（异步 Python worker）→ 结果复核（指标、图形、明细、解释、批准）→ 定时分发（本地收件箱、CSV/JSON、SHA256）；另有业务总览和审计轨迹。
三个贯穿全栈的实体：Dataset 数据批次、Job 分析任务、Report 分发计划；辅助 User、Audit、Delivery。

## 快速启动
```bash
cp .env.example .env
docker compose up -d --build --wait
docker compose exec -T backend python -m scripts.seed_demo
```
访问 http://localhost:18206；后端文档 http://localhost:19206/docs；数据库宿主端口 17706。
`SEED_DEMO=true` 自动幂等 seed；不覆盖用户修改。手动 seed 命令可重复执行。

## 演示账号与权限
|账号|密码|真实权限|
|---|---|---|
|admin@demo.local|Demo123!|接入、执行、批准、分发、暂停、读取与下载|
|analyst@demo.local|Demo123!|接入、执行、读取与下载；不能批准或安排分发|
|viewer@demo.local|Demo123!|只读与下载|

## 技术与本地开发
Python 3.12 / FastAPI / SQLAlchemy / NumPy / SciPy / scikit-learn；PostgreSQL 16；Redis 7；Nginx；原生 HTML CSS JavaScript ES modules（用户指定）。后端所有校验、持久化和算法在服务端。无前端打包步骤。
后端：安装 backend/requirements.txt，设置 DATABASE_URL、REDIS_URL、JWT_SECRET、ARTIFACT_DIR 后在 backend/ 执行 `python -m migrations.initial`、`python -m scripts.seed_demo`、`uvicorn src.main:app`，另开 `python -m src.worker`。前端使用带 /api 反向代理的 Nginx，直接打开 index.html 不支持 API。

## 目录与工程约定
backend/src/{models,schemas,services,routes,controllers,middlewares,constants,config,utils}；backend/scripts/{seed_demo.py,export_evidence.py,verify_package.py}；backend/migrations/initial.py；backend/tests/（证据链单测与端到端测试，`cd backend && python -m pytest tests/`）。
frontend/src/{api,stores,types,components/common,hooks,pages,router,utils,constants}。
Role 枚举：admin/analyst/viewer；JobStatus：queued/running/completed/failed。后端 backend/src/constants/enums.py，前端 frontend/src/constants/enums.js；路由权限在 middlewares/auth.py；页面按相同角色控制操作入口。

## 证据链（完整性保障）
接入、分析完成、批准、简报分发四个业务事件与业务变更同一事务写入哈希链证据账（`evidence_events` + 单行链头 `evidence_chain_head`）：同成同败，回滚不留成功记录。追加经链头行锁串行化（PostgreSQL `SELECT … FOR UPDATE`；SQLite `BEGIN IMMEDIATE` + WAL），多进程并发写不分叉，`seq` 主键与 `hash` 唯一约束兜底、冲突失败关闭。
- 页面「证据链」：完整性状态、首个断点（序号/类型/关联业务）、链上事件、导出记录与旧日志。证据链损坏时，后端拒绝新增批准与分发（409），前端同步禁用入口；接入不受限以保留现场。
- 导出：`POST /api/integrity/export` 或 `python -m scripts.export_evidence`，取当前链头为固定截止点生成增量证据包（Ed25519 签名）；导出期间新增记录留给下一包。私钥在 `LEDGER_KEY_DIR`（0600），公钥随包分发。
- 离线核验：`python -m scripts.verify_package 证据包.json --checkpoint 上次凭证.json --pubkey 公钥.pem`，可发现改写、丢失记录与截尾；非首包必须凭独立保管的上次凭证续验，通过后输出新凭证继续独立保管。
- 旧日志：`POST /api/integrity/legacy` 登记为「未认证历史」，登记行为入链而内容永不认证，不冒充已验证证据。
- 核验口径：`src/services/ledger_core.py` 是在线与离线共用的唯一哈希口径，`scripts/verify_package.py` 内联同口径实现（测试断言一致），可单文件拷贝到离线机器运行。

## 环境变量与 Docker
COMPOSE_PROJECT_NAME=sensor-bootstrap；FRONTEND_PORT=18206；BACKEND_PORT=19206；DB_PORT=17706；DB_PASSWORD、JWT_SECRET 见 .env.example；SEED_DEMO 默认 true。共享命名产物卷供后端下载与 worker 写入，数据库/Redis 各持久卷。
恰好五服务均有健康检查。Redis 队列加 SQL 排队状态兜底；worker 按 next_run 生成本地收件箱文件。周期 60 秒至 30 天。分发结果为批准分析的固定快照；若需新数据重新计算并建立新计划。当前不连接邮件或企业聊天。
错误响应、请求编号、Redis 每 IP 每分钟 240 次限流、JWT 和数据库操作审计。演示密钥与密码仅供本机模拟；生产部署前配置独立密钥与账号。证据链签名私钥默认在 `LEDGER_KEY_DIR`（缺省 `ARTIFACT_DIR/ledger-keys`），证据包与凭证默认导出到 `LEDGER_EXPORT_DIR`（缺省 `ARTIFACT_DIR/ledger-exports`）；凭证文件须复制到独立介质保管，生产环境建议改用 KMS/HSM 托管私钥。

## 数据与验收
所有数据为固定随机种子生成的模拟业务数据，不能作为实际生产决策证据。项目独立算法、输入边界及业务局限详见 BUSINESS.md。测试与截图统一存放 ../../test-artifacts/gb-1007/，源码不含日志/截图/测试报告。
清理本项目演示数据：`docker compose down -v --remove-orphans`（会删除本项目命名卷）。

## License
MIT，见 LICENSE。
