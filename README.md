# 拾音工坊 · 日志采集与事件流处理平台

面向多租户应用日志的结构化采集、事件流解析、格式标准化、敏感脱敏、采样归并、异常告警与归档回溯的日志采集与事件流处理平台。

这是一个前后端分离的管理平台：前端 Vue 3 + Vite + TypeScript，后端 FastAPI（Python）。
两边各自独立启动，前端 dev server 已关掉自动打开页面，启动后按终端打印的地址手工打开。

## 目录结构

```text
.
├── frontend/                 Vue 3 + Vite + TypeScript 前端
│   ├── src/views/WorkbenchView.vue|tsx  全部模块共享工作台
│   ├── src/data/modules.ts              18个业务模块配置
│   ├── src/api/              统一请求封装
│   └── vite.config.ts        dev server 配置（open: false）
├── backend/                  FastAPI（Python） 后端
│   ├── app/routers/resource.py  通用查询/导出/登记/动作接口
│   ├── app/services/<key>.py    每个模块独立领域逻辑
│   ├── app/services/base.py     共享服务骨架
│   └── app/store.py          内存数据仓库与示例数据
├── .gitignore
└── docker-compose.yml
```

## 启动

### 后端

```bash
cd backend
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
./run.sh
```

健康检查：`curl http://127.0.0.1:8000/api/health`

### 前端

```bash
cd frontend
npm ci
npm run dev
```

前端默认监听 `http://127.0.0.1:5173/`，dev server 不会自动打开浏览器，
需要自己访问。`/api` 由 vite 代理到后端 `http://127.0.0.1:8000`。

## 业务模块

| 模块 | 目录 | 业务对象 | 主要字段 |
| --- | --- | --- | --- |
| 日志源 | `log_source` | 日志来源 | 源编号、源名称、应用标识 |
| 解析规则 | `parser_rule` | 解析方案 | 方案编号、日志来源、正则表达式 |
| 脱敏规则 | `mask_rule` | 脱敏配置 | 规则编号、目标字段、脱敏方式 |
| 事件分类 | `event_type` | 事件类型 | 类型编号、类型名称、分类标签 |
| 采集作业 | `ingest_job` | 采集任务 | 作业编号、日志来源、采集模式 |
| 批次检查点 | `batch_checkpoint` | 检查点记录 | 记录编号、采集作业、文件路径 |
| 事件存储 | `event_store` | 事件记录 | 记录编号、事件类型、原始内容 |
| 异常告警 | `anomaly_rule` | 告警规则 | 规则编号、事件类型、检测条件 |
| 采样归并 | `sample_job` | 采样计划 | 计划编号、事件类型、采样比例 |
| 字段增强 | `field_enrich` | 增强规则 | 规则编号、目标字段、增强来源 |
| 归档策略 | `archive_policy` | 归档方案 | 方案编号、事件类型、保留天数 |
| 转发路由 | `forward_rule` | 转发规则 | 规则编号、事件类型、目标地址 |
| Schema版本 | `schema_version` | 版本记录 | 版本编号、日志来源、字段变更 |
| 去重过滤 | `dedup_filter` | 去重规则 | 规则编号、事件类型、去重字段 |
| 采集指标 | `ingest_metric` | 指标记录 | 记录编号、日志来源、采集速率 |
| 事件重放 | `replay_record` | 重放任务 | 任务编号、来源事件、重放范围 |
| 质量报告 | `quality_report` | 质量评估 | 报告编号、日志来源、完整率 |
| 标签分类 | `tag_taxonomy` | 标签定义 | 标签编号、标签名称、父级标签 |
| 打包导出 | `export_bundle` | 导出包 | 包编号、事件类型、时间范围 |
| 访问审计 | `audit_event` | 审计记录 | 记录编号、操作模块、操作人 |
| 租户隔离 | `tenant_isolation` | 租户配置 | 租户编号、租户名称、日志来源 |
| 格式适配 | `format_adapt` | 适配器配置 | 适配器编号、输入格式、输出格式 |

## 去重与采样归并（去重后采样批次）

去重窗口按事件**实际发生时间**计算：同一指纹的代表时间 `T` 覆盖
`[T, T + 去重窗口)`，窗口内的后续同指纹事件记为重复，窗口外的事件
重新保留。因此 60 分钟规则下 09:00 / 09:59 / 10:01 的首次计算只保留
09:00 与 10:01，不会把 60 分钟前的指纹永久当成已见。

每次去重都会形成一份可复查的 `DedupedSampleBatch`：

- `retained`：实际保留的真实事件；`deliverable`：尚未交给采样计划的代表。
- `windows`：窗口依据（规则、指纹、窗口长度、锚点、区间、代表）。
- `hit_count` / `ignore_count`：按实际原行重算并**覆盖**，不做旧累计值累加。

采样归并从去重后批次读取保留事件，再按 `sample_job` 计划选代表；每个
样本（`Sample`）都记录原始发生时间与所属区间。窗口依据与样本保存在
`DedupSamplePipeline` 中，可通过接口复查：

```bash
curl http://127.0.0.1:8000/api/dedup/batches                    # 批次列表
curl http://127.0.0.1:8000/api/dedup/batches/<batch_id>         # 批次快照
curl http://127.0.0.1:8000/api/dedup/samples/<sample_id>        # 样本与区间
curl http://127.0.0.1:8000/api/dedup/investigations/<id>        # 调查证据链
```

主要行为：

| 场景 | 行为 |
| --- | --- |
| 正序 / 反序 / 迟到补采 | 按原行重排重建，保留事件与命中数一致 |
| 同一依据重算多遍 | 不新增批次版本，09:59 的重复只计一次 |
| 确认来源更正撤回原代表 | 保留原区间，从区间内合法原行补出代表；被撤回行不再采样 |
| 已发出的旧调查 | 旧批次/旧代表按原编号保留，仍可用旧证据复算 |
| 计划已领代表后迟到更早原行 | 已领/已交代表不重交，迟到范围作为待处理保留 |
| 交付后消费确认中断再恢复 | 补确认只核销已交代表，不按重开窗口再交一遍 |
| 并发提交同一批次 | 只确认一次，一套去重依据只核销一次 |
| 已确认批次收到迟到结果 | 确认快照不被覆盖，迟到窗口按实际确认版本记录冲突 |

## 约定

- 全部模块共享`frontend/src/views/WorkbenchView.vue|tsx`和一套资源路由。
- 每个模块仍保留独立`backend/app/services/<模块>.py`；纯前端保留
  `frontend/src/domain/<模块>.ts`，用于承载真实业务差异并维持36题位容量。
- 列表接口统一返回 `{ items, total, page, size }`，动作接口统一返回 `{ ok, message }`。
- 状态流转只允许在 `app/services` 里改，路由层不做业务判断。

## 测试

后端测试是确定性脚本，不依赖 pytest：

```bash
cd backend
for f in tests/test_*.py; do .venv/bin/python "$f"; done
```

领域：数据工程
子方向：数据采集、爬虫与RPA
