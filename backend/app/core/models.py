"""拾音工坊核心数据模型：真实日志采集与事件流处理的数据结构。"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class LogFormat(Enum):
    """日志格式枚举，对应 parser_rule 的正则表达式匹配。"""
    ACCESS = "access"
    APP = "app"
    SYS = "sys"
    CUSTOM = "custom"


class ParseResultStatus(Enum):
    """解析结果状态。"""
    OK = "ok"
    FORMAT_MISMATCH = "format_mismatch"
    FIELD_MISSING = "field_missing"
    ENCODING_ERROR = "encoding_error"
    LINE_EMPTY = "line_empty"


class MaskMethod(Enum):
    """脱敏方式枚举。"""
    PHONE = "phone"
    ID_CARD = "id_card"
    EMAIL = "email"
    IP = "ip"
    TOKEN = "token"
    CUSTOM_REGEX = "custom_regex"


@dataclass
class LogSourceConfig:
    """日志来源配置模型——对应 log_source 模块。"""
    source_id: str
    source_name: str
    app_label: str
    log_path: str
    log_format: str
    encoding: str = "utf-8"
    collect_method: str = "file_tail"
    access_state: str = "待验证"

    def match_format(self, line: str) -> bool:
        """校验一条日志行是否匹配此来源的格式。"""
        if self.log_format == "access":
            return bool(re.match(
                r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s.*?"[A-Z]+\s\S+\sHTTP',
                line.strip()))
        if self.log_format == "app":
            return bool(re.match(
                r'^\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\.\d{3}\s+\[.*?\]\s+(INFO|WARN|ERROR|DEBUG)\s+',
                line.strip()))
        if self.log_format == "sys":
            return bool(re.match(
                r'^[\w-]+\s+\d+\s+\d{2}:\d{2}:\d{2}\s+[\w-]+\s+[\w-]+\[',
                line.strip()))
        return bool(line.strip() and len(line.strip()) > 10)


@dataclass
class ParseRule:
    """解析规则模型——对应 parser_rule 模块。"""
    rule_id: str
    source_id: str
    regex_pattern: str
    field_names: list[str]
    time_format: str = "%Y-%m-%d %H:%M:%S"
    multiline: bool = False
    priority: int = 0
    state: str = "草稿"
    _compiled_re: re.Pattern[str] | None = field(default=None, repr=False, compare=False)

    def compile(self) -> re.Pattern[str]:
        """编译正则表达式（惰性编译）。"""
        if self._compiled_re is None:
            self._compiled_re = re.compile(self.regex_pattern)
        return self._compiled_re

    def parse(self, line: str) -> tuple[ParseResultStatus, dict[str, str] | None]:
        """用解析规则提取一条日志行的字段。"""
        try:
            compiled = self.compile()
            m = compiled.match(line.strip())
            if m is None:
                return ParseResultStatus.FORMAT_MISMATCH, None
            fields = dict(zip(self.field_names, m.groups()))
            missing = [name for name in self.field_names if name not in fields]
            if missing:
                return ParseResultStatus.FIELD_MISSING, fields
            return ParseResultStatus.OK, fields
        except re.error:
            return ParseResultStatus.FORMAT_MISMATCH, None


@dataclass
class LogEntry:
    """单条日志条目——跨模块流转的核心数据载体。"""
    raw_line: str
    line_number: int
    source_id: str
    parsed_fields: dict[str, str] | None = None
    parse_status: ParseResultStatus = ParseResultStatus.OK
    event_time: datetime | None = None
    host: str = ""
    checksum: str = field(default="")

    def compute_checksum(self) -> str:
        """基于原始行和解析字段计算内容校验哈希。"""
        raw = (
            f"{self.source_id}|{self.line_number}|{self.raw_line[:200]}"
            f"|{sorted((self.parsed_fields or {}).items())}"
        )
        return hashlib.sha256(raw.encode()).hexdigest()

    def __post_init__(self):
        if not self.checksum:
            self.checksum = self.compute_checksum()


@dataclass
class MaskRule:
    """脱敏规则模型——对应 mask_rule 模块。"""
    rule_id: str
    target_field: str
    mask_method: MaskMethod
    mask_pattern: str
    retain_count: int = 0
    rule_state: str = "草稿"

    def apply(self, value: str) -> str:
        """对字段值执行脱敏变换。"""
        if not value:
            return value
        if self.mask_method == MaskMethod.PHONE:
            if len(value) >= 11:
                return value[:3] + "****" + value[-4:]
            return value[:1] + "****" + value[-1:] if len(value) > 2 else "****"
        if self.mask_method == MaskMethod.ID_CARD:
            if len(value) >= 18:
                return value[:6] + "********" + value[-4:]
            return value[:2] + "****" + value[-2:] if len(value) > 4 else "****"
        if self.mask_method == MaskMethod.EMAIL:
            parts = value.split("@")
            if len(parts) == 2:
                local = parts[0]
                masked_local = local[:2] + "***" + local[-1:] if len(local) > 3 else "***"
                return f"{masked_local}@{parts[1]}"
            return "***@***"
        if self.mask_method == MaskMethod.IP:
            octets = value.split(".")
            if len(octets) == 4:
                return f"{octets[0]}.{octets[1]}.*.*"
            return "***.***.***.***"
        if self.mask_method == MaskMethod.CUSTOM_REGEX:
            compiled = re.compile(self.mask_pattern)
            return compiled.sub("***", value)
        return value


@dataclass
class MaskResult:
    """脱敏变换结果——记录哪个字段被何种方式脱敏。"""
    rule_id: str
    field_name: str
    original: str
    masked: str
    method: MaskMethod
    is_masked: bool = True

    def verify(self) -> bool:
        """校验脱敏结果：敏感原值不应出现在掩码后的结果中。"""
        if not self.is_masked:
            return True
        if len(self.original) < 3:
            return self.masked != self.original
        core = self.original[3:-3] if len(self.original) > 6 else self.original
        return core not in self.masked


@dataclass
class FieldEnrichRule:
    """字段增强规则——对应 field_enrich 模块。"""
    rule_id: str
    target_field: str
    enrich_source: str
    mapping_dict: dict[str, str]
    default_value: str = "unknown"
    priority: int = 0

    def enrich(self, fields: dict[str, str]) -> str:
        """根据映射字典增强目标字段。"""
        key = fields.get(self.enrich_source, "").strip()
        return self.mapping_dict.get(key, self.default_value)


@dataclass
class EventTypeDef:
    """事件类型定义——对应 event_type 模块。"""
    type_id: str
    type_name: str
    category_tag: str
    severity: str = "INFO"
    alert_threshold: int = 0
    sample_ratio: float = 1.0
    retain_days: int = 30


@dataclass
class EventRecord:
    """标准化事件记录——解析、脱敏、增强后的最终产物。"""
    record_id: str
    event_type: EventTypeDef
    original_content: str
    parsed_fields: dict[str, str]
    masked_fields: dict[str, str]
    enriched_fields: dict[str, str]
    event_time: datetime
    source_host: str
    store_partition: str = ""
    index_state: str = "已写入"
    # 去重/采样回溯信息：所属窗口区间、批次、样本。
    window_start: datetime | None = None
    window_end: datetime | None = None
    window_basis: dict[str, Any] = field(default_factory=dict)
    batch_id: str = ""
    sample_id: str = ""
    sample: Any = field(default=None, repr=False, compare=False)


@dataclass
class DedupFilter:
    """去重过滤规则——对应 dedup_filter 模块。"""
    rule_id: str
    event_type_id: str
    dedup_fields: list[str]
    window_minutes: int = 60
    fingerprint_algo: str = "sha256"
    hit_count: int = 0
    ignore_count: int = 0

    def fingerprint(self, event: EventRecord) -> str:
        """基于去重字段生成事件指纹。"""
        key_parts = [event.event_type.type_id]
        for field in sorted(self.dedup_fields):
            val = event.parsed_fields.get(field) or event.masked_fields.get(field) or ""
            key_parts.append(f"{field}={val}")
        raw_key = "|".join(key_parts)
        return hashlib.sha256(raw_key.encode()).hexdigest()

    def is_duplicate(self, event: EventRecord, seen_fingerprints: set[str]) -> bool:
        """判断事件是否重复。"""
        fp = self.fingerprint(event)
        if fp in seen_fingerprints:
            self.hit_count += 1
            return True
        seen_fingerprints.add(fp)
        return False


@dataclass
class SampleConfig:
    """采样归并配置——对应 sample_job 模块。"""
    plan_id: str
    event_type_id: str
    sample_ratio: float
    merge_key: str = ""
    merge_window_minutes: int = 5
    retain_policy: str = "latest"


@dataclass
class BatchCheckpoint:
    """批次检查点——对应 batch_checkpoint 模块。"""
    checkpoint_id: str
    job_id: str
    file_path: str
    byte_offset: int
    line_count: int
    content_hash: str
    check_time: datetime = field(default_factory=datetime.now)
    state: str = "已记录"


@dataclass
class IngestJob:
    """采集作业模型——对应 ingest_job 模块。"""
    job_id: str
    source_id: str
    collect_mode: str = "incremental"
    file_cursor: int = 0
    batch_size: int = 100
    thread_count: int = 1
    processed_lines: int = 0
    skipped_lines: int = 0
    state: str = "待执行"


@dataclass
class IngestMetric:
    """采集指标——对应 ingest_metric 模块。"""
    metric_id: str
    source_id: str
    ingest_rate: float = 0.0
    process_delay_ms: float = 0.0
    error_rate: float = 0.0
    backlog_lines: int = 0
    sample_time: datetime = field(default_factory=datetime.now)


@dataclass
class QualityReport:
    """质量报告——对应 quality_report 模块。"""
    report_id: str
    source_id: str
    completeness_rate: float = 0.0
    parse_success_rate: float = 0.0
    field_coverage_rate: float = 0.0
    time_delay_seconds: float = 0.0
    eval_period: str = "daily"
    state: str = "待生成"


@dataclass
class AnomalyRule:
    """异常告警规则——对应 anomaly_rule 模块。"""
    rule_id: str
    event_type_id: str
    detect_condition: str
    alert_level: str = "WARNING"
    trigger_frequency: int = 1
    aggregate_window_minutes: int = 5
    notify_channel: str = "webhook"


@dataclass
class ForwardRule:
    """转发路由规则——对应 forward_rule 模块。"""
    rule_id: str
    event_type_id: str
    target_address: str
    forward_format: str = "json"
    batch_size: int = 100
    retry_limit: int = 3
    timeout_seconds: int = 30

# ---------- 去重窗口 / 去重后采样批次 / 样本 / 调查 ----------
# 这些模型把“有效重复区间”持久化下来：每个窗口记录指纹、区间依据、
# 实际代表和全部成员原行；批次是窗口与保留事件的不可变快照；样本记录
# 原始发生时间和所属区间，供调查刷新与回溯查询。


@dataclass
class DedupWindow:
    """某个指纹的一段有效重复区间——去重窗口的持久化依据。

    start_time/end_time 是窗口实际生效的区间，representative 是区间内
    仍合法的最早原行（首见代表）；members 保存窗口内全部原行（包含重复
    行与被撤回行），用于来源更正后从仍合法原行补出代表。
    """
    fingerprint: str
    rule_id: str
    window_minutes: int
    start_time: datetime
    end_time: datetime
    representative: EventRecord | None = None
    members: list[EventRecord] = field(default_factory=list)
    state: str = "pending"  # pending / claimed / delivered / confirmed
    replaced_representative_ids: list[str] = field(default_factory=list)
    # 窗口内重复数（命中/忽略按实际原行重算，覆盖而非累加）。
    duplicate_count: int = 0
    # 更正来源后需要保留的既有区间：即使代表被撤回也从区间内合法原行补位。
    preserve_interval: bool = False

    @property
    def representative_id(self) -> str:
        return self.representative.record_id if self.representative else ""

    @property
    def member_ids(self) -> list[str]:
        return [member.record_id for member in self.members]

    @property
    def anchor_time(self) -> datetime:
        """窗口锚点：代表的原始发生时间；没有代表时退回区间起点。"""
        return self.representative.event_time if self.representative else self.start_time

    def contains(self, event_time: datetime) -> bool:
        return self.start_time <= event_time < self.end_time

    def legal_members(self, invalid_ids: set[str] | None = None) -> list[EventRecord]:
        invalid = invalid_ids or set()
        return [member for member in self.members if member.record_id not in invalid]

    def duplicate_count(self, invalid_ids: set[str] | None = None) -> int:
        legal = self.legal_members(invalid_ids)
        representative_legal = bool(
            self.representative
            and self.representative.record_id not in (invalid_ids or set())
        )
        return max(0, len(legal) - (1 if representative_legal else 0))

    def basis(self) -> dict[str, object]:
        """窗口依据：规则、指纹、窗口长度、锚点、区间和代表。"""
        return {
            "rule_id": self.rule_id,
            "fingerprint": self.fingerprint,
            "window_minutes": self.window_minutes,
            "anchor_time": self.anchor_time.isoformat(),
            "window_start": self.start_time.isoformat(),
            "window_end": self.end_time.isoformat(),
            "representative_id": self.representative_id,
            "state": self.state,
        }

    def snapshot(self) -> "DedupWindow":
        """生成不可变快照，供批次保存，避免并发读到同一指纹的两个版本。"""
        return DedupWindow(
            fingerprint=self.fingerprint,
            rule_id=self.rule_id,
            window_minutes=self.window_minutes,
            start_time=self.start_time,
            end_time=self.end_time,
            representative=self.representative,
            members=list(self.members),
            state=self.state,
            replaced_representative_ids=list(self.replaced_representative_ids),
            duplicate_count=self.duplicate_count,
            preserve_interval=self.preserve_interval,
        )


@dataclass
class DedupedSampleBatch:
    """可复查的去重后采样批次——去重端交给采样端的证据快照。

    retained 是此刻实际保留的全部真实事件；deliverable 是本批次尚未交付
    给采样计划的代表；windows 保存窗口依据。已确认批次不会被迟到结果改写。
    """
    batch_id: str
    investigation_id: str | None
    rule_id: str
    event_type_id: str
    window_minutes: int
    version: int
    created_at: datetime
    retained: list[EventRecord] = field(default_factory=list)
    deliverable: list[EventRecord] = field(default_factory=list)
    windows: list[DedupWindow] = field(default_factory=list)
    hit_count: int = 0
    ignore_count: int = 0
    state: str = "pending"  # pending / partially_delivered / delivered / confirmed / superseded
    sample_ids: list[str] = field(default_factory=list)
    raw_record_ids: list[str] = field(default_factory=list)
    invalid_record_ids: list[str] = field(default_factory=list)
    legal_record_ids: list[str] = field(default_factory=list)
    delivered_ids: list[str] = field(default_factory=list)
    claimed_ids: list[str] = field(default_factory=list)
    settled_ids: list[str] = field(default_factory=list)
    conflicts: list[dict[str, object]] = field(default_factory=list)
    basis_signature: str = ""
    acknowledged: bool = False
    acknowledged_at: datetime | None = None
    confirm_count: int = 0
    confirmed_at: datetime | None = None
    delivered_at: datetime | None = None
    superseded_by: str | None = None

    @property
    def retained_ids(self) -> list[str]:
        return [record.record_id for record in self.retained]

    @property
    def deliverable_ids(self) -> list[str]:
        return [record.record_id for record in self.deliverable]

    @property
    def pending_records(self) -> list[EventRecord]:
        return list(self.deliverable)

    def window_for(self, record_id: str) -> DedupWindow | None:
        for window in self.windows:
            if window.representative_id == record_id:
                return window
        for window in self.windows:
            if record_id in window.member_ids:
                return window
        return None

    def retained_window_basis(self) -> list[dict[str, object]]:
        return [window.basis() for window in self.windows]


# 兼容不同命名习惯的别名，保持调用侧语义清晰。
DedupBatch = DedupedSampleBatch
DedupSampleBatch = DedupedSampleBatch


@dataclass
class Sample:
    """采样代表——记录原始发生时间、所属去重窗口和所属批次/调查。"""
    sample_id: str
    batch_id: str
    investigation_id: str | None
    plan_id: str
    record_id: str
    event_time: datetime
    window_start: datetime
    window_end: datetime
    fingerprint: str = ""
    merge_key: str = ""
    state: str = "pending"  # pending / claimed / delivered / confirmed / superseded
    created_at: datetime = field(default_factory=datetime.now)
    confirmed_at: datetime | None = None
    superseded_by: str | None = None
    window_basis: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "sample_id": self.sample_id,
            "batch_id": self.batch_id,
            "investigation_id": self.investigation_id,
            "plan_id": self.plan_id,
            "record_id": self.record_id,
            "event_time": self.event_time.isoformat(),
            "window_start": self.window_start.isoformat(),
            "window_end": self.window_end.isoformat(),
            "fingerprint": self.fingerprint,
            "state": self.state,
        }


SampleRecord = Sample


@dataclass
class Investigation:
    """一次去重采样调查——持有原始行、窗口、批次和样本的完整证据链。

    调查自身保存 raw_records 快照，来源更正只作用于被更正的那个调查；
    已发出的旧调查仍能用旧证据复算，旧批次和旧代表也一直可按编号查回。
    """
    investigation_id: str
    rule: DedupFilter
    window_minutes: int
    created_at: datetime = field(default_factory=datetime.now)
    config: SampleConfig | None = None
    state: str = "进行中"
    raw_records: dict[str, EventRecord] = field(default_factory=dict)
    invalid_ids: set[str] = field(default_factory=set)
    windows: list[DedupWindow] = field(default_factory=list)
    batch_ids: list[str] = field(default_factory=list)
    sample_ids: list[str] = field(default_factory=list)
    origin_investigation_id: str | None = None
    superseded_by: str | None = None
    delivered_ids: set[str] = field(default_factory=set)
    claimed_ids: set[str] = field(default_factory=set)
    settled_ids: set[str] = field(default_factory=set)
    confirmed_batch_ids: list[str] = field(default_factory=list)
    version: int = 0
    hit_count: int = 0
    ignore_count: int = 0
    last_batch_id: str | None = None

    @property
    def rule_id(self) -> str:
        return self.rule.rule_id

    @property
    def event_type_id(self) -> str:
        return self.rule.event_type_id

    def legal_records(self) -> list[EventRecord]:
        return [
            record for record_id, record in self.raw_records.items()
            if record_id not in self.invalid_ids
        ]

    def add_records(self, records: list[EventRecord]) -> None:
        for record in records:
            self.raw_records[record.record_id] = record
