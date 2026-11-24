"""拾音工坊去重与采样归并管道：event_type→dedup_filter→sample_job。

数据流：事件分类 → 去重过滤 → 采样归并
涉及模块：event_type, dedup_filter, sample_job

关键语义——一次去重计算的“有效重复区间”：

* 指纹由 dedup_fields 生成；每个指纹持有若干窗口，窗口从代表（区间内最早的
  合法原行）的 event_time 起算，长度为规则 window_minutes，区间是
  ``[start, end)``。窗口内的后续同指纹原行记为重复（命中/忽略），
  **不会**把窗口顺延；超过区间边界才开启新代表。因此 09:00、09:59、10:01
  在 60 分钟规则下首次计算只保留 09:00 与 10:01。
* 每次计算都从调查持有的全部**原始行**按发生时间重排后重建，正序、反序、
  迟到补采得到一致结果；命中/忽略数按实际原行重新核销，不做“旧累计值再加”。
* 窗口依据持久保存在调查和批次里，并与实际样本关联；重算、刷新调查可复算。
* 已被计划领取/交付/确认的代表是“实际确认版本”：迟到的更早原行只能开启
  自己的待处理区间，不能把已交代表按重开的窗口再交一遍，也不能丢掉新范围。
* 一次已确认来源更正撤回原代表的有效事件时间时，保留原窗口区间，从该区间
  仍合法的原行补出代表；被撤回行不再参与采样。更正默认派生新调查，已发出
  的旧调查仍保留旧证据、可按原编号复算。
* 批次是窗口与保留事件的快照；并发/重复提交同一批次只确认一次，
  已确认样本不会被迟到结果覆盖。
"""
from __future__ import annotations

import copy
import hashlib
import threading
from datetime import datetime, timedelta

from app.core.models import (
    DedupedSampleBatch, DedupFilter, DedupWindow, EventRecord, Investigation,
    Sample, SampleConfig,
)


# ---------- 预置去重过滤规则 ----------

PRESET_DEDUP_RULES: list[DedupFilter] = [
    DedupFilter(
        rule_id="DEDU-0001",
        event_type_id="EVEN-0001",
        dedup_fields=["client_ip", "url"],
        window_minutes=60,
        fingerprint_algo="sha256",
    ),
    DedupFilter(
        rule_id="DEDU-0002",
        event_type_id="EVEN-0002",
        dedup_fields=["level", "message"],
        window_minutes=10,
        fingerprint_algo="sha256",
    ),
]

# ---------- 预置采样归并配置 ----------

PRESET_SAMPLE_CONFIGS: list[SampleConfig] = [
    SampleConfig(
        plan_id="SAMP-0001",
        event_type_id="EVEN-0001",
        sample_ratio=0.5,
        merge_key="client_ip",
        merge_window_minutes=5,
        retain_policy="latest",
    ),
    SampleConfig(
        plan_id="SAMP-0002",
        event_type_id="EVEN-0002",
        sample_ratio=1.0,
        merge_key="message",
        merge_window_minutes=10,
        retain_policy="latest",
    ),
]


class BatchRecordList(list):
    """去重结果列表：本身是 ``list[EventRecord]``，同时携带所属批次。

    保持 ``deduped, hit, ignored = pipeline.deduplicate(...)`` 的既有解包方式，
    又让调用方可以 ``result.batch`` 直接拿到可复查的批次。
    """

    def __init__(self, records=(), batch: DedupedSampleBatch | None = None):
        super().__init__(records)
        self.batch = batch


class SampleList(list):
    """采样结果列表：承载代表事件，同时可访问 :class:`Sample` 明细。"""

    def __init__(self, records=(), samples: list[Sample] | None = None,
                 batch: DedupedSampleBatch | None = None):
        super().__init__(records)
        self.samples = samples or []
        self.batch = batch


class DedupSamplePipeline:
    """去重与采样归并处理管道。

    接收 EventRecord 集合 → dedup_filter 去重 → sample_job 采样归并
    """

    def __init__(self, dedup_rules: list[DedupFilter] | None = None,
                 sample_configs: list[SampleConfig] | None = None):
        if dedup_rules is None:
            dedup_rules = copy.deepcopy(PRESET_DEDUP_RULES)
        if sample_configs is None:
            sample_configs = copy.deepcopy(PRESET_SAMPLE_CONFIGS)
        self.dedup_rules = dedup_rules
        self.sample_configs = sample_configs
        # 兼容旧属性：只用于观测当前活跃指纹，不再参与“永久已见”判定。
        self._fingerprint_store: dict[str, set[str]] = {}
        self._lock = threading.RLock()
        self._investigations: dict[str, Investigation] = {}
        self._batches: dict[str, DedupedSampleBatch] = {}
        self._samples: dict[str, Sample] = {}
        self._default_investigation: dict[str, str] = {}
        self._sample_seq = 0
        self._investigation_seq = 0
        self._last_investigation_id: str | None = None

    # ---------- 数据流 4: event_type → dedup_filter → sample_job ----------

    def deduplicate(self, records: list[EventRecord],
                    dedup_rule: DedupFilter,
                    investigation_id: str | None = None,
                    batch_id: str | None = None,
                    recompute: bool = True) -> tuple[BatchRecordList, int, int]:
        """对事件集合按 dedup_filter 执行去重，并形成可复查批次。

        每条事件按去重字段生成 SHA256 指纹；只有落在窗口
        ``[代表时间, 代表时间 + window_minutes)`` 内的同指纹事件才算重复。
        窗口不会因为出现重复而顺延——这正是 09:00、09:59、10:01 中
        09:00 与 10:01 都被保留的原因。

        返回：(去重后记录列表(携带 batch), 命中次数, 忽略次数)。
        命中/忽略数是对当前调查全部合法原行重算后的值，不做增量累加。
        """
        with self._lock:
            investigation = self._ensure_investigation(dedup_rule,
                                                       investigation_id)
            if recompute:
                investigation.add_records(records)
                batch = self._rebuild(investigation, batch_id=batch_id)
            else:
                batch = self._latest_batch(investigation)
                if batch is None:
                    investigation.add_records(records)
                    batch = self._rebuild(investigation, batch_id=batch_id)
            return (BatchRecordList(batch.retained, batch=batch),
                    batch.hit_count, batch.ignore_count)

    def deduplicate_all(self, records: list[EventRecord],
                        investigation_id: str | None = None) -> BatchRecordList:
        """按事件类型匹配去重规则批量去重。

        每种事件类型匹配对应的 dedup_filter 规则；未匹配规则的事件原样保留。
        """
        with self._lock:
            result: list[EventRecord] = list(records)
            last_batch: DedupedSampleBatch | None = None
            for dedup_rule in self.dedup_rules:
                target_type_id = dedup_rule.event_type_id
                target_records = [r for r in result
                                  if r.event_type.type_id == target_type_id]
                other_records = [r for r in result
                                 if r.event_type.type_id != target_type_id]
                if target_records:
                    investigation = self._ensure_investigation(
                        dedup_rule, investigation_id)
                    investigation.add_records(target_records)
                    last_batch = self._rebuild(investigation)
                    deduped: list[EventRecord] = list(last_batch.retained)
                else:
                    deduped = []
                result = deduped + other_records
            return BatchRecordList(result, batch=last_batch)

    # ---------- 采样归并 ----------

    def sample(self, records, config: SampleConfig, *,
               batch: DedupedSampleBatch | None = None,
               batch_id: str | None = None,
               investigation_id: str | None = None,
               claim: bool = True) -> SampleList:
        """按采样配置从去重后批次选代表。

        - ``records`` 可以传真实事件列表，也可以直接传
          :class:`DedupedSampleBatch`（等价于从批次读取保留事件）。
        - 传了批次上下文时，只从批次快照的保留事件中取，且已被领取/交付/
          确认的代表不会再次被采样（“不能按重开的窗口再交一遍”）。
        - 每个输出代表都带 :class:`Sample` 明细，记录原始发生时间与所属区间。
        """
        with self._lock:
            target_batch = batch
            if isinstance(records, DedupedSampleBatch):
                target_batch = records
            if target_batch is None and batch_id:
                target_batch = self._batches.get(batch_id)

            investigation = None
            if target_batch is not None and target_batch.investigation_id:
                investigation = self._investigations.get(
                    target_batch.investigation_id)
            if investigation is None and investigation_id:
                investigation = self._investigations.get(investigation_id)

            if target_batch is not None:
                invalid = set(target_batch.invalid_record_ids)
                source = [r for r in target_batch.retained
                          if r.record_id not in invalid]
                # 已领/已交/已确认代表不会再次被采样：即便本次只是回看
                # （claim=False），也只能看到下一批尚未领取的代表。
                claimed = set(target_batch.claimed_ids) | set(
                    target_batch.delivered_ids) | set(
                    target_batch.settled_ids)
                if investigation is not None:
                    claimed |= (set(investigation.claimed_ids)
                                | set(investigation.delivered_ids)
                                | set(investigation.settled_ids))
                source = [r for r in source if r.record_id not in claimed]
            else:
                source = list(records)

            source = sorted(source, key=lambda r: (r.event_time, r.record_id))
            threshold = max(1, int(len(source) * config.sample_ratio))
            sampled = list(source[:threshold])

            # 归并：按 merge_key 分组，每组保留最新（或按 retain_policy）。
            if config.merge_key:
                merged: dict[str, EventRecord] = {}
                for record in sampled:
                    mkey = record.parsed_fields.get(config.merge_key, "")
                    if not mkey:
                        continue
                    existing = merged.get(mkey)
                    if existing is None or (
                            config.retain_policy != "earliest"
                            and record.event_time > existing.event_time):
                        merged[mkey] = record
                sampled = sorted(merged.values(),
                                 key=lambda r: (r.event_time, r.record_id))

            samples = self._build_samples(sampled, config, target_batch,
                                          investigation, investigation_id)
            if claim and target_batch is not None:
                self._claim_in_batch(target_batch, samples)
            return SampleList(sampled, samples=samples, batch=target_batch)

    def sample_all(self, records: list[EventRecord]) -> list[EventRecord]:
        """按事件类型匹配采样配置批量采样归并（不产生领取记录）。"""
        with self._lock:
            result: list[EventRecord] = []
            handled_type_ids: set[str] = set()
            for config in self.sample_configs:
                target_type_id = config.event_type_id
                target_records = [r for r in records
                                  if r.event_type.type_id == target_type_id]
                handled_type_ids.add(target_type_id)
                sampled = self.sample(target_records, config, claim=False)
                result.extend(sampled)
            for record in records:
                if record.event_type.type_id not in handled_type_ids:
                    result.append(record)
            return result

    def sample_batch(self, batch_id: str, config: SampleConfig | None = None,
                     *, claim: bool = True) -> SampleList:
        """从指定去重后采样批次读取保留事件并选代表。"""
        with self._lock:
            batch = self._batches.get(batch_id)
            if batch is None:
                return SampleList()
            if config is None:
                config = self._config_for(batch)
            return self.sample(batch, config, batch=batch, claim=claim)

    def claim_samples(self, batch_id: str, plan_id: str | None = None,
                      count: int | None = None,
                      config: SampleConfig | None = None) -> SampleList:
        """计划领取批次代表——“已领”后不会再被下一次取样重复交出。"""
        with self._lock:
            batch = self._batches.get(batch_id)
            if batch is None:
                return SampleList()
            if config is None:
                config = self._config_for(batch)
            samples = self.sample(batch, config, batch=batch, claim=False)
            chosen = list(samples.samples)
            if count is not None:
                chosen = chosen[:count]
            chosen_ids = {sample.sample_id for sample in chosen}
            records = [record for record in samples
                       if getattr(record, "sample_id", "") in chosen_ids]
            for sample in chosen:
                if plan_id is not None:
                    sample.plan_id = plan_id
                sample.state = "claimed"
            self._claim_in_batch(batch, chosen)
            if chosen:
                investigation = self._investigations.get(
                    batch.investigation_id or "")
                if investigation is not None:
                    self._rebuild(investigation)
            return SampleList(records, samples=chosen, batch=batch)

    def claim_representative(self, batch_id: str, record_id: str,
                             plan_id: str | None = None,
                             config: SampleConfig | None = None) -> Sample | None:
        """按代表编号领取（例如计划已领取 10:01 代表但尚未写入统计）。"""
        with self._lock:
            batch = self._batches.get(batch_id)
            if batch is None:
                return None
            record = next(
                (r for r in batch.retained if r.record_id == record_id), None)
            if record is None or record_id in batch.invalid_record_ids:
                return None
            if record_id in (set(batch.claimed_ids) | set(batch.delivered_ids)
                             | set(batch.settled_ids)):
                # 已领取/交付的代表不重复生成样本。
                existing = next(
                    (s for s in self._samples.values()
                     if s.batch_id == batch_id and s.record_id == record_id),
                    None)
                return existing
            if config is None:
                config = self._config_for(batch)
            investigation = self._investigations.get(
                batch.investigation_id or "")
            samples = self._build_samples([record], config, batch,
                                          investigation,
                                          batch.investigation_id)
            sample = samples[0]
            if plan_id is not None:
                sample.plan_id = plan_id
            sample.state = "claimed"
            self._claim_in_batch(batch, [sample])
            if investigation is not None:
                self._rebuild(investigation)
            return sample

    claim_sample = claim_representative

    # ---------- 窗口重算 / 来源更正 ----------

    def recompute(self, investigation_id: str | None = None,
                  rule_id: str | None = None,
                  batch_id: str | None = None) -> DedupedSampleBatch | None:
        """刷新调查并重算：按实际原行重建窗口、重新核销命中/忽略数。

        同一批、同一去重依据重算任意多次结果一致；新批次只取代未确认批次，
        已确认批次快照保持不变。
        """
        with self._lock:
            investigation = self._resolve_investigation(investigation_id,
                                                        rule_id)
            if investigation is None:
                return None
            return self._rebuild(investigation, batch_id=batch_id)

    # 语义别名：刷新调查同样能重算。
    refresh_investigation = recompute
    recompute_investigation = recompute

    def correct_source(self, investigation_id: str, record_id: str,
                       event_time: datetime | None = None,
                       valid: bool | None = None,
                       corrected_event_time: datetime | None = None,
                       batch_id: str | None = None,
                       fork: bool = True) -> DedupedSampleBatch | None:
        """确认来源更正：撤回/修正某条原行，并重算。

        - 未给新时间（或 ``valid=False``）：撤回该原行。
        - 给了 ``event_time``/``corrected_event_time``：按更正后的时间重算。
        撤回原代表时保留该窗口区间，从区间内仍合法的原行补出代表；被撤回行
        不再参与采样。``fork=True``（默认）派生新调查，旧调查保留旧证据。
        """
        with self._lock:
            source = self._investigations.get(investigation_id)
            if source is None:
                return None
            if corrected_event_time is not None:
                event_time = corrected_event_time

            if fork:
                investigation = self._fork_investigation(source)
            else:
                investigation = source

            self._apply_correction(investigation, record_id, event_time,
                                   valid)
            return self._rebuild(investigation, batch_id=batch_id)

    apply_correction = correct_source
    revoke_record = correct_source
    retract_record = correct_source

    def correct_source_in_place(self, investigation_id: str, record_id: str,
                                event_time: datetime | None = None,
                                valid: bool | None = None,
                                corrected_event_time: datetime | None = None,
                                batch_id: str | None = None
                                ) -> DedupedSampleBatch | None:
        """就地更正当前调查（不派生新调查）。"""
        return self.correct_source(
            investigation_id, record_id, event_time=event_time, valid=valid,
            corrected_event_time=corrected_event_time, batch_id=batch_id,
            fork=False)

    # ---------- 批次交付 / 消费确认 ----------

    def deliver_batch(self, batch_id: str) -> DedupedSampleBatch | None:
        """把批次待交付代表交给采样侧（消费确认由 acknowledge 单独落下）。"""
        with self._lock:
            batch = self._batches.get(batch_id)
            if batch is None:
                return None
            if batch.acknowledged:
                return batch
            pending = [
                rid for rid in (batch.deliverable_ids + batch.claimed_ids)
                if rid not in batch.delivered_ids
            ]
            if not pending:
                # 恢复场景：代表早已交出，只是确认没落下——保持原样。
                return batch
            batch.delivered_ids = list(dict.fromkeys(
                batch.delivered_ids + pending))
            batch.deliverable = [r for r in batch.deliverable
                                 if r.record_id not in pending]
            batch.delivered_at = datetime.now()
            if batch.state != "confirmed":
                batch.state = ("partially_delivered"
                               if batch.deliverable else "delivered")
            investigation = self._investigations.get(
                batch.investigation_id or "")
            if investigation is not None:
                investigation.delivered_ids.update(pending)
                for sample in self._samples.values():
                    if (sample.batch_id == batch_id
                            and sample.record_id in pending
                            and sample.state != "confirmed"):
                        sample.state = "delivered"
            return batch

    mark_delivered = deliver_batch
    handoff_batch = deliver_batch

    def acknowledge_batch(self, batch_id: str,
                          plan_id: str | None = None
                          ) -> DedupedSampleBatch | None:
        """落下去重端的消费确认，核销已交代表（幂等，只生效一次）。"""
        with self._lock:
            batch = self._batches.get(batch_id)
            if batch is None:
                return None
            if batch.acknowledged:
                return batch
            delivered = list(batch.delivered_ids)
            if not delivered:
                # 消费确认先于/独立于交付落下时，只核销已领代表
                # （待交付代表尚未交出，不能凭空记成已交）。
                delivered = list(batch.claimed_ids)
            batch.delivered_ids = list(dict.fromkeys(
                batch.delivered_ids + delivered))
            batch.settled_ids = list(dict.fromkeys(
                batch.settled_ids + delivered))
            batch.deliverable = [r for r in batch.deliverable
                                 if r.record_id not in delivered]
            batch.acknowledged = True
            batch.acknowledged_at = datetime.now()
            if not batch.delivered_at:
                batch.delivered_at = batch.acknowledged_at
            investigation = self._investigations.get(
                batch.investigation_id or "")
            if investigation is not None:
                investigation.delivered_ids.update(delivered)
                investigation.settled_ids.update(delivered)
                if batch.batch_id not in investigation.confirmed_batch_ids:
                    investigation.confirmed_batch_ids.append(batch.batch_id)
            for sample in self._samples.values():
                if (sample.batch_id == batch_id
                        and sample.record_id in delivered):
                    sample.state = "confirmed"
                    sample.confirmed_at = batch.acknowledged_at
            if batch.state != "confirmed":
                batch.state = "confirmed" if not batch.deliverable else (
                    "partially_delivered")
            return batch

    acknowledge = acknowledge_batch
    settle_batch = acknowledge_batch

    def confirm_batch(self, batch_id: str,
                      plan_id: str | None = None) -> DedupedSampleBatch | None:
        """确认采样批次——并发/重复提交只能确认一次。"""
        with self._lock:
            batch = self._batches.get(batch_id)
            if batch is None:
                return None
            if batch.confirm_count > 0:
                # 重复（含并发）确认：一套去重依据只核销一次。
                return batch
            if batch.state == "confirmed" and batch.acknowledged:
                batch.confirm_count = 1
                return batch
            batch = self.acknowledge_batch(batch_id, plan_id=plan_id)
            if batch is None:
                return None
            batch.confirm_count = 1
            batch.confirmed_at = batch.acknowledged_at or datetime.now()
            batch.state = "confirmed"
            return batch

    confirm = confirm_batch

    # ---------- 查询 ----------

    def get_batch(self, batch_id: str) -> DedupedSampleBatch | None:
        return self._batches.get(batch_id)

    get_dedup_batch = get_batch

    def latest_batch(self, investigation_id: str | None = None,
                     rule_id: str | None = None
                     ) -> DedupedSampleBatch | None:
        with self._lock:
            investigation = self._resolve_investigation(investigation_id,
                                                        rule_id)
            return self._latest_batch(investigation) if investigation else None

    def list_batches(self, investigation_id: str | None = None,
                     rule_id: str | None = None
                     ) -> list[DedupedSampleBatch]:
        with self._lock:
            batches = list(self._batches.values())
        if investigation_id:
            batches = [b for b in batches
                       if b.investigation_id == investigation_id]
        if rule_id:
            batches = [b for b in batches if b.rule_id == rule_id]
        return sorted(batches, key=lambda b: (b.investigation_id or "",
                                             b.version))

    def get_sample(self, sample_id: str) -> Sample | None:
        return self._samples.get(sample_id)

    def list_samples(self, investigation_id: str | None = None,
                     batch_id: str | None = None) -> list[Sample]:
        samples = list(self._samples.values())
        if investigation_id:
            samples = [s for s in samples
                       if s.investigation_id == investigation_id]
        if batch_id:
            samples = [s for s in samples if s.batch_id == batch_id]
        return sorted(samples, key=lambda s: s.sample_id)

    def get_investigation(self, investigation_id: str) -> Investigation | None:
        return self._investigations.get(investigation_id)

    def get_windows(self, investigation_id: str | None = None,
                    rule_id: str | None = None) -> list[DedupWindow]:
        with self._lock:
            investigation = self._resolve_investigation(
                investigation_id, rule_id)
            return list(investigation.windows) if investigation else []

    def pending_records(self, batch_id: str) -> list[EventRecord]:
        """批次中仍待采样/待交付的真实代表。"""
        batch = self._batches.get(batch_id)
        if batch is None:
            return []
        invalid = set(batch.invalid_record_ids)
        done = set(batch.claimed_ids) | set(batch.delivered_ids) | set(
            batch.settled_ids)
        return [r for r in batch.deliverable
                if r.record_id not in invalid and r.record_id not in done]

    def create_investigation(self, records: list[EventRecord],
                             dedup_rule: DedupFilter,
                             config: SampleConfig | None = None,
                             investigation_id: str | None = None
                             ) -> Investigation:
        """开启独立调查：保存自己的原始行快照，便于新旧调查分别复算。"""
        with self._lock:
            investigation = self._ensure_investigation(
                dedup_rule, investigation_id, force_new=True)
            if config is not None:
                investigation.config = config
            investigation.add_records(records)
            self._rebuild(investigation)
            return investigation

    open_investigation = create_investigation

    def get_stats(self) -> dict[str, dict[str, int]]:
        """获取去重规则统计数据。"""
        stats: dict[str, dict[str, int]] = {}
        for rule in self.dedup_rules:
            stats[rule.rule_id] = {
                "hit_count": rule.hit_count,
                "ignore_count": rule.ignore_count,
            }
        return stats

    def reset_fingerprints(self):
        """重置去重状态（窗口周期结束或测试隔离用）。"""
        with self._lock:
            self._fingerprint_store.clear()
            self._investigations.clear()
            self._batches.clear()
            self._samples.clear()
            self._default_investigation.clear()
            self._last_investigation_id = None
            for rule in self.dedup_rules:
                rule.hit_count = 0
                rule.ignore_count = 0

    # ---------- 内部实现 ----------

    def _ensure_investigation(self, rule: DedupFilter,
                              investigation_id: str | None = None,
                              force_new: bool = False) -> Investigation:
        if investigation_id:
            existing = self._investigations.get(investigation_id)
            if existing is not None and not force_new:
                return existing
            if existing is not None:
                # 显式重开：沿用原编号但清空证据，开启新调查。
                investigation = Investigation(
                    investigation_id=investigation_id,
                    rule=rule,
                    window_minutes=rule.window_minutes,
                )
                self._investigations[investigation_id] = investigation
                self._default_investigation[rule.rule_id] = investigation_id
                self._last_investigation_id = investigation_id
                return investigation
            # 新编号的独立调查，不影响该规则已有的默认调查。
            investigation = Investigation(
                investigation_id=investigation_id,
                rule=rule,
                window_minutes=rule.window_minutes,
            )
            self._investigations[investigation_id] = investigation
            self._last_investigation_id = investigation_id
            return investigation
        investigation_id = self._default_investigation.get(rule.rule_id)
        if investigation_id and investigation_id in self._investigations:
            return self._investigations[investigation_id]
        self._investigation_seq += 1
        investigation_id = f"INVE-{rule.rule_id}-{self._investigation_seq:04d}"

        investigation = Investigation(
            investigation_id=investigation_id,
            rule=rule,
            window_minutes=rule.window_minutes,
        )
        self._investigations[investigation_id] = investigation
        self._default_investigation[rule.rule_id] = investigation_id
        self._last_investigation_id = investigation_id
        return investigation

    def _resolve_investigation(self, investigation_id: str | None,
                               rule_id: str | None) -> Investigation | None:
        if investigation_id:
            return self._investigations.get(investigation_id)
        if rule_id:
            key = self._default_investigation.get(rule_id)
            if key:
                return self._investigations.get(key)
            return next((inv for inv in self._investigations.values()
                         if inv.rule_id == rule_id), None)
        if self._last_investigation_id:
            return self._investigations.get(self._last_investigation_id)
        if len(self._investigations) == 1:
            return next(iter(self._investigations.values()))
        return None

    def _latest_batch(self, investigation: Investigation
                      ) -> DedupedSampleBatch | None:
        if not investigation.batch_ids:
            return None
        return self._batches.get(investigation.batch_ids[-1])

    def _pinned_ids(self, investigation: Investigation) -> set[str]:
        """已领取/交付/确认的代表：代表实际确认版本，迟到结果不能重开。"""
        pinned: set[str] = set(investigation.claimed_ids)
        pinned.update(investigation.delivered_ids)
        pinned.update(investigation.settled_ids)
        for batch in self._batches.values():
            if batch.investigation_id != investigation.investigation_id:
                continue
            pinned.update(batch.claimed_ids)
            pinned.update(batch.delivered_ids)
            pinned.update(batch.settled_ids)
        for sample in self._samples.values():
            if sample.investigation_id == investigation.investigation_id:
                if sample.state in ("claimed", "delivered", "confirmed"):
                    pinned.add(sample.record_id)
        pinned -= set(investigation.invalid_ids)
        return pinned

    def _rebuild(self, investigation: Investigation,
                 batch_id: str | None = None) -> DedupedSampleBatch:
        rule = investigation.rule
        window_delta = timedelta(minutes=investigation.window_minutes)
        legal = sorted(investigation.legal_records(),
                       key=lambda r: (r.event_time, r.record_id))
        legal_ids = {record.record_id for record in legal}
        pinned = self._pinned_ids(investigation)
        conflicts: list[dict[str, object]] = []
        windows: list[DedupWindow] = []

        def _prior_interval(record: EventRecord
                            ) -> tuple[datetime, datetime] | None:
            for old in investigation.windows:
                if old.representative_id == record.record_id:
                    return old.start_time, old.end_time
                if record.record_id in old.member_ids:
                    return old.start_time, old.end_time
            return None

        # Phase 1 —— 来源更正留下的区间：代表被撤回时保留原区间，
        # 从区间内仍合法的原行补出代表（不能删除整组，也不能把区间重开）。
        anchored: list[DedupWindow] = []
        for old in investigation.windows:
            if not old.preserve_interval:
                continue
            members = self._window_members(old, legal_ids)
            if not members:
                continue
            representative = min(
                members, key=lambda r: (r.event_time, r.record_id))
            old_rep_id = old.representative_id
            window = DedupWindow(
                fingerprint=old.fingerprint,
                rule_id=old.rule_id,
                window_minutes=old.window_minutes,
                start_time=old.start_time,
                end_time=old.end_time,
                representative=representative,
                members=list(members),
                preserve_interval=True,
                replaced_representative_ids=list(
                    old.replaced_representative_ids),
            )
            if old_rep_id and old_rep_id != representative.record_id:
                window.replaced_representative_ids = list(dict.fromkeys(
                    window.replaced_representative_ids + [old_rep_id]))
            anchored.append(window)

        # Phase 2 —— 已被领取/交付/确认的代表：按“实际确认版本”钉住区间，
        # 迟到的更早原行只能开启自己的待处理区间，不能把它们重开再交一遍。
        anchored_reps = {w.representative_id for w in anchored}
        for record in legal:
            if record.record_id not in pinned:
                continue
            if record.record_id in anchored_reps:
                continue
            interval = _prior_interval(record)
            start, end = (interval if interval is not None else (
                record.event_time, record.event_time + window_delta))
            window = DedupWindow(
                fingerprint=rule.fingerprint(record),
                rule_id=rule.rule_id,
                window_minutes=investigation.window_minutes,
                start_time=start,
                end_time=end,
                representative=record,
                members=[record],
            )
            anchored.append(window)
            anchored_reps.add(record.record_id)
        anchored_reps = {w.representative_id for w in anchored}
        windows.extend(anchored)

        def _containing(fingerprint: str, at: datetime) -> list[DedupWindow]:
            return [w for w in windows
                    if w.fingerprint == fingerprint
                    and w.start_time <= at < w.end_time]

        def _target(candidates: list[DedupWindow]) -> DedupWindow:
            # 窗口冲突时按实际确认版本处理：优先已确认/已领代表所在窗口。
            for window in candidates:
                if window.representative_id in pinned:
                    return window
            return min(candidates, key=lambda w: (w.start_time, w.end_time))

        # Phase 3 —— 其余原行按发生时间统一重排后归入区间；没人包含时才以
        # 自身时间为锚点开启新区间。该过程与输入顺序无关（正序/反序一致）。
        for record in legal:
            if record.record_id in anchored_reps:
                continue
            if any(record.record_id in w.member_ids for w in windows):
                continue
            fingerprint = rule.fingerprint(record)
            candidates = _containing(fingerprint, record.event_time)
            if candidates:
                target = _target(candidates)
                if record.record_id not in target.member_ids:
                    target.members.append(record)
                    target.members.sort(
                        key=lambda r: (r.event_time, r.record_id))
                if len(candidates) > 1:
                    self._record_conflict(
                        conflicts, record, candidates, target, pinned)
                continue
            window = DedupWindow(
                fingerprint=fingerprint,
                rule_id=rule.rule_id,
                window_minutes=investigation.window_minutes,
                start_time=record.event_time,
                end_time=record.event_time + window_delta,
                representative=record,
                members=[record],
            )
            overlapping = [
                other for other in windows
                if other.fingerprint == fingerprint
                and other.start_time < window.end_time
                and window.start_time < other.end_time
            ]
            if overlapping:
                self._record_conflict(conflicts, record, overlapping,
                                      window, pinned)
            windows.append(window)

        windows.sort(key=lambda w: (w.start_time, w.end_time, w.fingerprint))

        # 重新核销：命中/忽略按实际原行重算后覆盖，不做旧值累加。
        retained = sorted(
            [w.representative for w in windows if w.representative],
            key=lambda r: (r.event_time, r.record_id))
        retained_ids = {record.record_id for record in retained}
        for window in windows:
            window.duplicate_count = len([
                member for member in window.members
                if member.record_id != window.representative_id
                and member.record_id not in retained_ids
            ])
        duplicates = max(0, len(legal) - len(retained))

        investigation.hit_count = duplicates
        investigation.ignore_count = duplicates
        # 规则级统计跟随该规则的默认（最新）调查，避免复算旧调查时
        # 把当前调查的核销值覆盖回旧值；CONSTANT 预置规则也同步，便于读取。
        if self._default_investigation.get(rule.rule_id) in (
                None, investigation.investigation_id):
            rule.hit_count = duplicates
            rule.ignore_count = duplicates
            self._sync_rule_counts(rule, duplicates)
            self._default_investigation.setdefault(
                rule.rule_id, investigation.investigation_id)
        investigation.windows = windows

        settled = set(investigation.settled_ids)
        delivered_or_claimed = (set(investigation.delivered_ids)
                                | set(investigation.claimed_ids)
                                | settled)
        deliverable = [record for record in retained
                       if record.record_id not in delivered_or_claimed]
        for window in windows:
            if window.representative_id in settled:
                window.state = "confirmed"
            elif window.representative_id in investigation.delivered_ids:
                window.state = "delivered"
            elif window.representative_id in investigation.claimed_ids:
                window.state = "claimed"

        candidate = DedupedSampleBatch(
            batch_id="",
            investigation_id=investigation.investigation_id,
            rule_id=rule.rule_id,
            event_type_id=rule.event_type_id,
            window_minutes=investigation.window_minutes,
            version=investigation.version,
            created_at=datetime.now(),
            retained=list(retained),
            deliverable=deliverable,
            windows=[window.snapshot() for window in windows],
            hit_count=duplicates,
            ignore_count=duplicates,
            state=("pending" if deliverable else
                   ("delivered" if retained else "confirmed")),
            raw_record_ids=list(investigation.raw_records.keys()),
            invalid_record_ids=sorted(investigation.invalid_ids),
            legal_record_ids=[record.record_id for record in legal],
            conflicts=conflicts,
        )
        candidate.basis_signature = self._basis_signature(candidate)

        previous = self._latest_batch(investigation)
        if (previous is not None and batch_id is None
                and previous.basis_signature == candidate.basis_signature):
            # 同一依据重算：不新增批次版本，计数与已确认样本保持不变。
            return previous

        investigation.version += 1
        candidate.version = investigation.version
        candidate.batch_id = batch_id or (
            f"DBAT-{investigation.investigation_id}-"
            f"{investigation.version:04d}")
        if previous is not None and previous.batch_id != candidate.batch_id:
            if previous.state != "confirmed":
                previous.state = "superseded"
                previous.superseded_by = candidate.batch_id
        self._batches[candidate.batch_id] = candidate
        investigation.batch_ids.append(candidate.batch_id)
        investigation.last_batch_id = candidate.batch_id
        self._annotate_records(candidate, windows)
        self._fingerprint_store[rule.rule_id] = {
            window.fingerprint for window in windows}
        return candidate

    @staticmethod
    def _window_members(old: DedupWindow,
                        legal_ids: set[str]) -> list[EventRecord]:
        members: list[EventRecord] = []
        seen: set[str] = set()
        for member in old.members:
            if member.record_id in legal_ids and member.record_id not in seen:
                members.append(member)
                seen.add(member.record_id)
        return members

    @staticmethod
    def _record_conflict(conflicts: list[dict[str, object]],
                         record: EventRecord,
                         others: list[DedupWindow],
                         target: DedupWindow,
                         pinned: set[str]) -> None:
        for other in others:
            if other is target:
                continue
            other_rep = other.representative_id
            if not other_rep:
                continue
            if other_rep in pinned:
                confirmed_rep, pending_rep = other_rep, target.representative_id
                resolved_by = "confirmed_version"
            elif target.representative_id in pinned:
                confirmed_rep, pending_rep = target.representative_id, other_rep
                resolved_by = "confirmed_version"
            else:
                confirmed_rep, pending_rep = "", target.representative_id
                resolved_by = "overlap_pending"
            key = {
                "fingerprint": target.fingerprint,
                "confirmed_representative_id": confirmed_rep,
                "pending_representative_id": pending_rep,
                "record_id": record.record_id,
                "window_start": target.start_time.isoformat(),
                "window_end": target.end_time.isoformat(),
                "resolved_by": resolved_by,
            }
            if key not in conflicts:
                conflicts.append(key)

    @staticmethod
    def _annotate_records(batch: DedupedSampleBatch,
                          windows: list[DedupWindow]) -> None:
        """给事件挂上所属区间/批次依据，让原始发生时间与区间可回溯查询。"""
        for window in windows:
            for member in window.members:
                member.window_start = window.start_time
                member.window_end = window.end_time
                member.window_basis = window.basis()
                member.batch_id = batch.batch_id
        for record in batch.retained:
            record.batch_id = batch.batch_id

    def _build_samples(self, sampled: list[EventRecord],
                       config: SampleConfig,
                       batch: DedupedSampleBatch | None,
                       investigation: Investigation | None,
                       investigation_id: str | None) -> list[Sample]:
        samples: list[Sample] = []
        for record in sampled:
            window = batch.window_for(record.record_id) if batch else None
            if window is not None:
                window_start = window.start_time
                window_end = window.end_time
                fingerprint = window.fingerprint
                window_basis = window.basis()
            else:
                window_start = getattr(record, "window_start",
                                       record.event_time)
                window_end = getattr(
                    record, "window_end",
                    record.event_time + timedelta(
                        minutes=max(config.merge_window_minutes, 0)))
                fingerprint = (
                    investigation.rule.fingerprint(record)
                    if investigation is not None else "")
                window_basis = getattr(record, "window_basis", {})
            self._sample_seq += 1
            sample = Sample(
                sample_id=f"SMPL-{self._sample_seq:06d}",
                batch_id=batch.batch_id if batch else "",
                investigation_id=(batch.investigation_id if batch
                                  else investigation_id),
                plan_id=config.plan_id,
                record_id=record.record_id,
                event_time=record.event_time,
                window_start=window_start,
                window_end=window_end,
                fingerprint=fingerprint,
                merge_key=(record.parsed_fields.get(config.merge_key, "")
                           if config.merge_key else ""),
                window_basis=window_basis,
            )
            self._samples[sample.sample_id] = sample
            samples.append(sample)
            # 样本元数据挂到真实事件上：原始发生时间与所属区间直接可查。
            record.sample_id = sample.sample_id
            record.sample = sample
            record.batch_id = sample.batch_id
            record.window_start = window_start
            record.window_end = window_end
            record.window_basis = window_basis
        return samples

    def _claim_in_batch(self, batch: DedupedSampleBatch,
                        samples: list[Sample]) -> None:
        ids = [sample.record_id for sample in samples]
        batch.claimed_ids = list(dict.fromkeys(batch.claimed_ids + ids))
        batch.deliverable = [r for r in batch.deliverable
                             if r.record_id not in set(ids)]
        batch.sample_ids = list(dict.fromkeys(
            batch.sample_ids + [sample.sample_id for sample in samples]))
        if batch.state != "confirmed":
            batch.state = ("partially_delivered" if batch.delivered_ids
                           else ("claimed" if batch.deliverable
                                 else "delivered"))
        investigation = self._investigations.get(batch.investigation_id or "")
        if investigation is not None:
            investigation.claimed_ids.update(ids)
            investigation.sample_ids = list(dict.fromkeys(
                investigation.sample_ids
                + [sample.sample_id for sample in samples]))

    def _fork_investigation(self, source: Investigation) -> Investigation:
        """派生更正后的新调查：复制原行与窗口区间，旧调查保持旧证据。

        原行做浅拷贝（字段字典单独复制），这样更正事件时间不会污染旧调查。
        新调查成为该规则的默认去重调查，旧调查仍可按原编号取出旧代表。
        """
        self._investigation_seq += 1
        new_id = f"{source.investigation_id}-C{self._investigation_seq:02d}"
        while new_id in self._investigations:
            self._investigation_seq += 1
            new_id = f"{source.investigation_id}-C{self._investigation_seq:02d}"
        raw_records = {
            record_id: self._clone_record(record)
            for record_id, record in source.raw_records.items()
        }
        investigation = Investigation(
            investigation_id=new_id,
            rule=source.rule,
            window_minutes=source.window_minutes,
            config=source.config,
            raw_records=raw_records,
            invalid_ids=set(source.invalid_ids),
            origin_investigation_id=source.investigation_id,
            claimed_ids=set(source.claimed_ids),
            delivered_ids=set(source.delivered_ids),
            settled_ids=set(source.settled_ids),
        )
        investigation.windows = [window.snapshot()
                                 for window in source.windows]
        self._investigations[new_id] = investigation
        self._default_investigation[source.rule.rule_id] = new_id
        self._last_investigation_id = new_id
        return investigation

    @staticmethod
    def _clone_record(record: EventRecord) -> EventRecord:
        clone = copy.copy(record)
        clone.parsed_fields = dict(record.parsed_fields)
        clone.masked_fields = dict(record.masked_fields)
        clone.enriched_fields = dict(record.enriched_fields)
        clone.window_basis = dict(record.window_basis)
        return clone

    def _apply_correction(self, investigation: Investigation,
                          record_id: str,
                          event_time: datetime | None,
                          valid: bool | None) -> None:
        record = investigation.raw_records.get(record_id)
        revoking = valid is False or (valid is None and event_time is None)
        # 撤回原行时保留它所在窗口的区间（补位而不是重开/删除整组）；
        # 只是更正发生时间则按新时间重新锚定，不保留旧区间。
        if revoking:
            for window in investigation.windows:
                if (window.representative_id == record_id
                        or record_id in window.member_ids):
                    window.preserve_interval = True
            investigation.invalid_ids.add(record_id)
            # 被撤回行上的未确认样本不能再被交付/采样。
            for sample in self._samples.values():
                if (sample.investigation_id == investigation.investigation_id
                        and sample.record_id == record_id
                        and sample.state != "confirmed"):
                    sample.state = "revoked"
            # 撤回已确认代表时不再钉住旧代表，允许从同区间合法原行补位。
            investigation.claimed_ids.discard(record_id)
            investigation.delivered_ids.discard(record_id)
            investigation.settled_ids.discard(record_id)
            for batch in self._batches.values():
                if batch.investigation_id != investigation.investigation_id:
                    continue
                if batch.state == "confirmed":
                    continue
                batch.claimed_ids = [rid for rid in batch.claimed_ids
                                     if rid != record_id]
                batch.delivered_ids = [rid for rid in batch.delivered_ids
                                       if rid != record_id]
                batch.invalid_record_ids = list(dict.fromkeys(
                    batch.invalid_record_ids + [record_id]))
        elif event_time is not None and record is not None:
            record.event_time = event_time
            investigation.invalid_ids.discard(record_id)
        investigation.state = "已更正"

    def _sync_rule_counts(self, rule: DedupFilter, hits: int) -> None:
        """把核销结果同步到同编号的规则对象，保持 get_stats 可读且不串规则。"""
        for candidate in self.dedup_rules:
            if candidate is rule or candidate.rule_id == rule.rule_id:
                candidate.hit_count = hits
                candidate.ignore_count = hits
        for candidate in PRESET_DEDUP_RULES:
            if candidate.rule_id == rule.rule_id:
                candidate.hit_count = hits
                candidate.ignore_count = hits

    @staticmethod
    def _basis_signature(batch: DedupedSampleBatch) -> str:
        raw = "|".join([
            batch.rule_id,
            str(batch.window_minutes),
            ",".join(sorted(batch.legal_record_ids)),
            ",".join(sorted(f"{w.fingerprint}@{w.start_time.isoformat()}"
                            for w in batch.windows)),
        ])
        return hashlib.sha256(raw.encode()).hexdigest()

    def _config_for(self, batch: DedupedSampleBatch) -> SampleConfig:
        return next(
            (c for c in self.sample_configs
             if c.event_type_id == batch.event_type_id),
            SampleConfig(plan_id=batch.rule_id,
                         event_type_id=batch.event_type_id,
                         sample_ratio=1.0),
        )


def make_dedup_sample_pipeline() -> DedupSamplePipeline:
    """工厂函数：创建预配置的去重采样管道实例。"""
    return DedupSamplePipeline()
