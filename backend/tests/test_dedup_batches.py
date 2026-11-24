"""测试：去重窗口重算、来源更正与去重后采样批次的完整证据链。

覆盖数据流 event_type → dedup_filter → sample_job 的关键回归场景：

- 有效重复区间：09:00 / 09:59 / 10:01 在 60 分钟规则下只保留 09:00 与 10:01
- 正序 / 反序 / 迟到补采得到一致的保留事件与命中数
- 同一依据重算多遍：09:59 的重复只计一次，未受影响的窗口计数不变
- deduplicate 的窗口依据持久保存，样本可查到原始发生时间与所属区间
- 确认来源更正撤回原代表：保留窗口区间并从合法原行补出代表，旧调查仍可复算
- 交付后消费确认中断、恢复收到更早原行：不重复交付已交代表，不丢新范围
- 并发确认同一采样批次只生效一次，已确认批次不被迟到结果覆盖
"""
from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.core.dedup_sample import (
    DedupSamplePipeline, PRESET_DEDUP_RULES,
)
from app.core.models import (
    DedupFilter, EventRecord, EventTypeDef, SampleConfig,
)


ACCESS_EVENT = EventTypeDef(
    type_id="EVEN-0001", type_name="访问事件",
    category_tag="access", severity="INFO",
)


def t(hour: int, minute: int, day: int = 15) -> datetime:
    return datetime(2026, 11, day, hour, minute, 0)


def make_event(record_id: str, event_time: datetime, *,
               url: str = "/api/users", ip: str = "192.168.1.10",
               event_type: EventTypeDef | None = None) -> EventRecord:
    return EventRecord(
        record_id=record_id,
        event_type=event_type or ACCESS_EVENT,
        original_content=f"raw line for {record_id}",
        parsed_fields={"client_ip": ip, "url": url},
        masked_fields={},
        enriched_fields={},
        event_time=event_time,
        source_host=ip,
    )


def make_rule(window_minutes: int = 60) -> DedupFilter:
    return DedupFilter(
        rule_id="DEDU-REG-0001",
        event_type_id="EVEN-0001",
        dedup_fields=["client_ip", "url"],
        window_minutes=window_minutes,
    )


def make_config(ratio: float = 1.0, merge_key: str = "") -> SampleConfig:
    return SampleConfig(
        plan_id="SAMP-REG-0001",
        event_type_id="EVEN-0001",
        sample_ratio=ratio,
        merge_key=merge_key,
        merge_window_minutes=60,
    )


class TestEffectiveDuplicateInterval:
    """有效重复区间必须按代表时间计算，不能把旧指纹永久当成已见。"""

    def test_window_keeps_first_and_first_outside(self):
        """09:00 / 09:59 / 10:01 在 60 分钟窗口下保留 09:00 与 10:01。"""
        pipeline = DedupSamplePipeline()
        rule = make_rule()
        records = [
            make_event("e-0900", t(9, 0)),
            make_event("e-0959", t(9, 59)),
            make_event("e-1001", t(10, 1)),
        ]

        retained, hit, ignore = pipeline.deduplicate(records, rule)

        assert [r.record_id for r in retained] == ["e-0900", "e-1001"]
        assert hit == 1
        assert ignore == 1

    def test_sample_sees_surviving_representatives(self):
        """采样应看到窗口外的 10:01，而不是被 60 分钟前的旧指纹吞掉。"""
        pipeline = DedupSamplePipeline()
        rule = make_rule()
        records = [
            make_event("e-0900", t(9, 0)),
            make_event("e-0959", t(9, 59)),
            make_event("e-1001", t(10, 1)),
        ]
        retained, _, _ = pipeline.deduplicate(records, rule)

        sampled = pipeline.sample(retained.batch, make_config())

        assert [r.record_id for r in sampled] == ["e-0900", "e-1001"]

    def test_order_independent_ingest(self):
        """正序、反序、迟到补采必须得到一致的保留事件与命中数。"""
        rule = make_rule()
        orders = {
            "forward": ["e-0900", "e-0959", "e-1001"],
            "reversed": ["e-1001", "e-0959", "e-0900"],
            "late": ["e-0900", "e-1001", "e-0959"],
        }
        events = {
            "e-0900": make_event("e-0900", t(9, 0)),
            "e-0959": make_event("e-0959", t(9, 59)),
            "e-1001": make_event("e-1001", t(10, 1)),
        }
        results = {}
        for name, order in orders.items():
            pipeline = DedupSamplePipeline()
            batch = None
            for rid in order:
                retained, hit, _ = pipeline.deduplicate([events[rid]], rule)
                batch = retained.batch
            results[name] = (batch.retained_ids, batch.hit_count)

        assert results["forward"] == results["reversed"] == results["late"]
        assert results["forward"] == (["e-0900", "e-1001"], 1)

    def test_no_fingerprint_residue_across_calls(self):
        """上一次计算留下的指纹不能阻断下一次窗口外的同指纹事件。"""
        pipeline = DedupSamplePipeline()
        rule = make_rule()
        pipeline.deduplicate([make_event("e-0900", t(9, 0))], rule)
        retained, hit, _ = pipeline.deduplicate(
            [make_event("e-1001", t(10, 1))], rule)

        assert [r.record_id for r in retained] == ["e-0900", "e-1001"]
        assert hit == 0


class TestRecomputeSettlement:
    """重算必须按实际原行重新核销，不做旧累计值再加一次。"""

    def test_recompute_twice_counts_once(self):
        """同一批按同一依据重算两遍，09:59 的重复只计一次。"""
        pipeline = DedupSamplePipeline()
        rule = make_rule()
        retained, _, _ = pipeline.deduplicate([
            make_event("e-0900", t(9, 0)),
            make_event("e-0959", t(9, 59)),
            make_event("e-1001", t(10, 1)),
        ], rule)
        investigation_id = retained.batch.investigation_id

        first = pipeline.recompute(investigation_id)
        second = pipeline.recompute(investigation_id)

        assert first.hit_count == second.hit_count == 1
        assert first.ignore_count == second.ignore_count == 1
        assert first.retained_ids == second.retained_ids == ["e-0900", "e-1001"]

    def test_unaffected_window_counts_stay(self):
        """迟到原行只影响自己的窗口，未受影响的窗口计数不变。"""
        pipeline = DedupSamplePipeline()
        rule = make_rule()
        other = make_event("e-other-1", t(9, 30), url="/api/health")
        other_dup = make_event("e-other-2", t(9, 31), url="/api/health")
        retained, _, _ = pipeline.deduplicate([
            make_event("e-0900", t(9, 0)),
            make_event("e-0959", t(9, 59)),
            other,
            other_dup,
        ], rule)
        investigation_id = retained.batch.investigation_id
        before = {w.representative_id: w.duplicate_count
                  for w in pipeline.recompute(investigation_id).windows}

        pipeline.deduplicate([make_event("e-late", t(12, 30))], rule,
                             investigation_id=investigation_id)
        after = {w.representative_id: w.duplicate_count
                 for w in pipeline.recompute(investigation_id).windows}

        assert before["e-0900"] == after["e-0900"] == 1
        assert before["e-other-1"] == after["e-other-1"] == 1
        assert pipeline.latest_batch(investigation_id).hit_count == 2


class TestSampleTraceability:
    """样本必须能查到原始发生时间、所属区间和批次依据。"""

    def test_sample_carries_event_time_and_window(self):
        pipeline = DedupSamplePipeline()
        rule = make_rule()
        retained, _, _ = pipeline.deduplicate([
            make_event("e-0900", t(9, 0)),
            make_event("e-0959", t(9, 59)),
            make_event("e-1001", t(10, 1)),
        ], rule)
        batch = retained.batch

        sampled = pipeline.sample(batch, make_config())

        assert len(sampled.samples) == 2
        by_record = {s.record_id: s for s in sampled.samples}
        by_event = {r.record_id: r for r in sampled}
        assert by_record["e-0900"].event_time == t(9, 0)
        assert by_record["e-0900"].window_start == t(9, 0)
        assert by_record["e-0900"].window_end == t(10, 0)
        assert by_record["e-1001"].window_start == t(10, 1)
        assert by_record["e-1001"].window_end == t(11, 1)
        # 事件对象本身也带上区间与样本编号，便于直接读取。
        assert by_event["e-1001"].sample_id == by_record["e-1001"].sample_id
        assert by_event["e-1001"].window_start == t(10, 1)
        assert pipeline.get_sample(by_record["e-1001"].sample_id) is not None

    def test_batch_is_reviewable_snapshot(self):
        """批次保存窗口依据与实际保留事件，可供复查。"""
        pipeline = DedupSamplePipeline()
        rule = make_rule()
        retained, _, _ = pipeline.deduplicate([
            make_event("e-0900", t(9, 0)),
            make_event("e-0959", t(9, 59)),
            make_event("e-1001", t(10, 1)),
        ], rule)
        batch = pipeline.get_batch(retained.batch.batch_id)

        assert batch is not None
        assert batch.retained_ids == ["e-0900", "e-1001"]
        assert batch.raw_record_ids == ["e-0900", "e-0959", "e-1001"]
        basis = batch.retained_window_basis()
        assert len(basis) == 2
        assert basis[0]["window_minutes"] == 60
        assert basis[0]["representative_id"] == "e-0900"
        assert pytest_datetime(basis[0]["window_end"]) == t(10, 0)


def pytest_datetime(value: object) -> datetime:
    return datetime.fromisoformat(str(value))


class TestConfirmedCorrection:
    """一次已确认来源更正撤回代表后，必须补出替补并保留旧调查。"""

    def test_withdraw_representative_backfills_from_window(self):
        pipeline = DedupSamplePipeline()
        rule = make_rule()
        retained, _, _ = pipeline.deduplicate([
            make_event("e-0900", t(9, 0)),
            make_event("e-0959", t(9, 59)),
            make_event("e-1001", t(10, 1)),
        ], rule)
        investigation_id = retained.batch.investigation_id
        old_batch = retained.batch

        corrected = pipeline.correct_source(
            investigation_id, "e-0900", valid=False)

        # 原代表被撤回，窗口区间保留，从区间内仍合法原行补出代表。
        assert corrected.retained_ids == ["e-0959", "e-1001"]
        window = corrected.window_for("e-0959")
        assert window is not None
        assert window.start_time == t(9, 0)
        assert window.end_time == t(10, 0)
        assert "e-0900" in window.replaced_representative_ids

    def test_withdrawn_row_is_not_sampled(self):
        pipeline = DedupSamplePipeline()
        rule = make_rule()
        retained, _, _ = pipeline.deduplicate([
            make_event("e-0900", t(9, 0)),
            make_event("e-0959", t(9, 59)),
        ], rule)
        investigation_id = retained.batch.investigation_id
        pipeline.sample(retained.batch, make_config())

        corrected = pipeline.correct_source(
            investigation_id, "e-0900", valid=False)
        sampled = pipeline.sample(corrected, make_config())

        assert [r.record_id for r in sampled] == ["e-0959"]

    def test_old_investigation_recomputes_with_old_evidence(self):
        pipeline = DedupSamplePipeline()
        rule = make_rule()
        retained, _, _ = pipeline.deduplicate([
            make_event("e-0900", t(9, 0)),
            make_event("e-0959", t(9, 59)),
            make_event("e-1001", t(10, 1)),
        ], rule)
        investigation_id = retained.batch.investigation_id
        old_sample = pipeline.sample(retained.batch, make_config())
        old_sample_ids = [s.sample_id for s in old_sample.samples]

        pipeline.correct_source(investigation_id, "e-0900", valid=False)

        old_batch = pipeline.get_batch(retained.batch.batch_id)
        assert old_batch.retained_ids == ["e-0900", "e-1001"]
        assert pipeline.get_sample(old_sample_ids[0]).record_id == "e-0900"
        recomputed = pipeline.recompute(investigation_id)
        assert recomputed.retained_ids == ["e-0900", "e-1001"]

    def test_substitute_available_for_same_code_group(self):
        """同码原行组中代表被判错时，新批次确有替补。"""
        pipeline = DedupSamplePipeline()
        rule = make_rule()
        retained, _, _ = pipeline.deduplicate([
            make_event("e-0900", t(9, 0)),
            make_event("e-0910", t(9, 10)),
            make_event("e-0920", t(9, 20)),
        ], rule)
        investigation_id = retained.batch.investigation_id
        pipeline.sample(retained.batch, make_config())

        corrected = pipeline.correct_source(
            investigation_id, "e-0900", valid=False)

        assert corrected.retained_ids == ["e-0910"]
        assert corrected.deliverable_ids == ["e-0910"]
        next_samples = pipeline.sample(corrected, make_config())
        assert [r.record_id for r in next_samples] == ["e-0910"]


class TestDeliveryAndConfirmation:
    """交付/确认中断恢复与并发确认的幂等性。"""

    def _prepare(self):
        pipeline = DedupSamplePipeline()
        rule = make_rule()
        retained, _, _ = pipeline.deduplicate([
            make_event("e-0900", t(9, 0)),
            make_event("e-0959", t(9, 59)),
            make_event("e-1001", t(10, 1)),
        ], rule)
        return pipeline, rule, retained.batch

    def test_recovery_does_not_redeliver_handed_representative(self):
        pipeline, rule, batch = self._prepare()
        pipeline.sample(batch, make_config())
        pipeline.deliver_batch(batch.batch_id)

        # 消费确认未落下就中断，恢复又收到更早的原行。
        recovered_retained, _, _ = pipeline.deduplicate(
            [make_event("e-0850", t(8, 50))], rule)
        recovered = recovered_retained.batch

        assert "e-0900" in recovered.retained_ids  # 已交代表仍被核销保留
        assert "e-0850" in recovered.retained_ids  # 新范围不丢
        assert recovered.deliverable_ids == ["e-0850"]
        next_samples = pipeline.sample(recovered, make_config())
        assert [r.record_id for r in next_samples] == ["e-0850"]

    def test_ack_settles_already_delivered_once(self):
        pipeline, _, batch = self._prepare()
        pipeline.sample(batch, make_config())
        pipeline.deliver_batch(batch.batch_id)

        acked = pipeline.acknowledge_batch(batch.batch_id)
        assert set(acked.settled_ids) == {"e-0900", "e-1001"}
        # 再次确认不重复核销。
        again = pipeline.confirm_batch(batch.batch_id)
        assert again.confirm_count == 1

    def test_concurrent_confirm_only_once(self):
        pipeline, _, batch = self._prepare()
        pipeline.sample(batch, make_config())

        first = pipeline.confirm_batch(batch.batch_id)
        second = pipeline.confirm_batch(batch.batch_id)

        assert first is second
        assert first.confirm_count == 1
        assert first.state == "confirmed"

    def test_threaded_confirm_only_once(self):
        """多线程并发提交同一批次：只确认一次、只核销一套依据。"""
        import threading

        pipeline, _, batch = self._prepare()
        pipeline.sample(batch, make_config())
        results: list[object] = []
        barrier = threading.Barrier(8)

        def worker():
            barrier.wait()
            results.append(pipeline.confirm_batch(batch.batch_id))

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        batch = pipeline.get_batch(batch.batch_id)
        assert batch.confirm_count == 1
        assert batch.state == "confirmed"
        assert set(batch.settled_ids) == {"e-0900", "e-1001"}
        assert len(batch.settled_ids) == len(set(batch.settled_ids))
        assert all(result is batch for result in results)

    def test_concurrent_sample_only_one_list(self):
        """并发取样同一批次：代表只会被交出一次。"""
        import threading

        pipeline, _, batch = self._prepare()
        barrier = threading.Barrier(6)
        handed: list[str] = []

        def worker():
            barrier.wait()
            sampled = pipeline.sample(batch, make_config())
            for record in sampled:
                handed.append(record.record_id)

        threads = [threading.Thread(target=worker) for _ in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert sorted(handed) == ["e-0900", "e-1001"]
        assert len(handed) == len(set(handed))

    def test_confirmed_batch_not_overwritten_by_late_result(self):
        pipeline, rule, batch = self._prepare()
        pipeline.sample(batch, make_config())
        pipeline.confirm_batch(batch.batch_id)

        late_retained, _, _ = pipeline.deduplicate(
            [make_event("e-0850", t(8, 50))], rule)

        confirmed = pipeline.get_batch(batch.batch_id)
        assert confirmed.state == "confirmed"
        assert confirmed.retained_ids == ["e-0900", "e-1001"]
        assert late_retained.batch.retained_ids == ["e-0850", "e-0900", "e-1001"]
        assert late_retained.batch.deliverable_ids == ["e-0850"]
        # 迟到的更早窗口按实际确认版本处理，冲突被记录。
        assert late_retained.batch.conflicts
        assert any(c["resolved_by"] == "confirmed_version"
                   for c in late_retained.batch.conflicts)

    def test_claim_then_late_record_keeps_pending_range(self):
        """计划已领取 10:01 代表、统计未写入时，迟到 08:50 重开更早范围。"""
        pipeline = DedupSamplePipeline()
        rule = make_rule()
        retained, _, _ = pipeline.deduplicate([
            make_event("e-0900", t(9, 0)),
            make_event("e-1001", t(10, 1)),
        ], rule)
        batch = retained.batch
        claimed = pipeline.claim_samples(batch.batch_id, plan_id="SAMP-X",
                                         count=1)
        assert [s.record_id for s in claimed.samples] == ["e-0900"]

        late_retained, _, _ = pipeline.deduplicate(
            [make_event("e-0850", t(8, 50))], rule)
        late = late_retained.batch

        assert late.deliverable_ids == ["e-0850", "e-1001"]
        # 已领取的 e-0900 不会被重开窗口再交一次。
        assert "e-0900" not in late.deliverable_ids
        next_samples = pipeline.sample(late, make_config())
        assert [r.record_id for r in next_samples] == ["e-0850", "e-1001"]

    def test_claim_1001_then_late_0850(self):
        """已领取 10:01 代表后迟到的 08:50 重开更早范围，不重交 10:01。"""
        pipeline = DedupSamplePipeline()
        rule = make_rule()
        retained, _, _ = pipeline.deduplicate([
            make_event("e-0900", t(9, 0)),
            make_event("e-0959", t(9, 59)),
            make_event("e-1001", t(10, 1)),
        ], rule)
        batch = retained.batch
        claimed = pipeline.claim_representative(
            batch.batch_id, "e-1001", plan_id="SAMP-X")
        assert claimed is not None
        assert claimed.window_start == t(10, 1)
        assert claimed.window_end == t(11, 1)

        late_retained, _, _ = pipeline.deduplicate(
            [make_event("e-0850", t(8, 50))], rule)
        late = late_retained.batch

        assert late.retained_ids == ["e-0850", "e-0959", "e-1001"]
        assert late.deliverable_ids == ["e-0850", "e-0959"]
        next_samples = pipeline.sample(late, make_config())
        assert [r.record_id for r in next_samples] == ["e-0850", "e-0959"]

    def test_ack_after_recovery_settles_without_redelivery(self):
        """交付后确认中断、恢复收到更早原行；补确认时只核销已交代表。"""
        pipeline, rule, batch = self._prepare()
        pipeline.sample(batch, make_config())
        pipeline.deliver_batch(batch.batch_id)

        late_retained, _, _ = pipeline.deduplicate(
            [make_event("e-0850", t(8, 50))], rule)
        late = late_retained.batch
        acked_old = pipeline.acknowledge_batch(batch.batch_id)

        assert set(acked_old.settled_ids) == {"e-0900", "e-1001"}
        assert late.deliverable_ids == ["e-0850"]
        next_samples = pipeline.sample(late, make_config())
        assert [r.record_id for r in next_samples] == ["e-0850"]
        # 重算新批次不能把已核销代表重新变成待交付。
        assert pipeline.recompute(late.investigation_id).deliverable_ids == []


class TestBatchSnapshotIsolation:
    """采样从批次快照读取，并发/迟到结果不能改写已取样的版本。"""

    def test_sample_reads_from_batch_not_live_windows(self):
        pipeline = DedupSamplePipeline()
        rule = make_rule()
        retained, _, _ = pipeline.deduplicate([
            make_event("e-0900", t(9, 0)),
            make_event("e-0959", t(9, 59)),
        ], rule)
        batch = retained.batch

        # 迟到原行触发重算，新批次的窗口与旧批次不同。
        pipeline.deduplicate([make_event("e-0850", t(8, 50))], rule,
                             investigation_id=batch.investigation_id)

        sampled_old = pipeline.sample(batch, make_config())
        assert [r.record_id for r in sampled_old] == ["e-0900"]

    def test_late_duplicate_does_not_change_retained(self):
        pipeline = DedupSamplePipeline()
        rule = make_rule()
        retained, _, _ = pipeline.deduplicate([
            make_event("e-0900", t(9, 0)),
            make_event("e-1001", t(10, 1)),
        ], rule)
        investigation_id = retained.batch.investigation_id

        pipeline.deduplicate([make_event("e-0930", t(9, 30))], rule,
                             investigation_id=investigation_id)

        latest = pipeline.latest_batch(investigation_id)
        assert latest.retained_ids == ["e-0900", "e-1001"]
        assert latest.hit_count == 1


# ---------- 运行入口 ----------

if __name__ == "__main__":
    import traceback

    tests = {
        "window_first_and_outside":
            TestEffectiveDuplicateInterval().test_window_keeps_first_and_first_outside,
        "window_sample_sees":
            TestEffectiveDuplicateInterval().test_sample_sees_surviving_representatives,
        "window_order_independent":
            TestEffectiveDuplicateInterval().test_order_independent_ingest,
        "window_no_residue":
            TestEffectiveDuplicateInterval().test_no_fingerprint_residue_across_calls,
        "recompute_twice":
            TestRecomputeSettlement().test_recompute_twice_counts_once,
        "recompute_unaffected":
            TestRecomputeSettlement().test_unaffected_window_counts_stay,
        "sample_traceable":
            TestSampleTraceability().test_sample_carries_event_time_and_window,
        "batch_reviewable":
            TestSampleTraceability().test_batch_is_reviewable_snapshot,
        "correction_backfill":
            TestConfirmedCorrection().test_withdraw_representative_backfills_from_window,
        "correction_not_sampled":
            TestConfirmedCorrection().test_withdrawn_row_is_not_sampled,
        "correction_old_evidence":
            TestConfirmedCorrection().test_old_investigation_recomputes_with_old_evidence,
        "correction_substitute":
            TestConfirmedCorrection().test_substitute_available_for_same_code_group,
        "delivery_no_redeliver":
            TestDeliveryAndConfirmation().test_recovery_does_not_redeliver_handed_representative,
        "delivery_ack_once":
            TestDeliveryAndConfirmation().test_ack_settles_already_delivered_once,
        "delivery_confirm_once":
            TestDeliveryAndConfirmation().test_concurrent_confirm_only_once,
        "delivery_confirm_threaded":
            TestDeliveryAndConfirmation().test_threaded_confirm_only_once,
        "delivery_sample_threaded":
            TestDeliveryAndConfirmation().test_concurrent_sample_only_one_list,
        "delivery_confirmed_not_overwritten":
            TestDeliveryAndConfirmation().test_confirmed_batch_not_overwritten_by_late_result,
        "delivery_pending_range":
            TestDeliveryAndConfirmation().test_claim_then_late_record_keeps_pending_range,
        "delivery_claim_1001_late_0850":
            TestDeliveryAndConfirmation().test_claim_1001_then_late_0850,
        "delivery_ack_after_recovery":
            TestDeliveryAndConfirmation().test_ack_after_recovery_settles_without_redelivery,
        "snapshot_isolation":
            TestBatchSnapshotIsolation().test_sample_reads_from_batch_not_live_windows,
        "snapshot_late_duplicate":
            TestBatchSnapshotIsolation().test_late_duplicate_does_not_change_retained,
    }

    passed = 0
    failed = 0
    for name, test_func in tests.items():
        try:
            test_func()
            passed += 1
            print(f"  PASS  test_dedup_batches: {name}")
        except Exception:
            failed += 1
            print(f"  FAIL  test_dedup_batches: {name}")
            traceback.print_exc()

    print(f"\ntest_dedup_batches: {passed} passed, {failed} failed, {len(tests)} total")
    sys.exit(1 if failed else 0)
