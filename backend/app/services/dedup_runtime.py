"""去重采样运行时：为接口层提供可复查批次、样本与调查的只读视图。

真实项目里这些状态会落在数据库；当前沿用内存仓库风格，用单例管道
承载一次进程内的去重/采样证据链，保证样本的原始发生时间和所属区间
可以通过接口查到。
"""
from __future__ import annotations

from typing import Any

from app.core.dedup_sample import DedupSamplePipeline
from app.core.models import DedupedSampleBatch, Sample


def serialize_batch(batch: DedupedSampleBatch,
                    include_windows: bool = True) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "batch_id": batch.batch_id,
        "investigation_id": batch.investigation_id,
        "rule_id": batch.rule_id,
        "event_type_id": batch.event_type_id,
        "window_minutes": batch.window_minutes,
        "version": batch.version,
        "state": batch.state,
        "retained_ids": batch.retained_ids,
        "deliverable_ids": batch.deliverable_ids,
        "claimed_ids": list(batch.claimed_ids),
        "delivered_ids": list(batch.delivered_ids),
        "settled_ids": list(batch.settled_ids),
        "invalid_record_ids": list(batch.invalid_record_ids),
        "hit_count": batch.hit_count,
        "ignore_count": batch.ignore_count,
        "confirm_count": batch.confirm_count,
        "created_at": batch.created_at.isoformat(),
        "basis_signature": batch.basis_signature,
        "conflicts": list(batch.conflicts),
    }
    if include_windows:
        payload["windows"] = [
            {
                **window.basis(),
                "member_ids": window.member_ids,
                "duplicate_count": window.duplicate_count,
                "replaced_representative_ids":
                    list(window.replaced_representative_ids),
            }
            for window in batch.windows
        ]
        payload["retained"] = [
            {
                "record_id": record.record_id,
                "event_time": record.event_time.isoformat(),
                "window_start": record.window_start.isoformat()
                if record.window_start else None,
                "window_end": record.window_end.isoformat()
                if record.window_end else None,
            }
            for record in batch.retained
        ]
    return payload


def serialize_sample(sample: Sample) -> dict[str, Any]:
    return sample.to_dict()


# 进程内单例：接口层与领域逻辑共用同一套去重依据。
pipeline = DedupSamplePipeline()
