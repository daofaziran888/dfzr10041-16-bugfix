"""去重采样证据接口：按批次/调查/样本编号复查去重后采样批次。"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query

from app.services.dedup_runtime import pipeline, serialize_batch, serialize_sample

router = APIRouter(prefix="/api/dedup", tags=["去重采样"])


@router.get("/batches")
def list_batches(investigation_id: str | None = Query(default=None),
                 rule_id: str | None = Query(default=None)) -> dict[str, Any]:
    """列出可复查的去重后采样批次。"""
    batches = pipeline.list_batches(investigation_id=investigation_id,
                                    rule_id=rule_id)
    return {"items": [serialize_batch(b) for b in batches],
            "total": len(batches)}


@router.get("/batches/{batch_id}")
def get_batch(batch_id: str) -> dict[str, Any]:
    """按批次编号复查窗口依据、实际保留事件与已领/已交代表。"""
    batch = pipeline.get_batch(batch_id)
    if batch is None:
        raise HTTPException(status_code=404,
                            detail=f"去重后采样批次 {batch_id} 不存在")
    return serialize_batch(batch)


@router.get("/batches/{batch_id}/samples")
def list_batch_samples(batch_id: str) -> dict[str, Any]:
    """批次下所有样本（原始发生时间、所属区间可查）。"""
    if pipeline.get_batch(batch_id) is None:
        raise HTTPException(status_code=404,
                            detail=f"去重后采样批次 {batch_id} 不存在")
    samples = pipeline.list_samples(batch_id=batch_id)
    return {"items": [serialize_sample(s) for s in samples],
            "total": len(samples)}


@router.get("/samples/{sample_id}")
def get_sample(sample_id: str) -> dict[str, Any]:
    """按样本编号查回原始发生时间与所属区间。"""
    sample = pipeline.get_sample(sample_id)
    if sample is None:
        raise HTTPException(status_code=404,
                            detail=f"采样样本 {sample_id} 不存在")
    return serialize_sample(sample)


@router.get("/investigations/{investigation_id}")
def get_investigation(investigation_id: str) -> dict[str, Any]:
    """按调查编号查回去重依据、批次和样本。"""
    investigation = pipeline.get_investigation(investigation_id)
    if investigation is None:
        raise HTTPException(status_code=404,
                            detail=f"调查 {investigation_id} 不存在")
    samples = pipeline.list_samples(investigation_id=investigation_id)
    return {
        "investigation_id": investigation.investigation_id,
        "rule_id": investigation.rule_id,
        "event_type_id": investigation.event_type_id,
        "window_minutes": investigation.window_minutes,
        "state": investigation.state,
        "version": investigation.version,
        "hit_count": investigation.hit_count,
        "ignore_count": investigation.ignore_count,
        "origin_investigation_id": investigation.origin_investigation_id,
        "batch_ids": list(investigation.batch_ids),
        "windows": [
            {
                **window.basis(),
                "member_ids": window.member_ids,
                "duplicate_count": window.duplicate_count,
                "replaced_representative_ids":
                    list(window.replaced_representative_ids),
            }
            for window in investigation.windows
        ],
        "samples": [serialize_sample(s) for s in samples],
    }


@router.get("/samples")
def list_samples(investigation_id: str | None = Query(default=None),
                 batch_id: str | None = Query(default=None)
                 ) -> dict[str, Any]:
    samples = pipeline.list_samples(investigation_id=investigation_id,
                                    batch_id=batch_id)
    return {"items": [serialize_sample(s) for s in samples],
            "total": len(samples)}
