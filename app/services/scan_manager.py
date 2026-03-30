from __future__ import annotations

from datetime import datetime, timezone

from flask import current_app

from app.extensions import db, socketio
from app.models import ScanBatchJob, ScanPortResult, ScanTargetResult
from app.utils.audit import audit


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def dispatch_scan_batch(batch_job_id: int) -> None:
    # Keep the worker queue filled up to the configured per-batch concurrency.
    batch = db.session.get(ScanBatchJob, batch_job_id)
    if batch is None or batch.status in {"PAUSED", "STOPPED", "COMPLETED", "FAILED"}:
        return

    if batch.started_at is None:
        batch.started_at = utcnow()
    batch.status = "RUNNING"

    running_count = batch.targets.filter(ScanTargetResult.status == "RUNNING").count()
    available_slots = max(batch.batch_size - running_count, 0)
    if available_slots == 0:
        db.session.commit()
        return

    pending_targets = (
        batch.targets.filter(ScanTargetResult.status.in_(["QUEUED", "RETRYING"]))
        .order_by(ScanTargetResult.id.asc())
        .limit(available_slots)
        .all()
    )
    if not pending_targets and running_count == 0:
        finalize_batch_status(batch)
        db.session.commit()
        emit_batch_event(batch, event="batch_finished")
        return

    queue = current_app.extensions["scan_queue"]
    for target in pending_targets:
        target.status = "RUNNING"
        target.started_at = target.started_at or utcnow()
        target.attempt_count += 1
        job = queue.enqueue("app.tasks.scans.run_target_scan", batch.id, target.id)
        target.last_worker_job_id = job.id

    refresh_batch_counters(batch)
    db.session.commit()
    emit_batch_event(batch)


def refresh_batch_counters(batch: ScanBatchJob) -> None:
    batch.completed_targets = batch.targets.filter(ScanTargetResult.status == "COMPLETED").count()
    batch.failed_targets = batch.targets.filter(ScanTargetResult.status.in_(["FAILED", "STOPPED"])).count()
    batch.running_targets = batch.targets.filter(ScanTargetResult.status == "RUNNING").count()


def finalize_batch_status(batch: ScanBatchJob) -> None:
    refresh_batch_counters(batch)
    batch.finished_at = utcnow()

    stopped = batch.targets.filter(ScanTargetResult.status == "STOPPED").count()
    failed = batch.targets.filter(ScanTargetResult.status == "FAILED").count()
    completed = batch.targets.filter(ScanTargetResult.status == "COMPLETED").count()
    total = batch.total_targets

    if stopped and completed + failed + stopped == total:
        batch.status = "STOPPED"
    elif failed and completed + failed == total:
        batch.status = "FAILED"
    else:
        batch.status = "COMPLETED"


def persist_scan_result(target_row: ScanTargetResult, result: dict, error_message: str | None = None) -> None:
    # Flatten parsed Nmap output into summary columns for the live table and history filters.
    parsed_host = next(iter(result.get("parsed", {}).get("hosts", [])), None)
    target_row.finished_at = utcnow()
    target_row.duration_seconds = (
        (target_row.finished_at - target_row.started_at).total_seconds()
        if target_row.started_at
        else None
    )
    target_row.raw_output = result.get("raw_output")
    target_row.xml_output = result.get("xml_output")
    target_row.parsed_payload = result.get("parsed")
    target_row.error_message = error_message

    target_row.ports.clear()
    if parsed_host:
        open_ports = [port for port in parsed_host["ports"] if port["state"] == "open"]
        target_row.host_state = parsed_host["state"]
        target_row.open_ports_count = len(open_ports)
        target_row.open_ports_summary = ", ".join(
            f'{port["port"]}/{port["protocol"]}' for port in open_ports[:20]
        )
        target_row.services_summary = ", ".join(
            f'{port["service"] or "unknown"} ({port["port"]})' for port in open_ports[:20]
        )
        target_row.os_guess = parsed_host.get("os_guess")

        for port in parsed_host["ports"]:
            target_row.ports.append(
                ScanPortResult(
                    protocol=port["protocol"],
                    port=port["port"],
                    state=port["state"],
                    service=port["service"],
                    product=port["product"],
                    version=port["version"],
                    extra_info=port["extra_info"],
                )
            )
    else:
        target_row.host_state = "unknown"
        target_row.open_ports_count = 0
        target_row.open_ports_summary = ""
        target_row.services_summary = ""
        target_row.os_guess = ""


def emit_target_event(target_row: ScanTargetResult) -> None:
    socketio.emit(
        "scan_update",
        {
            "batch_id": target_row.batch_job_id,
            "target_id": target_row.id,
            "status": target_row.status,
            "target": target_row.target,
            "started_at": target_row.started_at.isoformat() if target_row.started_at else None,
            "finished_at": target_row.finished_at.isoformat() if target_row.finished_at else None,
            "host_state": target_row.host_state,
            "open_ports_count": target_row.open_ports_count,
            "open_ports_summary": target_row.open_ports_summary,
            "services_summary": target_row.services_summary,
            "os_guess": target_row.os_guess,
            "duration_seconds": target_row.duration_seconds,
            "updated_at": target_row.updated_at.isoformat(),
        },
        room=f"batch-{target_row.batch_job_id}",
    )
    socketio.emit("dashboard_refresh", {"batch_id": target_row.batch_job_id})


def emit_batch_event(batch: ScanBatchJob, event: str = "batch_progress") -> None:
    socketio.emit(
        event,
        {
            "batch_id": batch.id,
            "status": batch.status,
            "completed_targets": batch.completed_targets,
            "failed_targets": batch.failed_targets,
            "running_targets": batch.running_targets,
            "total_targets": batch.total_targets,
            "progress_percent": batch.progress_percent,
        },
        room=f"batch-{batch.id}",
    )
    socketio.emit("dashboard_refresh", {"batch_id": batch.id})


def record_batch_action(action: str, batch: ScanBatchJob, extra: dict | None = None, commit: bool = False) -> None:
    details = {"batch_status": batch.status, **(extra or {})}
    audit(action, object_type="scan_batch_job", object_id=str(batch.id), details=details, commit=commit)
