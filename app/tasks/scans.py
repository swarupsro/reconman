from __future__ import annotations

from rq import get_current_job

from app import create_app
from app.extensions import db
from app.models import ScanBatchJob, ScanTargetResult
from app.services.nmap_profiles import build_profile_args
from app.services.nmap_service import ScanExecutionError, execute_nmap_scan
from app.services.scan_manager import (
    dispatch_scan_batch,
    emit_batch_event,
    emit_target_event,
    finalize_batch_status,
    persist_scan_result,
    record_batch_action,
    refresh_batch_counters,
)


app = create_app(initialize_database=False)


def run_target_scan(batch_job_id: int, target_result_id: int) -> None:
    with app.app_context():
        batch = db.session.get(ScanBatchJob, batch_job_id)
        target_row = db.session.get(ScanTargetResult, target_result_id)
        if batch is None or target_row is None:
            return

        if batch.status == "PAUSED":
            target_row.status = "QUEUED"
            refresh_batch_counters(batch)
            db.session.commit()
            emit_target_event(target_row)
            return

        if batch.status == "STOPPED":
            target_row.status = "STOPPED"
            refresh_batch_counters(batch)
            db.session.commit()
            emit_target_event(target_row)
            return

        current_job = get_current_job()
        if current_job:
            target_row.last_worker_job_id = current_job.id
            db.session.commit()

        try:
            _, profile_args = build_profile_args(batch.profile_key, batch.custom_options or {})
            result = execute_nmap_scan(
                target_row.target,
                profile_args,
                batch.host_timeout,
                stop_checker=lambda: should_stop(batch.id, target_row.id),
            )
            target_row.status = "COMPLETED"
            persist_scan_result(target_row, result)
        except ScanExecutionError as exc:
            handle_scan_error(batch, target_row, str(exc))
        except FileNotFoundError:
            handle_scan_error(batch, target_row, "Nmap binary was not found in PATH or NMAP_BINARY.")
        except Exception as exc:
            handle_scan_error(batch, target_row, f"Unhandled scan error: {exc}")

        refresh_batch_counters(batch)
        running = batch.targets.filter(ScanTargetResult.status == "RUNNING").count()
        pending = batch.targets.filter(ScanTargetResult.status.in_(["QUEUED", "RETRYING"])).count()
        if running == 0 and pending == 0:
            finalize_batch_status(batch)

        db.session.commit()
        emit_target_event(target_row)
        emit_batch_event(batch)
        dispatch_scan_batch(batch.id)


def should_stop(batch_id: int, target_result_id: int) -> bool:
    # Expire cached ORM state so the polling loop sees operator stop requests promptly.
    db.session.expire_all()
    batch = db.session.get(ScanBatchJob, batch_id)
    target_row = db.session.get(ScanTargetResult, target_result_id)
    if batch is None or target_row is None:
        return True
    return batch.status == "STOPPED" or target_row.status == "STOPPED"


def handle_scan_error(batch: ScanBatchJob, target_row: ScanTargetResult, message: str) -> None:
    retries_left = batch.retry_failed - (target_row.attempt_count - 1)
    if retries_left > 0 and batch.status not in {"STOPPED", "PAUSED"}:
        target_row.status = "RETRYING"
        target_row.error_message = message
        record_batch_action(
            "scan_target_retry",
            batch,
            extra={"target_id": target_row.id, "target": target_row.target, "reason": message},
        )
    else:
        target_row.status = "STOPPED" if "stopped by an operator" in message.lower() else "FAILED"
        target_row.error_message = message
        target_row.finished_at = target_row.finished_at or target_row.updated_at
        record_batch_action(
            "scan_target_failed",
            batch,
            extra={"target_id": target_row.id, "target": target_row.target, "reason": message},
        )
