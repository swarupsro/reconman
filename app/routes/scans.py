from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timedelta, timezone

from flask import (
    Blueprint,
    Response,
    abort,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user, login_required
from flask_socketio import join_room

from app.extensions import db, limiter, socketio
from app.forms import ScanRequestForm
from app.models import AppSetting, ScanBatchJob, ScanPortResult, ScanTargetResult
from app.services.nmap_profiles import ProfileValidationError, build_profile_args, get_available_profiles
from app.services.scan_manager import dispatch_scan_batch, record_batch_action
from app.services.targeting import TargetValidationError, parse_targets, validate_targets_within_scope
from app.utils.audit import audit


scans_bp = Blueprint("scans", __name__, url_prefix="/scans")


@scans_bp.route("/new", methods=["GET", "POST"])
@login_required
@limiter.limit(lambda: current_app_rate_limit())
def new_scan():
    form = ScanRequestForm()
    max_concurrency = int(AppSetting.get_value("max_concurrency", "50"))
    if not form.is_submitted():
        form.batch_size.data = int(AppSetting.get_value("default_batch_size", "25"))
        form.host_timeout.data = int(AppSetting.get_value("default_host_timeout", "300"))
        form.retry_failed.data = int(AppSetting.get_value("default_retry_count", "1"))

    profile_choices = [(key, value["label"]) for key, value in get_available_profiles().items()]
    form.profile_key.choices = profile_choices

    if form.validate_on_submit():
        try:
            if form.batch_size.data > max_concurrency:
                raise TargetValidationError(f"Batch size exceeds the configured maximum of {max_concurrency}.")

            targets = parse_targets(form.targets.data)
            validate_targets_within_scope(targets)
            profile_label, _ = build_profile_args(form.profile_key.data, build_custom_options(form))
        except (TargetValidationError, ProfileValidationError) as exc:
            flash(str(exc), "danger")
        else:
            batch = ScanBatchJob(
                name=form.name.data.strip(),
                profile_key=form.profile_key.data,
                profile_label=profile_label,
                target_input=form.targets.data.strip(),
                total_targets=len(targets),
                batch_size=form.batch_size.data,
                host_timeout=form.host_timeout.data,
                retry_failed=form.retry_failed.data,
                custom_options=build_custom_options(form),
                created_by_id=current_user.id,
            )
            db.session.add(batch)
            db.session.flush()

            for target in targets:
                db.session.add(ScanTargetResult(batch_job_id=batch.id, target=target))

            audit(
                "scan_batch_created",
                object_type="scan_batch_job",
                object_id=str(batch.id),
                details={"target_count": len(targets), "profile": batch.profile_key},
            )
            db.session.commit()
            dispatch_scan_batch(batch.id)
            flash("Scan batch created and queued.", "success")
            return redirect(url_for("scans.job_details", batch_job_id=batch.id))

    return render_template(
        "scans/new_scan.html",
        form=form,
        profiles=get_available_profiles(),
        max_concurrency=max_concurrency,
    )


@scans_bp.route("/queue")
@login_required
def queue():
    jobs = ScanBatchJob.query.order_by(ScanBatchJob.created_at.desc()).all()
    return render_template("scans/queue.html", jobs=jobs)


@scans_bp.route("/history")
@login_required
def history():
    page = request.args.get("page", 1, type=int)
    query = ScanTargetResult.query.join(ScanBatchJob)
    join_ports = False

    if target := request.args.get("target", "").strip():
        query = query.filter(ScanTargetResult.target.ilike(f"%{target}%"))
    if host_state := request.args.get("host_state", "").strip():
        query = query.filter(ScanTargetResult.host_state == host_state)
    if profile_key := request.args.get("profile_key", "").strip():
        query = query.filter(ScanBatchJob.profile_key == profile_key)
    if service := request.args.get("service", "").strip():
        join_ports = True
    if open_port := request.args.get("open_port", type=int):
        join_ports = True
    if join_ports:
        query = query.outerjoin(ScanPortResult)
    if service:
        query = query.filter(ScanPortResult.service.ilike(f"%{service}%"))
    if open_port:
        query = query.filter(ScanPortResult.port == open_port)
    if time_range := request.args.get("time_range", "").strip():
        query = apply_time_filter(query, time_range)

    results = query.order_by(ScanTargetResult.updated_at.desc()).distinct().paginate(
        page=page,
        per_page=20,
        error_out=False,
    )
    filters = request.args.to_dict()
    filters.pop("page", None)
    return render_template(
        "scans/history.html",
        results=results,
        profiles=get_available_profiles(),
        filters=filters,
    )


@scans_bp.route("/<int:batch_job_id>")
@login_required
def job_details(batch_job_id: int):
    batch = ScanBatchJob.query.get_or_404(batch_job_id)
    page = request.args.get("page", 1, type=int)
    targets = batch.targets.order_by(ScanTargetResult.id.asc()).paginate(page=page, per_page=25, error_out=False)
    return render_template("scans/job_details.html", batch=batch, targets=targets)


@scans_bp.route("/<int:batch_job_id>/pause", methods=["POST"])
@login_required
def pause_batch(batch_job_id: int):
    batch = ScanBatchJob.query.get_or_404(batch_job_id)
    batch.status = "PAUSED"
    record_batch_action("scan_batch_paused", batch)
    db.session.commit()
    flash("Batch paused. Running hosts will finish, and new hosts will not start.", "warning")
    return redirect(url_for("scans.job_details", batch_job_id=batch.id))


@scans_bp.route("/<int:batch_job_id>/resume", methods=["POST"])
@login_required
def resume_batch(batch_job_id: int):
    batch = ScanBatchJob.query.get_or_404(batch_job_id)
    if batch.status in {"PAUSED", "FAILED", "STOPPED"}:
        batch.status = "QUEUED"
        record_batch_action("scan_batch_resumed", batch)
        db.session.commit()
        dispatch_scan_batch(batch.id)
        flash("Batch resumed.", "success")
    return redirect(url_for("scans.job_details", batch_job_id=batch.id))


@scans_bp.route("/<int:batch_job_id>/stop", methods=["POST"])
@login_required
def stop_batch(batch_job_id: int):
    batch = ScanBatchJob.query.get_or_404(batch_job_id)
    batch.status = "STOPPED"
    for target in batch.targets.filter(ScanTargetResult.status.in_(["QUEUED", "RETRYING"])).all():
        target.status = "STOPPED"
    record_batch_action("scan_batch_stopped", batch)
    db.session.commit()
    flash("Stop requested for the batch.", "danger")
    return redirect(url_for("scans.job_details", batch_job_id=batch.id))


@scans_bp.route("/<int:batch_job_id>/export.csv")
@login_required
def export_batch_csv(batch_job_id: int):
    batch = ScanBatchJob.query.get_or_404(batch_job_id)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "Job ID",
            "Target",
            "Profile",
            "Status",
            "Start Time",
            "End Time",
            "Host State",
            "Open Ports Count",
            "Open Ports",
            "Services",
            "OS Detection",
            "Duration",
            "Error",
        ]
    )
    for row in batch.targets.order_by(ScanTargetResult.id.asc()).all():
        writer.writerow(
            [
                batch.id,
                row.target,
                batch.profile_label,
                row.status,
                row.started_at.isoformat() if row.started_at else "",
                row.finished_at.isoformat() if row.finished_at else "",
                row.host_state or "",
                row.open_ports_count,
                row.open_ports_summary or "",
                row.services_summary or "",
                row.os_guess or "",
                row.duration_seconds or "",
                row.error_message or "",
            ]
        )
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=batch-{batch.id}.csv"},
    )


@scans_bp.route("/<int:batch_job_id>/export.json")
@login_required
def export_batch_json(batch_job_id: int):
    batch = ScanBatchJob.query.get_or_404(batch_job_id)
    payload = {
        "batch": {
            "id": batch.id,
            "name": batch.name,
            "profile_key": batch.profile_key,
            "profile_label": batch.profile_label,
            "status": batch.status,
            "created_at": batch.created_at.isoformat(),
            "created_by": batch.created_by_user.username,
        },
        "results": [serialize_target(row) for row in batch.targets.order_by(ScanTargetResult.id.asc()).all()],
    }
    return Response(
        json.dumps(payload, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename=batch-{batch.id}.json"},
    )


@scans_bp.route("/api/batches/<int:batch_job_id>")
@login_required
def batch_api(batch_job_id: int):
    batch = ScanBatchJob.query.get_or_404(batch_job_id)
    return jsonify(
        {
            "id": batch.id,
            "name": batch.name,
            "profile_key": batch.profile_key,
            "profile_label": batch.profile_label,
            "status": batch.status,
            "total_targets": batch.total_targets,
            "completed_targets": batch.completed_targets,
            "failed_targets": batch.failed_targets,
            "running_targets": batch.running_targets,
            "progress_percent": batch.progress_percent,
        }
    )


@scans_bp.route("/api/targets/<int:target_result_id>")
@login_required
def target_api(target_result_id: int):
    row = ScanTargetResult.query.get_or_404(target_result_id)
    return jsonify(serialize_target(row))


@scans_bp.route("/api/targets/<int:target_result_id>/output/<string:output_type>")
@login_required
def target_output(target_result_id: int, output_type: str):
    row = ScanTargetResult.query.get_or_404(target_result_id)
    if output_type == "raw":
        return jsonify({"content": row.raw_output or "", "label": "Raw Output"})
    if output_type == "xml":
        return jsonify({"content": row.xml_output or "", "label": "XML Output"})
    abort(404)


@socketio.on("subscribe_batch")
def subscribe_batch(data):
    batch_id = data.get("batch_id")
    if batch_id:
        join_room(f"batch-{batch_id}")


def serialize_target(row: ScanTargetResult) -> dict:
    return {
        "id": row.id,
        "batch_job_id": row.batch_job_id,
        "target": row.target,
        "status": row.status,
        "started_at": row.started_at.isoformat() if row.started_at else None,
        "finished_at": row.finished_at.isoformat() if row.finished_at else None,
        "duration_seconds": row.duration_seconds,
        "host_state": row.host_state,
        "open_ports_count": row.open_ports_count,
        "open_ports_summary": row.open_ports_summary,
        "services_summary": row.services_summary,
        "os_guess": row.os_guess,
        "error_message": row.error_message,
        "ports": [
            {
                "protocol": port.protocol,
                "port": port.port,
                "state": port.state,
                "service": port.service,
                "product": port.product,
                "version": port.version,
                "extra_info": port.extra_info,
            }
            for port in row.ports
        ],
    }


def build_custom_options(form: ScanRequestForm) -> dict:
    return {
        "top_ports": form.custom_top_ports.data or None,
        "timing": form.custom_timing.data or None,
        "service_detection": bool(form.custom_service_detection.data),
        "os_detection": bool(form.custom_os_detection.data),
        "tcp_connect": bool(form.custom_tcp_connect.data),
        "udp_top20": bool(form.custom_udp_top20.data),
    }


def apply_time_filter(query, time_range: str):
    now = datetime.now(timezone.utc)
    if time_range == "24h":
        return query.filter(ScanTargetResult.updated_at >= now.replace(microsecond=0) - timedelta(hours=24))
    if time_range == "7d":
        return query.filter(ScanTargetResult.updated_at >= now.replace(microsecond=0) - timedelta(days=7))
    return query


def current_app_rate_limit() -> str:
    return current_app.config["SCAN_RATE_LIMIT"]
