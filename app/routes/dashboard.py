from datetime import datetime, timedelta, timezone

from flask import Blueprint, jsonify, render_template
from flask_login import login_required

from app.models import ScanBatchJob, ScanTargetResult


dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
@login_required
def index():
    stats = build_dashboard_stats()
    recent_jobs = ScanBatchJob.query.order_by(ScanBatchJob.created_at.desc()).limit(8).all()
    recent_results = ScanTargetResult.query.order_by(ScanTargetResult.updated_at.desc()).limit(12).all()
    return render_template(
        "dashboard/index.html",
        stats=stats,
        recent_jobs=recent_jobs,
        recent_results=recent_results,
    )


@dashboard_bp.route("/api/dashboard/stats")
@login_required
def dashboard_stats():
    return jsonify(build_dashboard_stats())


def build_dashboard_stats() -> dict:
    last_24h = datetime.now(timezone.utc) - timedelta(hours=24)
    return {
        "total_jobs": ScanBatchJob.query.count(),
        "running_jobs": ScanBatchJob.query.filter(ScanBatchJob.status == "RUNNING").count(),
        "completed_jobs": ScanBatchJob.query.filter(ScanBatchJob.status == "COMPLETED").count(),
        "failed_jobs": ScanBatchJob.query.filter(ScanBatchJob.status.in_(["FAILED", "STOPPED"])).count(),
        "total_hosts_scanned": ScanTargetResult.query.filter(ScanTargetResult.status == "COMPLETED").count(),
        "hosts_last_24h": ScanTargetResult.query.filter(ScanTargetResult.updated_at >= last_24h).count(),
    }
