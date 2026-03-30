from __future__ import annotations

from datetime import datetime, timezone

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from app.constants import ROLES
from app.extensions import db, login_manager


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class TimestampMixin:
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = db.Column(
        db.DateTime(timezone=True),
        default=utcnow,
        onupdate=utcnow,
        nullable=False,
    )


class User(UserMixin, TimestampMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255), unique=True, nullable=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default=ROLES["OPERATOR"], nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    scan_jobs = db.relationship("ScanBatchJob", back_populates="created_by_user")
    audit_logs = db.relationship("AuditLog", back_populates="user")

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self) -> bool:
        return self.role == ROLES["ADMIN"]


@login_manager.user_loader
def load_user(user_id: str) -> User | None:
    return db.session.get(User, int(user_id))


class AppSetting(TimestampMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(120), unique=True, nullable=False)
    value = db.Column(db.Text, nullable=False)
    description = db.Column(db.String(255), nullable=True)

    @staticmethod
    def get_value(key: str, default: str | None = None) -> str | None:
        record = AppSetting.query.filter_by(key=key).first()
        return record.value if record else default

    @staticmethod
    def set_value(key: str, value: str, description: str | None = None) -> "AppSetting":
        record = AppSetting.query.filter_by(key=key).first()
        if record is None:
            record = AppSetting(key=key, value=value, description=description)
            db.session.add(record)
        else:
            record.value = value
            if description:
                record.description = description
        return record


class ScanBatchJob(TimestampMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    profile_key = db.Column(db.String(50), nullable=False, index=True)
    profile_label = db.Column(db.String(120), nullable=False)
    status = db.Column(db.String(20), default="QUEUED", nullable=False, index=True)
    target_input = db.Column(db.Text, nullable=False)
    total_targets = db.Column(db.Integer, default=0, nullable=False)
    completed_targets = db.Column(db.Integer, default=0, nullable=False)
    failed_targets = db.Column(db.Integer, default=0, nullable=False)
    running_targets = db.Column(db.Integer, default=0, nullable=False)
    batch_size = db.Column(db.Integer, nullable=False)
    host_timeout = db.Column(db.Integer, nullable=False)
    retry_failed = db.Column(db.Integer, default=0, nullable=False)
    custom_options = db.Column(db.JSON, nullable=True)
    started_at = db.Column(db.DateTime(timezone=True), nullable=True)
    finished_at = db.Column(db.DateTime(timezone=True), nullable=True)
    created_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    created_by_user = db.relationship("User", back_populates="scan_jobs")
    targets = db.relationship(
        "ScanTargetResult",
        back_populates="batch_job",
        cascade="all, delete-orphan",
        lazy="dynamic",
    )

    @property
    def progress_percent(self) -> int:
        if self.total_targets == 0:
            return 0
        return int((self.completed_targets + self.failed_targets) / self.total_targets * 100)


class ScanTargetResult(TimestampMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    batch_job_id = db.Column(db.Integer, db.ForeignKey("scan_batch_job.id"), nullable=False)
    target = db.Column(db.String(120), nullable=False, index=True)
    status = db.Column(db.String(20), default="QUEUED", nullable=False, index=True)
    attempt_count = db.Column(db.Integer, default=0, nullable=False)
    started_at = db.Column(db.DateTime(timezone=True), nullable=True)
    finished_at = db.Column(db.DateTime(timezone=True), nullable=True)
    duration_seconds = db.Column(db.Float, nullable=True)
    host_state = db.Column(db.String(32), nullable=True, index=True)
    open_ports_count = db.Column(db.Integer, default=0, nullable=False)
    open_ports_summary = db.Column(db.Text, nullable=True)
    services_summary = db.Column(db.Text, nullable=True)
    os_guess = db.Column(db.String(255), nullable=True)
    raw_output = db.Column(db.Text, nullable=True)
    xml_output = db.Column(db.Text, nullable=True)
    parsed_payload = db.Column(db.JSON, nullable=True)
    error_message = db.Column(db.Text, nullable=True)
    last_worker_job_id = db.Column(db.String(64), nullable=True)

    batch_job = db.relationship("ScanBatchJob", back_populates="targets")
    ports = db.relationship(
        "ScanPortResult",
        back_populates="target_result",
        cascade="all, delete-orphan",
    )


class ScanPortResult(TimestampMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target_result_id = db.Column(db.Integer, db.ForeignKey("scan_target_result.id"), nullable=False)
    protocol = db.Column(db.String(16), nullable=False, index=True)
    port = db.Column(db.Integer, nullable=False, index=True)
    state = db.Column(db.String(32), nullable=False, index=True)
    service = db.Column(db.String(120), nullable=True, index=True)
    product = db.Column(db.String(255), nullable=True)
    version = db.Column(db.String(255), nullable=True)
    extra_info = db.Column(db.String(255), nullable=True)

    target_result = db.relationship("ScanTargetResult", back_populates="ports")


class AuditLog(TimestampMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    action = db.Column(db.String(120), nullable=False, index=True)
    object_type = db.Column(db.String(120), nullable=True)
    object_id = db.Column(db.String(120), nullable=True)
    ip_address = db.Column(db.String(64), nullable=True)
    details = db.Column(db.JSON, nullable=True)

    user = db.relationship("User", back_populates="audit_logs")
