from __future__ import annotations

from flask import has_request_context, request
from flask_login import current_user

from app.extensions import db
from app.models import AuditLog


def audit(
    action: str,
    object_type: str | None = None,
    object_id: str | None = None,
    details: dict | None = None,
    commit: bool = False,
) -> AuditLog:
    user_id = None
    ip_address = None
    if has_request_context():
        ip_address = request.headers.get("X-Forwarded-For", request.remote_addr)
        if getattr(current_user, "is_authenticated", False):
            user_id = current_user.id

    entry = AuditLog(
        user_id=user_id,
        action=action,
        object_type=object_type,
        object_id=object_id,
        ip_address=ip_address,
        details=details or {},
    )
    db.session.add(entry)
    if commit:
        db.session.commit()
    return entry
