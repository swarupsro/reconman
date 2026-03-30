from flask import Blueprint, flash, redirect, render_template, url_for
from flask_login import login_required

from app.extensions import db
from app.forms import SettingsForm
from app.models import AppSetting
from app.utils.audit import audit
from app.utils.decorators import admin_required


settings_bp = Blueprint("settings", __name__, url_prefix="/settings")


@settings_bp.route("/", methods=["GET", "POST"])
@login_required
@admin_required
def index():
    form = SettingsForm()
    if form.validate_on_submit():
        AppSetting.set_value("allowed_ranges", normalize_ranges(form.allowed_ranges.data))
        AppSetting.set_value("default_batch_size", str(form.default_batch_size.data))
        AppSetting.set_value("max_concurrency", str(form.max_concurrency.data))
        AppSetting.set_value("default_host_timeout", str(form.default_host_timeout.data))
        AppSetting.set_value("default_retry_count", str(form.default_retry_count.data))
        audit("settings_updated", object_type="settings", object_id="global")
        db.session.commit()
        flash("Settings updated.", "success")
        return redirect(url_for("settings.index"))

    if not form.is_submitted():
        form.allowed_ranges.data = AppSetting.get_value("allowed_ranges", "")
        form.default_batch_size.data = int(AppSetting.get_value("default_batch_size", "25"))
        form.max_concurrency.data = int(AppSetting.get_value("max_concurrency", "50"))
        form.default_host_timeout.data = int(AppSetting.get_value("default_host_timeout", "300"))
        form.default_retry_count.data = int(AppSetting.get_value("default_retry_count", "1"))

    return render_template("settings/index.html", form=form)


def normalize_ranges(value: str) -> str:
    parts = [item.strip() for item in value.replace("\n", ",").split(",") if item.strip()]
    return ",".join(parts)
