from flask_wtf import FlaskForm
from wtforms import (
    BooleanField,
    IntegerField,
    PasswordField,
    SelectField,
    StringField,
    SubmitField,
    TextAreaField,
)
from wtforms.validators import DataRequired, Length, NumberRange, Optional

from app.constants import SCAN_PROFILES


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(max=80)])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Sign In")


class ScanRequestForm(FlaskForm):
    name = StringField("Job Name", validators=[DataRequired(), Length(max=120)])
    targets = TextAreaField(
        "Targets",
        validators=[DataRequired()],
        description="One IP, range, or CIDR per line.",
    )
    profile_key = SelectField(
        "Scan Profile",
        choices=[(key, value["label"]) for key, value in SCAN_PROFILES.items()],
        validators=[DataRequired()],
    )
    batch_size = IntegerField(
        "Concurrent Targets",
        validators=[DataRequired(), NumberRange(min=1, max=500)],
    )
    host_timeout = IntegerField(
        "Timeout Per Host (seconds)",
        validators=[DataRequired(), NumberRange(min=30, max=3600)],
    )
    retry_failed = IntegerField(
        "Retries For Failed Hosts",
        validators=[DataRequired(), NumberRange(min=0, max=5)],
    )
    custom_top_ports = IntegerField(
        "Custom Builder: Top Ports",
        validators=[Optional(), NumberRange(min=1, max=1000)],
    )
    custom_timing = SelectField(
        "Custom Builder: Timing",
        choices=[("", "Default"), ("T3", "Normal (T3)"), ("T4", "Fast (T4)")],
        validators=[Optional()],
    )
    custom_service_detection = BooleanField("Enable service detection (-sV)")
    custom_os_detection = BooleanField("Enable OS detection (-O)")
    custom_tcp_connect = BooleanField("Enable TCP connect scan (-sT)")
    custom_udp_top20 = BooleanField("Add UDP top 20 ports (-sU --top-ports 20)")
    submit = SubmitField("Launch Scan")


class SettingsForm(FlaskForm):
    allowed_ranges = TextAreaField("Allowed Internal Ranges", validators=[DataRequired()])
    default_batch_size = IntegerField(
        "Default Batch Size",
        validators=[DataRequired(), NumberRange(min=1, max=500)],
    )
    max_concurrency = IntegerField(
        "Max Concurrency",
        validators=[DataRequired(), NumberRange(min=1, max=500)],
    )
    default_host_timeout = IntegerField(
        "Default Host Timeout",
        validators=[DataRequired(), NumberRange(min=30, max=3600)],
    )
    default_retry_count = IntegerField(
        "Default Retry Count",
        validators=[DataRequired(), NumberRange(min=0, max=5)],
    )
    submit = SubmitField("Save Settings")
