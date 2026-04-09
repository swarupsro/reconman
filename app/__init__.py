from __future__ import annotations

from pathlib import Path

from flask import Flask
from redis import Redis
from rq import Queue

from config import config_by_name, sqlite_database_path
from app.extensions import csrf, db, limiter, login_manager, migrate, socketio
from app.models import AppSetting, User
from app.utils.audit import audit


def create_app(config_name: str | None = None, initialize_database: bool = True) -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    config_key = config_name or "default"
    app.config.from_object(config_by_name[config_key])
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)

    database_path = sqlite_database_path(app.config["SQLALCHEMY_DATABASE_URI"])
    if database_path is not None:
        database_path.parent.mkdir(parents=True, exist_ok=True)

    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    socketio.init_app(app, message_queue=app.config["SOCKETIO_MESSAGE_QUEUE"])

    redis_client = Redis.from_url(app.config["RQ_REDIS_URL"])
    app.extensions["redis_client"] = redis_client
    app.extensions["scan_queue"] = Queue(
        "scans",
        connection=redis_client,
        default_timeout=app.config["DEFAULT_HOST_TIMEOUT"] + 120,
    )

    register_blueprints(app)
    register_shell_context(app)
    register_template_helpers(app)

    if initialize_database:
        with app.app_context():
            db.create_all()
            bootstrap_defaults(app)

    return app


def register_blueprints(app: Flask) -> None:
    from app.routes.auth import auth_bp
    from app.routes.dashboard import dashboard_bp
    from app.routes.scans import scans_bp
    from app.routes.settings import settings_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(scans_bp)
    app.register_blueprint(settings_bp)


def register_shell_context(app: Flask) -> None:
    @app.shell_context_processor
    def shell_context() -> dict[str, object]:
        return {"db": db, "User": User, "AppSetting": AppSetting}


def register_template_helpers(app: Flask) -> None:
    @app.context_processor
    def inject_globals() -> dict[str, object]:
        return {"audit_banner": "Authorized internal security assessments only."}


def bootstrap_defaults(app: Flask) -> None:
    if User.query.count() == 0:
        admin = User(
            username=app.config["DEFAULT_ADMIN_USERNAME"],
            role="admin",
            is_active=True,
        )
        admin.set_password(app.config["DEFAULT_ADMIN_PASSWORD"])
        db.session.add(admin)

    default_settings = {
        "allowed_ranges": (
            app.config["DEFAULT_ALLOWED_RANGES"],
            "Comma separated internal ranges that scans must remain within.",
        ),
        "default_batch_size": (str(app.config["DEFAULT_BATCH_SIZE"]), "Default concurrent targets per batch."),
        "max_concurrency": (str(app.config["DEFAULT_MAX_CONCURRENCY"]), "Upper bound for user-selected concurrency."),
        "default_host_timeout": (str(app.config["DEFAULT_HOST_TIMEOUT"]), "Default Nmap timeout per host."),
        "default_retry_count": (str(app.config["DEFAULT_RETRY_COUNT"]), "Default retries for failed hosts."),
    }
    for key, (value, description) in default_settings.items():
        if AppSetting.get_value(key) is None:
            AppSetting.set_value(key, value, description)

    db.session.commit()
    if not AppSetting.query.filter_by(key="bootstrap_audit_done").first():
        AppSetting.set_value("bootstrap_audit_done", "true")
        audit(
            "system_bootstrap",
            object_type="system",
            object_id="bootstrap",
            details={"initialized": True},
        )
        db.session.commit()
