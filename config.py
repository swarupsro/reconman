import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-production")
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        f"sqlite:///{BASE_DIR / 'instance' / 'reconman.db'}",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    RQ_REDIS_URL = os.getenv("RQ_REDIS_URL", REDIS_URL)
    SOCKETIO_MESSAGE_QUEUE = os.getenv("SOCKETIO_MESSAGE_QUEUE", REDIS_URL)
    RATELIMIT_STORAGE_URI = os.getenv("RATELIMIT_STORAGE_URI", REDIS_URL)
    RATELIMIT_DEFAULT = os.getenv("RATELIMIT_DEFAULT", "200 per day;50 per hour")
    SESSION_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    DEFAULT_ADMIN_USERNAME = os.getenv("DEFAULT_ADMIN_USERNAME", "admin")
    DEFAULT_ADMIN_PASSWORD = os.getenv("DEFAULT_ADMIN_PASSWORD", "ChangeMe123!")
    DEFAULT_ALLOWED_RANGES = os.getenv(
        "DEFAULT_ALLOWED_RANGES",
        "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16",
    )
    DEFAULT_BATCH_SIZE = int(os.getenv("DEFAULT_BATCH_SIZE", "25"))
    DEFAULT_HOST_TIMEOUT = int(os.getenv("DEFAULT_HOST_TIMEOUT", "300"))
    DEFAULT_MAX_CONCURRENCY = int(os.getenv("DEFAULT_MAX_CONCURRENCY", "50"))
    DEFAULT_RETRY_COUNT = int(os.getenv("DEFAULT_RETRY_COUNT", "1"))
    NMAP_BINARY = os.getenv("NMAP_BINARY", "nmap")
    ENABLE_SYN_SCAN = os.getenv("ENABLE_SYN_SCAN", "false").lower() == "true"
    SCAN_RATE_LIMIT = os.getenv("SCAN_RATE_LIMIT", "10/hour")
    RESULTS_PER_PAGE = int(os.getenv("RESULTS_PER_PAGE", "20"))
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True}


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False


config_by_name = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}
