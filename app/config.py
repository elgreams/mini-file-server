import os
BASE_DIR = os.path.dirname(__file__)
SECRET_KEY = os.environ.get("APP_SECRET_KEY", "dev-secret-change-me")
UPLOAD_ROOT = os.environ.get("APP_UPLOAD_ROOT", os.path.join(BASE_DIR, "uploads"))
SITE_DOMAIN = os.environ.get("APP_SITE_DOMAIN")
SITE_TAGLINE = os.environ.get(
    "APP_SITE_TAGLINE", "Fast and reliable file hosting service."
)

# Default to 10GB max uploads unless overridden via environment
MAX_CONTENT_LENGTH = int(os.environ.get("APP_MAX_CONTENT_MB", str(10 * 1024))) * 1024 * 1024

# Allow all extensions by default; a comma-separated env var can restrict them
_raw_exts = os.environ.get("APP_ALLOWED_EXTS")
ALLOWED_EXTS = set(_raw_exts.split(",")) if _raw_exts else None
