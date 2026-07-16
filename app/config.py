import os
from datetime import timedelta
from dotenv import load_dotenv
load_dotenv()

class BaseConfig:
    SECRET_KEY = os.environ["SECRET_KEY"]
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///secauthos.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = os.environ["JWT_SECRET_KEY"]
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=15)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=14)
    JWT_TOKEN_LOCATION = ["headers"]
    API_TITLE = "SecAuthos API"; API_VERSION = "v1"; OPENAPI_VERSION = "3.0.3"
    OPENAPI_URL_PREFIX = "/"; OPENAPI_SWAGGER_UI_PATH = "/docs"; OPENAPI_SWAGGER_UI_URL = "https://cdn.jsdelivr.net/npm/swagger-ui-dist/"
    RATELIMIT_STORAGE_URI = os.getenv("REDIS_URL", "memory://")
    RATELIMIT_HEADERS_ENABLED = True
    ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000")
    TALISMAN_ENABLED = os.getenv("TALISMAN_ENABLED", "false").lower() == "true"
    PASSWORD_PEPPER = os.getenv("PASSWORD_PEPPER", "")
    MAX_CONTENT_LENGTH = 1024 * 1024
class DevelopmentConfig(BaseConfig): DEBUG = True
class TestingConfig(BaseConfig):
    TESTING = True; SQLALCHEMY_DATABASE_URI = "sqlite://"; TALISMAN_ENABLED = False
    SECRET_KEY = "test-secret"; JWT_SECRET_KEY = "test-jwt-secret"
config = {"default": DevelopmentConfig, "development": DevelopmentConfig, "testing": TestingConfig}
