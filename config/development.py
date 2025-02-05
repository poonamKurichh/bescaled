# config/development.py

from .base import Config


class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_ECHO = True  # ✅ Enable SQL query logging for debugging

