# config/production.py

from .base import Config


class ProductionConfig(Config):
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = 'postgresql://user:password@localhost/prod_db'
    SECRET_KEY = 'a_secure_production_key'
