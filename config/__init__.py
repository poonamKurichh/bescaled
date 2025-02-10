# config/__init__.py

import os
from .development import DevelopmentConfig
from .production import ProductionConfig
from .testing import TestingConfig

# Dynamically select the configuration based on an environment variable
ENV = os.getenv('FLASK_ENV', 'development')  # Default to development

if ENV == 'development':
    CurrentConfig = DevelopmentConfig
elif ENV == 'production':
    CurrentConfig = ProductionConfig
elif ENV == 'testing':
    CurrentConfig = TestingConfig
else:
    raise ValueError(f"Invalid FLASK_ENV value: {ENV}")
