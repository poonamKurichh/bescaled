from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

# models/__init__.py

from .user import User, UserRoles # Assuming  is in user.py
from .menu import Menu,MenuItem  # Assuming Menu model is in menu.py
from .page import Page  # Assuming Page is in page.py

# You can import additional models as needed:
# from .other_models import OtherModel

__all__ = [ 'db','Menu', 'MenuItem','Page','User','UserRoles']