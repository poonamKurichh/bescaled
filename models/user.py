from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

from models import db

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(50), nullable=False)
    lastname = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    contact_no = db.Column(db.String(15), nullable=True)
    password_hash = db.Column(db.String(128), nullable=False)
    address = db.Column(db.String(200), nullable=True)
    city = db.Column(db.String(100), nullable=True)
    country = db.Column(db.String(100), nullable=True)
    pincode = db.Column(db.String(10), nullable=True)
    business_area = db.Column(db.String(100), nullable=False, default='Information technology')
    ERP = db.Column(db.String(100), nullable=False, default='SAP')
    other_ques_comments = db.Column(db.String(200), nullable=True)
    company = db.Column(db.String(100), nullable=True)  # New company field
    role = db.Column(db.String(20), nullable=False, default='guest')  # Role can be 'admin', 'manager', or 'guest'
    job = db.Column(db.String(100), nullable=True)  # New job field
    about = db.Column(db.String(500), nullable=True)  # New about field
    twitter_profile = db.Column(db.String(100), nullable=True)  # New twitter field
    facebook_profile = db.Column(db.String(100), nullable=True)  # New facebook field
    instagram_profile = db.Column(db.String(100), nullable=True)  # New instagram field
    linkedin_profile = db.Column(db.String(100), nullable=True)  # New LinkedIn field
    profile_image = db.Column(db.String(255), default=None)  # New column for profile image
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    # Extend the role logic
    @property
    def is_admin(self):
        return self.role == "admin"
    
    @property
    def is_authenticated(self):
        """Return True if the user is authenticated."""
        return True

    @property
    def is_anonymous(self):
        """Return False for authenticated users."""
        return False

    def get_id(self):
        """Return the unique identifier for the user."""
        return str(self.id)

    @property
    def is_manager(self):
        return self.role == "manager"

class Item(db.Model):
    __tablename__ = 'items'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200), nullable=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

class UserRoles(db.Model):
    __tablename__ = 'user_roles'
    id = db.Column(db.Integer, primary_key=True)
    user_role = db.Column(db.String(50), unique=True, nullable=False)
