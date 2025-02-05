from flask import Flask, render_template, redirect, url_for, session, g, flash
from flask_jwt_extended import JWTManager  # ✅ Import JWT
from flask_login import LoginManager, current_user
from extensions import mail
from dotenv import load_dotenv
from flask_cors import CORS
import os
from routes import register_blueprints
from functools import wraps
from flask_migrate import Migrate
from models import db  # ✅ Import SQLAlchemy & models
from config import CurrentConfig  # ✅ Load dynamically selected config

# Load .env values
load_dotenv()

# ✅ Initialize JWT globally (but don't attach it to the app yet)
jwt = JWTManager()
login_manager = LoginManager()  # ✅ Initialize LoginManager globally


def create_app():
    app = Flask(__name__)

    # ✅ Load configurations
    app.config.from_object(CurrentConfig)

    # App Configurations
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
    app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
    app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
    app.config['MAIL_USE_SSL'] = os.getenv('MAIL_USE_SSL') == 'True'
    app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS') == 'True'
    app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
    app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')
    app.config['UPLOAD_FOLDER'] = 'static/upload'

    # ✅ Configure Flask-JWT for React Frontend Authentication
    app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")  # Use environment variable
    app.config["JWT_TOKEN_LOCATION"] = ["headers"]  # Ensure JWT is received via HTTP headers
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRES", 3600))  # Token expiry (1 hour default)
    app.config["JWT_REFRESH_TOKEN_EXPIRES"] = int(os.getenv("JWT_REFRESH_TOKEN_EXPIRES", 86400))  # Refresh token expiry (1 day default)

    # ✅ Initialize Flask Extensions
    mail.init_app(app)  # Flask-Mail
    CORS(app, resources={r"/*": {"origins": "http://localhost:3000"}})  # Enable CORS for React
    jwt.init_app(app)  # ✅ Properly initialize JWT here
    db.init_app(app)  # ✅ Initialize SQLAlchemy

    # ✅ Initialize Flask-Login
    login_manager.init_app(app)  # ✅ Attach login manager to Flask app
    login_manager.login_view = "user_routes.admin_login"  # ✅ Redirect unauthorized users

    # Lazy-print the database URL only inside an app context
    with app.app_context():
        print(f"✅ Database URL: {app.config['SQLALCHEMY_DATABASE_URI']}")

    # ✅ Register models before running migrations
    with app.app_context():
        from models.user import User, UserRoles  # ✅ Import here to avoid circular import
        from models.menu import Menu, MenuItem
        from models.page import Page
        db.create_all()    # ✅ Create tables if they don't exist

    # ✅ Initialize Flask-Migrate
    migrate = Migrate(app, db)

    # Register Blueprints
    register_blueprints(app)


    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))  # ✅ Fetch user from DB using ID

    # Admin-only route
    @app.context_processor
    def inject_user():
        return {'user': current_user}

    @app.route("/")
    def home():
        """Redirect to login if authenticated, otherwise go to login page."""
        if current_user.is_authenticated:  # ✅ Correct way to check if user is logged in
            return redirect(url_for("user_routes.admin_dashboard"))
        return redirect(url_for("user_routes.admin_login"))

    return app
