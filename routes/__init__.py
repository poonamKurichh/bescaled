from flask import Blueprint
from .user_routes import user_routes
from .item_routes import item_routes

def register_blueprints(app):
    """Registers all Flask blueprints."""
    app.register_blueprint(user_routes, url_prefix="/")
    app.register_blueprint(item_routes, url_prefix="/api/items")
