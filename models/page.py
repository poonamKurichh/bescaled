from models import db

class Page(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False, unique=True)  # Page Title
    slug = db.Column(db.String(255), nullable=False, unique=True)  # URL Slug
    content = db.Column(db.Text, nullable=False)  # Page Content (HTML/Markdown)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    updated_at = db.Column(db.DateTime, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())
