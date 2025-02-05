from flask import Blueprint, request, jsonify
from models import db, Page

page_routes = Blueprint("page_routes", __name__)

@page_routes.route('/api/pages', methods=['GET'])
def get_pages():
    """Retrieve all pages."""
    pages = Page.query.all()
    return jsonify([{"id": p.id, "title": p.title, "slug": p.slug} for p in pages])

@page_routes.route('/api/pages/<string:slug>', methods=['GET'])
def get_page(slug):
    """Retrieve a single page by slug."""
    page = Page.query.filter_by(slug=slug).first()
    if not page:
        return jsonify({"error": "Page not found"}), 404
    return jsonify({"title": page.title, "content": page.content})

@page_routes.route('/api/pages', methods=['POST'])
def create_page():
    """Create a new page."""
    data = request.json
    new_page = Page(title=data['title'], slug=data['slug'], content=data['content'])
    db.session.add(new_page)
    db.session.commit()
    return jsonify({"message": "Page created", "id": new_page.id})

@page_routes.route('/api/pages/<int:page_id>', methods=['DELETE'])
def delete_page(page_id):
    """Delete a page."""
    page = Page.query.get(page_id)
    if not page:
        return jsonify({"error": "Page not found"}), 404
    db.session.delete(page)
    db.session.commit()
    return jsonify({"message": "Page deleted"})
