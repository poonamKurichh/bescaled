from flask import Blueprint, request, jsonify
from models import db
from models.page import Page


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

#@page_routes.route('/api/pages', methods=['POST'])
#def create_page():
    """Create a new page."""
 #   data = request.json
#    new_page = Page(title=data['title'], slug=data['slug'], content=data['content'])
 #   db.session.add(new_page)
 #   db.session.commit()
#    return jsonify({"message": "Page created", "id": new_page.id})

@page_routes.route('/api/pages', methods=['POST'])
def create_page():
    """
    Create a new page with an editor's formatted content saved as HTML.
    Expects:
    {
        "title": "Page Title",
        "slug": "page-title",
        "content": "<h1>Hello World</h1><p>This is a rich text page!</p>",
        "author": "Admin"
    }
    """
    data = request.get_json()
    title = data.get('title')
    slug = data.get('slug')
    content = data.get('content')  # HTML from the rich text editor
    author = data.get('author')

    if not title or not slug or not content or not author:
        return jsonify({"error": "All fields (title, slug, content, author) are required"}), 400

    new_page = Page(title=title, slug=slug, content=content, author=author)
    try:
        db.session.add(new_page)
        db.session.commit()
        return jsonify({"message": "Page created successfully!", "page": new_page.serialize()}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"Failed to create page: {str(e)}"}), 500


@page_routes.route('/api/pages/<int:page_id>', methods=['DELETE'])
def delete_page(page_id):
    """Delete a page."""
    page = Page.query.get(page_id)
    if not page:
        return jsonify({"error": "Page not found"}), 404
    db.session.delete(page)
    db.session.commit()
    return jsonify({"message": "Page deleted"})
