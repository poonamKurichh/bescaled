from flask import Blueprint, request, jsonify
from models import db, Menu, MenuItem

menu_routes = Blueprint("menu_routes", __name__)


def get_nested_menu(menu_id, parent_id=None):
    """ Recursively get menu items and their children """
    items = MenuItem.query.filter_by(menu_id=menu_id, parent_id=parent_id).order_by(MenuItem.order).all()
    return [{"id": i.id, "title": i.title, "url": i.url, "order": i.order,
             "children": get_nested_menu(menu_id, i.id)} for i in items]


@menu_routes.route('/api/menus/<int:menu_id>/nested', methods=['GET'])
def get_menu_with_nested_items(menu_id):
    """Retrieve nested menu structure"""
    menu = Menu.query.get(menu_id)
    if not menu:
        return jsonify({"error": "Menu not found"}), 404

    nested_items = get_nested_menu(menu_id)
    return jsonify({"menu": {"id": menu.id, "name": menu.name, "items": nested_items}})


@menu_routes.route('/api/menu_items', methods=['POST'])
def add_menu_item():
    """Add a new menu item (Supports Nesting)"""
    data = request.json
    new_item = MenuItem(
        menu_id=data['menu_id'],
        parent_id=data.get('parent_id'),  # ✅ Parent ID is optional
        title=data['title'],
        url=data['url'],
        order=data.get('order', 0)
    )
    db.session.add(new_item)
    db.session.commit()
    return jsonify({"message": "Menu item added", "id": new_item.id})


@menu_routes.route('/api/menu_items/order', methods=['PUT'])
def update_menu_order():
    """Update menu item order (Supports Drag & Drop)"""
    data = request.json  # Expecting list of {id, order}

    for item in data:
        menu_item = MenuItem.query.get(item['id'])
        if menu_item:
            menu_item.order = item['order']

    db.session.commit()
    return jsonify({"message": "Menu order updated"})


@menu_routes.route('/api/menu_items/<int:item_id>', methods=['DELETE'])
def delete_menu_item(item_id):
    """Delete a menu item"""
    item = MenuItem.query.get(item_id)
    if not item:
        return jsonify({"error": "Menu item not found"}), 404

    db.session.delete(item)
    db.session.commit()
    return jsonify({"message": "Menu item deleted"})
