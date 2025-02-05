from flask import Blueprint, render_template
from models import db
from models.menu import MenuItem
from models.page import Page


mp_routes = Blueprint('frontend_menus_pages', __name__)


# Render Menu Management Page
@mp_routes.route('/api/get_menus', methods=['GET'])
def menu_management():
    menu_items = MenuItem.query.order_by(MenuItem.order.asc()).all()
    return render_template('menus/menus.html', menu_items=menu_items)


# Render Page Management Page
@mp_routes.route('/api/pages/new', methods=['GET'])
@mp_routes.route('/api/pages/<int:page_id>', methods=['GET'])
def page_management(page_id=None):
    if page_id:
        page = Page.query.get(page_id)
    else:
        page = None
    return render_template('pages/create_frontend_page.html', page=page)
