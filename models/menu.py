from models import db


class Menu(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    items = db.relationship('MenuItem', backref='menu', lazy=True, cascade="all, delete")


class MenuItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    menu_id = db.Column(db.Integer, db.ForeignKey('menu.id'), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('menu_item.id'), nullable=True)  # ✅ Supports nesting
    title = db.Column(db.String(100), nullable=False)
    url = db.Column(db.String(255), nullable=False)
    order = db.Column(db.Integer, nullable=False, default=0)

    children = db.relationship(
        'MenuItem',
        backref=db.backref('parent', remote_side=[id]),
        lazy='dynamic'
    )
