from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='barbero')  # 'jefe' o 'barbero'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    cuts = db.relationship('HairCut', backref='barber', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class HairCut(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date_cut = db.Column(db.Date, nullable=False)  # Fecha cuando se hizo el corte
    date_recorded = db.Column(db.DateTime, default=datetime.utcnow)  # Fecha cuando se registró
    price = db.Column(db.Float, nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    total = db.Column(db.Float, nullable=False)
    divided_total = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class MonthlyExpense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    month_year = db.Column(db.String(7), nullable=False)  # Formato: YYYY-MM
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(200))
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    creator = db.relationship('User', backref='expenses')

class ProductSale(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date_sale = db.Column(db.Date, nullable=False)
    date_recorded = db.Column(db.DateTime, default=datetime.utcnow)
    product_name = db.Column(db.String(200), nullable=False)
    price = db.Column(db.Float, nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    total = db.Column(db.Float, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # Relación con el usuario que creó la venta
    creator = db.relationship('User', backref='product_sales')