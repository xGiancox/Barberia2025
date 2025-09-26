from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date, timedelta
from functools import wraps
import os

app = Flask(__name__)

# Configuración para producción
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'barberapp_secret_key_2024')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///database.db').replace('postgres://', 'postgresql://')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Modelos (mantener igual)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='barbero')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    cuts = db.relationship('HairCut', backref='barber', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class HairCut(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date_cut = db.Column(db.Date, nullable=False)
    date_recorded = db.Column(db.DateTime, default=datetime.utcnow)
    price = db.Column(db.Float, nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    total = db.Column(db.Float, nullable=False)
    divided_total = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class MonthlyExpense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    month_year = db.Column(db.String(7), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(200))
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ProductSale(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date_sale = db.Column(db.Date, nullable=False)
    date_recorded = db.Column(db.DateTime, default=datetime.utcnow)
    product_name = db.Column(db.String(200), nullable=False)
    price = db.Column(db.Float, nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    total = db.Column(db.Float, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Decoradores (mantener igual)
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def jefe_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if user.role != 'jefe':
            flash('No tienes permisos para acceder a esta página', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Todas las rutas se mantienen EXACTAMENTE igual...
# [PEGA AQUÍ TODAS TUS RUTAS ACTUALES SIN MODIFICAR]

# ... tus rutas existentes ...

@app.route('/')
def index():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user.role == 'jefe':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            session['user_id'] = user.id
            session['user_name'] = user.name
            session['user_role'] = user.role

            if user.role == 'jefe':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('dashboard'))
        else:
            flash('Email o contraseña incorrectos', 'error')

    return render_template('login.html')

# ... pega aquí TODAS las demás rutas de tu app.py actual ...

@app.route('/admin/product_sales', methods=['GET', 'POST'])
@jefe_required
def admin_product_sales():
    if request.method == 'POST':
        try:
            date_sale_str = request.form['date_sale']
            product_name = request.form['product_name']
            price = float(request.form['price'])
            quantity = int(request.form['quantity'])

            date_sale = datetime.strptime(date_sale_str, '%Y-%m-%d').date()
            total = price * quantity

            sale = ProductSale(
                date_sale=date_sale,
                product_name=product_name,
                price=price,
                quantity=quantity,
                total=total,
                created_by=session['user_id']
            )

            db.session.add(sale)
            db.session.commit()

            flash('Venta de producto registrada exitosamente', 'success')
            return redirect(url_for('admin_product_sales'))

        except Exception as e:
            flash('Error al registrar la venta: ' + str(e), 'error')

    product_sales = ProductSale.query.order_by(ProductSale.date_sale.desc()).all()

    today = date.today()
    today_sales = ProductSale.query.filter_by(date_sale=today).all()
    today_total = sum(sale.total for sale in today_sales)

    month_sales = ProductSale.query.filter(
        ProductSale.date_sale >= date(today.year, today.month, 1)
    ).all()
    month_total = sum(sale.total for sale in month_sales)

    current_date = datetime.now().strftime('%Y-%m-%d')

    return render_template('admin_product_sales.html',
                         product_sales=product_sales,
                         today_total=today_total,
                         month_total=month_total,
                         current_date=current_date)

@app.route('/admin/delete_product_sale/<int:sale_id>')
@jefe_required
def delete_product_sale(sale_id):
    sale = ProductSale.query.get_or_404(sale_id)
    db.session.delete(sale)
    db.session.commit()
    flash('Venta de producto eliminada exitosamente', 'success')
    return redirect(url_for('admin_product_sales'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/manifest.json')
def manifest():
    return app.send_static_file('manifest.json')

# Inicialización de la base de datos
def initialize_database():
    with app.app_context():
        db.create_all()

        # Crear usuario jefe por defecto si no existe
        if not User.query.filter_by(role='jefe').first():
            jefe = User(email='jefe@barberia.com', name='Jefe Principal', role='jefe')
            jefe.set_password('admin123')
            db.session.add(jefe)
            db.session.commit()
            print("✅ Usuario jefe creado: jefe@barberia.com / admin123")

        print("✅ Base de datos inicializada")

# Inicializar al importar
initialize_database()

# Solo ejecutar el servidor de desarrollo si es el archivo principal
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
else:
    # Para producción con Gunicorn
    pass