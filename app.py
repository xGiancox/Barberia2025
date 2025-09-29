from flask import Flask, render_template, request, redirect, url_for, jsonify, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'barber-app-peru-secret-key-2024'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///barberia.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Inicializar SQLAlchemy
db = SQLAlchemy(app)

# Modelos
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    nombre = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='trabajador')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    activo = db.Column(db.Boolean, default=True)
    
    registros = db.relationship('RegistroDiario', backref='barbero', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def get_id(self):
        return str(self.id)
    
    @property
    def is_authenticated(self):
        return True
    
    @property
    def is_active(self):
        return self.activo
    
    @property
    def is_anonymous(self):
        return False

class RegistroDiario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fecha = db.Column(db.Date, nullable=False, default=datetime.utcnow)
    cantidad_cortes = db.Column(db.Integer, nullable=False)
    precio_corte = db.Column(db.Float, nullable=False)
    gastos_productos = db.Column(db.Float, default=0.0)
    notas = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    @property
    def total_dia(self):
        return self.cantidad_cortes * self.precio_corte
    
    @property
    def ingreso_neto(self):
        return self.total_dia - self.gastos_productos
    
    @property
    def pago_barbero(self):
        # Si el usuario es jefe, no hay pago (se queda con el 100%)
        if self.barbero.role == 'jefe':
            return self.ingreso_neto
        else:
            # Para trabajadores, 50% del ingreso neto
            return self.ingreso_neto / 2
    
    @property
    def ganancia_barberia(self):
        # Si el usuario es jefe, la ganancia de la barbería es 0 (él se queda con todo)
        if self.barbero.role == 'jefe':
            return 0
        else:
            # Para trabajadores, la barbería se queda con el 50%
            return self.ingreso_neto / 2

# Configurar Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Inicializar base de datos
def init_db():
    with app.app_context():
        # Crear todas las tablas
        db.create_all()
        
        # Crear usuario jefe si no existe
        jefe_exists = User.query.filter_by(role='jefe').first()
        if not jefe_exists:
            jefe = User(
                email='jefe@barberapp.com',
                nombre='Administrador Principal',
                role='jefe'
            )
            jefe.set_password('admin123')
            db.session.add(jefe)
            db.session.commit()
            print("Usuario jefe creado exitosamente")

# Inicializar la base de datos al iniciar
init_db()

# Rutas
@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.role == 'trabajador':
            return redirect(url_for('registro_diario'))
        else:
            return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        user = User.query.filter_by(email=email, activo=True).first()
        
        if user and user.check_password(password):
            login_user(user)
            if user.role == 'trabajador':
                return redirect(url_for('registro_diario'))
            else:
                return redirect(url_for('dashboard'))
        else:
            flash('Email o contraseña incorrectos', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    # Si ya está autenticado, redirigir según su rol
    if current_user.is_authenticated:
        if current_user.role == 'trabajador':
            return redirect(url_for('registro_diario'))
        else:
            return redirect(url_for('dashboard'))
    
    # Verificar si ya existe un jefe
    jefe_exists = User.query.filter_by(role='jefe').first()
    
    if request.method == 'POST':
        email = request.form['email']
        nombre = request.form['nombre']
        password = request.form['password']
        
        # Solo permitir crear trabajadores si ya hay un jefe
        role = 'trabajador'
        
        if User.query.filter_by(email=email).first():
            flash('El email ya está registrado', 'error')
            return render_template('register.html', jefe_exists=jefe_exists)
        
        user = User(email=email, nombre=nombre, role=role)
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        flash('Usuario registrado exitosamente. Ahora puedes iniciar sesión.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', jefe_exists=jefe_exists)

@app.route('/registro-diario', methods=['GET', 'POST'])
@login_required
def registro_diario():
    if request.method == 'POST':
        try:
            fecha = datetime.strptime(request.form['fecha'], '%Y-%m-%d').date()
            cantidad_cortes = int(request.form['cantidad_cortes'])
            precio_corte = float(request.form['precio_corte'])
            gastos_productos = float(request.form['gastos_productos'] or 0)
            notas = request.form['notas']
            
            # Verificar si ya existe un registro para esta fecha y usuario
            registro_existente = RegistroDiario.query.filter_by(
                fecha=fecha, 
                user_id=current_user.id
            ).first()
            
            if registro_existente:
                flash('Ya existe un registro para esta fecha. Edita el registro existente.', 'error')
                if current_user.role == 'jefe':
                    return redirect(url_for('dashboard'))
                else:
                    return redirect(url_for('mis_registros'))
            
            registro = RegistroDiario(
                fecha=fecha,
                cantidad_cortes=cantidad_cortes,
                precio_corte=precio_corte,
                gastos_productos=gastos_productos,
                notas=notas,
                user_id=current_user.id
            )
            
            db.session.add(registro)
            db.session.commit()
            
            flash('Registro guardado exitosamente', 'success')
            if current_user.role == 'jefe':
                return redirect(url_for('dashboard'))
            else:
                return redirect(url_for('mis_registros'))
            
        except Exception as e:
            flash('Error al guardar el registro: ' + str(e), 'error')
    
    return render_template('registro_diario.html', hoy=datetime.now().date())

@app.route('/mis-registros')
@login_required
def mis_registros():
    # Si es jefe, redirigir al dashboard
    if current_user.role == 'jefe':
        return redirect(url_for('dashboard'))
    
    # Obtener registros del usuario actual
    registros = RegistroDiario.query.filter_by(user_id=current_user.id)\
        .order_by(RegistroDiario.fecha.desc()).all()
    
    # Calcular totales
    total_cortes = sum(r.cantidad_cortes for r in registros)
    total_ingresos = sum(r.total_dia for r in registros)
    total_pagos = sum(r.pago_barbero for r in registros)
    
    # Calcular pagos por período
    hoy = datetime.now().date()
    inicio_semana = hoy - timedelta(days=hoy.weekday())
    inicio_quincena = hoy - timedelta(days=14)
    
    registros_semana = [r for r in registros if r.fecha >= inicio_semana]
    registros_quincena = [r for r in registros if r.fecha >= inicio_quincena]
    
    pago_semana = sum(r.pago_barbero for r in registros_semana)
    pago_quincena = sum(r.pago_barbero for r in registros_quincena)
    
    return render_template('mis_registros.html',
                         registros=registros,
                         total_cortes=total_cortes,
                         total_ingresos=total_ingresos,
                         total_pagos=total_pagos,
                         pago_semana=pago_semana,
                         pago_quincena=pago_quincena,
                         hoy=hoy)

@app.route('/dashboard')
@login_required
def dashboard():
    hoy = datetime.now().date()
    
    if current_user.role == 'jefe':
        total_barberos = User.query.filter_by(role='trabajador', activo=True).count()
        registros_hoy = RegistroDiario.query.filter(RegistroDiario.fecha == hoy).all()
    else:
        registros_hoy = RegistroDiario.query.filter(
            RegistroDiario.user_id == current_user.id,
            RegistroDiario.fecha == hoy
        ).all()
        total_barberos = None
    
    total_cortes_hoy = sum(r.cantidad_cortes for r in registros_hoy) if registros_hoy else 0
    total_ingresos_hoy = sum(r.total_dia for r in registros_hoy) if registros_hoy else 0
    total_pagos_hoy = sum(r.pago_barbero for r in registros_hoy) if registros_hoy else 0
    
    return render_template('dashboard.html',
                         registros=registros_hoy,
                         total_cortes=total_cortes_hoy,
                         total_ingresos=total_ingresos_hoy,
                         total_pagos=total_pagos_hoy,
                         total_barberos=total_barberos,
                         hoy=hoy)

@app.route('/calendario')
@login_required
def calendario():
    # Solo jefes pueden acceder al calendario
    if current_user.role != 'jefe':
        flash('No tienes permisos para acceder a esta sección', 'error')
        return redirect(url_for('registro_diario'))
    
    # Obtener fechas con registros
    registros_fechas = db.session.query(RegistroDiario.fecha).distinct().all()
    fechas_con_registros = [r.fecha.strftime('%Y-%m-%d') for r in registros_fechas]
    
    return render_template('calendario.html', 
                         fechas_con_registros=fechas_con_registros,
                         hoy=datetime.now().date())

@app.route('/api/registros/<fecha>')
@login_required
def api_registros_fecha(fecha):
    # Solo jefes pueden acceder a la API
    if current_user.role != 'jefe':
        return jsonify({'error': 'No autorizado'}), 403
    
    try:
        fecha_obj = datetime.strptime(fecha, '%Y-%m-%d').date()
        registros = RegistroDiario.query.filter_by(fecha=fecha_obj).all()
        
        registros_data = []
        for r in registros:
            registros_data.append({
                'barbero': r.barbero.nombre,
                'cantidad_cortes': r.cantidad_cortes,
                'precio_corte': r.precio_corte,
                'total_dia': r.total_dia,
                'pago_barbero': r.pago_barbero
            })
        
        return jsonify(registros_data)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/reportes')
@login_required
def reportes():
    # Solo jefes pueden acceder a reportes
    if current_user.role != 'jefe':
        flash('No tienes permisos para acceder a esta sección', 'error')
        return redirect(url_for('registro_diario'))
    
    # Reportes por períodos
    hoy = datetime.now().date()
    semana_pasada = hoy - timedelta(days=7)
    mes_pasado = hoy - timedelta(days=30)
    
    query_base = RegistroDiario.query
    
    # Datos del día
    registros_hoy = query_base.filter(RegistroDiario.fecha == hoy).all()
    
    # Datos de la semana
    registros_semana = query_base.filter(
        RegistroDiario.fecha >= semana_pasada
    ).all()
    
    # Datos del mes
    registros_mes = query_base.filter(
        RegistroDiario.fecha >= mes_pasado
    ).all()
    
    def calcular_estadisticas(registros):
        if not registros:
            return {
                'total_cortes': 0,
                'total_ingresos': 0,
                'total_pagos': 0,
                'promedio_diario': 0
            }
        
        total_cortes = sum(r.cantidad_cortes for r in registros)
        total_ingresos = sum(r.total_dia for r in registros)
        total_pagos = sum(r.pago_barbero for r in registros)
        
        # Agrupar por fecha para calcular promedio diario
        fechas_unicas = len(set(r.fecha for r in registros))
        promedio_diario = total_ingresos / fechas_unicas if fechas_unicas > 0 else 0
        
        return {
            'total_cortes': total_cortes,
            'total_ingresos': total_ingresos,
            'total_pagos': total_pagos,
            'promedio_diario': promedio_diario
        }
    
    stats_hoy = calcular_estadisticas(registros_hoy)
    stats_semana = calcular_estadisticas(registros_semana)
    stats_mes = calcular_estadisticas(registros_mes)
    
    return render_template('reportes.html',
                         stats_hoy=stats_hoy,
                         stats_semana=stats_semana,
                         stats_mes=stats_mes,
                         hoy=hoy)

@app.route('/usuarios')
@login_required
def gestion_usuarios():
    if current_user.role != 'jefe':
        flash('No tienes permisos para acceder a esta sección', 'error')
        return redirect(url_for('registro_diario'))
    
    usuarios = User.query.filter(User.role != 'jefe').all()
    return render_template('usuarios.html', 
                         usuarios=usuarios,
                         hoy=datetime.now().date())

@app.route('/register-admin', methods=['GET', 'POST'])
@login_required
def register_admin():
    # Solo jefes pueden crear otros administradores
    if current_user.role != 'jefe':
        flash('No tienes permisos para acceder a esta sección', 'error')
        return redirect(url_for('registro_diario'))
    
    if request.method == 'POST':
        try:
            email = request.form['email']
            nombre = request.form['nombre']
            password = request.form['password']
            
            if User.query.filter_by(email=email).first():
                flash('El email ya está registrado', 'error')
                return render_template('register_admin.html', hoy=datetime.now().date())
            
            admin = User(
                email=email,
                nombre=nombre,
                role='jefe'
            )
            admin.set_password(password)
            
            db.session.add(admin)
            db.session.commit()
            
            flash('Administrador creado exitosamente', 'success')
            return redirect(url_for('gestion_usuarios'))
            
        except Exception as e:
            flash('Error al crear el administrador: ' + str(e), 'error')
    
    return render_template('register_admin.html', hoy=datetime.now().date())

@app.route('/usuario/<int:user_id>')
@login_required
def ver_usuario(user_id):
    if current_user.role != 'jefe':
        flash('No tienes permisos para acceder a esta sección', 'error')
        return redirect(url_for('dashboard'))
    
    usuario = User.query.get_or_404(user_id)
    
    # Estadísticas del usuario
    registros_usuario = RegistroDiario.query.filter_by(user_id=user_id).all()
    total_registros = len(registros_usuario)
    total_cortes = sum(r.cantidad_cortes for r in registros_usuario)
    total_ingresos = sum(r.total_dia for r in registros_usuario)
    total_pagos = sum(r.pago_barbero for r in registros_usuario)
    
    # Últimos 5 registros
    ultimos_registros = RegistroDiario.query.filter_by(user_id=user_id)\
        .order_by(RegistroDiario.fecha.desc()).limit(5).all()
    
    return render_template('ver_usuario.html',
                         usuario=usuario,
                         total_registros=total_registros,
                         total_cortes=total_cortes,
                         total_ingresos=total_ingresos,
                         total_pagos=total_pagos,
                         ultimos_registros=ultimos_registros,
                         hoy=datetime.now().date())

@app.route('/usuario/<int:user_id>/editar', methods=['GET', 'POST'])
@login_required
def editar_usuario(user_id):
    if current_user.role != 'jefe':
        flash('No tienes permisos para acceder a esta sección', 'error')
        return redirect(url_for('dashboard'))
    
    usuario = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        try:
            usuario.nombre = request.form['nombre']
            usuario.email = request.form['email']
            
            # Verificar si el email ya existe (excluyendo el usuario actual)
            existing_user = User.query.filter(
                User.email == request.form['email'],
                User.id != user_id
            ).first()
            
            if existing_user:
                flash('El email ya está en uso por otro usuario', 'error')
                return render_template('editar_usuario.html', usuario=usuario, hoy=datetime.now().date())
            
            # Actualizar contraseña si se proporcionó una nueva
            nueva_password = request.form.get('password')
            if nueva_password:
                usuario.set_password(nueva_password)
            
            db.session.commit()
            flash('Usuario actualizado exitosamente', 'success')
            return redirect(url_for('ver_usuario', user_id=user_id))
            
        except Exception as e:
            flash('Error al actualizar el usuario: ' + str(e), 'error')
    
    return render_template('editar_usuario.html', usuario=usuario, hoy=datetime.now().date())

@app.route('/usuario/<int:user_id>/eliminar', methods=['POST'])
@login_required
def eliminar_usuario(user_id):
    if current_user.role != 'jefe':
        flash('No tienes permisos para realizar esta acción', 'error')
        return redirect(url_for('dashboard'))
    
    if user_id == current_user.id:
        flash('No puedes eliminar tu propio usuario', 'error')
        return redirect(url_for('gestion_usuarios'))
    
    usuario = User.query.get_or_404(user_id)
    
    try:
        # Eliminar primero los registros del usuario
        RegistroDiario.query.filter_by(user_id=user_id).delete()
        
        # Eliminar el usuario
        db.session.delete(usuario)
        db.session.commit()
        
        flash('Usuario eliminado exitosamente', 'success')
    except Exception as e:
        flash('Error al eliminar el usuario: ' + str(e), 'error')
    
    return redirect(url_for('gestion_usuarios'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Sesión cerrada exitosamente', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
