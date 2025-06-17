from flask import Flask, render_template, request, redirect, url_for, flash, make_response, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError
import pandas as pd
from io import BytesIO
import datetime
from dotenv import load_dotenv
import os
from xhtml2pdf import pisa

load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
# app.config['PDFKIT_CONFIG'] = pdfkit.configuration(wkhtmltopdf=r'C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Modelo de Usuario
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cedula = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    jefe_id = db.Column(db.Integer, db.ForeignKey('jefe_patrulla.id'), nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    nombre = db.Column(db.String(100))
    first_login = db.Column(db.Boolean, default=True)

class JefePatrulla(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    responsable = db.Column(db.String(100), nullable=False)
    cedula = db.Column(db.String(20), nullable=False, unique=True)
    centro_votacion = db.Column(db.String(100), nullable=False)
    telefono = db.Column(db.String(20))
    sector = db.Column(db.String(100))
    epm = db.Column(db.Boolean, default=False)
    ubch = db.Column(db.Boolean, default=False)
    comunidad = db.Column(db.Boolean, default=False)
    calle = db.Column(db.Boolean, default=False)
    militante = db.Column(db.Boolean, default=False)
    clap = db.Column(db.Boolean, default=False)
    mgm = db.Column(db.Boolean, default=False)
    mujeres = db.Column(db.Boolean, default=False)
    sv = db.Column(db.Boolean, default=False)
    milicia = db.Column(db.Boolean, default=False)
    consejo_comunal = db.Column(db.Boolean, default=False)
    comuna = db.Column(db.Boolean, default=False)
    cir_comunal = db.Column(db.Boolean, default=False)
    gppsb = db.Column(db.Boolean, default=False)
    mov_sociales = db.Column(db.Boolean, default=False)
    salud = db.Column(db.Boolean, default=False)
    educacion = db.Column(db.Boolean, default=False)
    corpoelec = db.Column(db.Boolean, default=False)
    h2o = db.Column(db.Boolean, default=False)
    saren = db.Column(db.Boolean, default=False)
    policia = db.Column(db.Boolean, default=False)
    ffm = db.Column(db.Boolean, default=False)
    linder = db.Column(db.Boolean, default=False)
    otro = db.Column(db.String(100))
    patrulleros = db.relationship('Patrullero', backref='jefe', lazy=True, cascade="all, delete-orphan")
    user = db.relationship('User', backref='jefe', uselist=False)

class Patrullero(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jefe_id = db.Column(db.Integer, db.ForeignKey('jefe_patrulla.id'), nullable=False)
    numero = db.Column(db.Integer)
    cedula = db.Column(db.String(20))
    nombres_apellidos = db.Column(db.String(100))
    telefono = db.Column(db.String(20))
    direccion = db.Column(db.String(200))
    centro_votacion = db.Column(db.String(100))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def cedula_existe(cedula):
    """Verifica si una cédula ya existe como jefe o patrullero"""
    # Verificar si es jefe
    if JefePatrulla.query.filter_by(cedula=cedula).first():
        return True
    
    # Verificar si es patrullero
    if Patrullero.query.filter_by(cedula=cedula).first():
        return True
    
    return False

def cedula_valida(cedula, patrullero_id=None):
    """Verifica si una cédula es válida para un nuevo o actualizado patrullero"""
    # Si la cédula está vacía, es válida
    if not cedula.strip():
        return True
    
    # Buscar si existe otro patrullero con la misma cédula
    patrullero_existente = Patrullero.query.filter_by(cedula=cedula).first()
    
    if patrullero_existente:
        # Si estamos actualizando el mismo patrullero, es válido
        if patrullero_id and patrullero_existente.id == patrullero_id:
            return True
        # Si es un nuevo patrullero o actualizando a otro, no es válido
        return False
    
    # Verificar si la cédula pertenece a algún jefe
    if JefePatrulla.query.filter_by(cedula=cedula).first():
        return False
    
    return True

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        cedula = request.form['cedula']
        password = request.form['password']
        user = User.query.filter_by(cedula=cedula).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Has iniciado sesión correctamente', 'success')
            
            if user.first_login:
                return redirect(url_for('cambiar_contrasena'))
                
            return redirect(url_for('dashboard'))
        flash('Cédula o contraseña incorrectos', 'danger')
    return render_template('login.html')

@app.route('/cambiar_contrasena', methods=['GET', 'POST'])
@login_required
def cambiar_contrasena():
    if request.method == 'POST':
        actual = request.form['actual']
        nueva = request.form['nueva']
        confirmacion = request.form['confirmacion']
        
        if not check_password_hash(current_user.password, actual):
            flash('Contraseña actual incorrecta', 'danger')
            return render_template('cambiar_contrasena.html')
        
        if nueva != confirmacion:
            flash('Las nuevas contraseñas no coinciden', 'danger')
            return render_template('cambiar_contrasena.html')
        
        current_user.password = generate_password_hash(nueva, method='pbkdf2:sha256')
        current_user.first_login = False
        db.session.commit()
        
        flash('Contraseña actualizada exitosamente', 'success')
        return redirect(url_for('dashboard'))
    
    mensaje = "Por seguridad, debe cambiar su contraseña inicial" if current_user.first_login else ""
    return render_template('cambiar_contrasena.html', primer_inicio=current_user.first_login, mensaje=mensaje)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Has cerrado sesión correctamente', 'success')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.first_login:
        return redirect(url_for('cambiar_contrasena'))
    
    if current_user.jefe:
        return render_template('dashboard.html', jefe=current_user.jefe)
    
    return render_template('registro_pendiente.html')

@app.route('/registro_jefe', methods=['GET', 'POST'])
@login_required
def registro_jefe():
    if current_user.first_login:
        return redirect(url_for('cambiar_contrasena'))
    
    if current_user.jefe:
        flash('Ya eres jefe de una patrulla', 'warning')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        try:
            cedula_jefe = request.form['cedula']
            
            # Verificar si la cédula del jefe ya existe
            if cedula_existe(cedula_jefe):
                flash('La cédula del jefe ya está registrada como patrullero o en otra patrulla', 'danger')
                return redirect(url_for('registro_jefe'))
            
            # Registrar jefe de patrulla
            jefe = JefePatrulla(
                responsable=request.form['responsable'],
                cedula=cedula_jefe,
                centro_votacion=request.form['centro_votacion'],
                telefono=request.form['telefono'],
                sector=request.form['sector'],
                epm='epm' in request.form,
                ubch='ubch' in request.form,
                comunidad='comunidad' in request.form,
                calle='calle' in request.form,
                militante='militante' in request.form,
                clap='clap' in request.form,
                mgm='mgm' in request.form,
                mujeres='mujeres' in request.form,
                sv='sv' in request.form,
                milicia='milicia' in request.form,
                consejo_comunal='consejo_comunal' in request.form,
                comuna='comuna' in request.form,
                cir_comunal='cir_comunal' in request.form,
                gppsb='gppsb' in request.form,
                mov_sociales='mov_sociales' in request.form,
                salud='salud' in request.form,
                educacion='educacion' in request.form,
                corpoelec='corpoelec' in request.form,
                h2o='h2o' in request.form,
                saren='saren' in request.form,
                policia='policia' in request.form,
                ffm='ffm' in request.form,
                linder='linder' in request.form,
                otro=request.form.get('otro', '')
            )
            db.session.add(jefe)
            db.session.flush()  # Obtener ID sin commit
            
            # Registrar patrulleros
            cedulas_registradas = set()
            for i in range(1, 22):
                cedula = request.form.get(f'cedula_{i}', '').strip()
                nombres = request.form.get(f'nombres_{i}', '').strip()
                
                if cedula or nombres:
                    # Verificar si la cédula ya está en uso
                    if cedula:
                        if cedula in cedulas_registradas:
                            flash(f'La cédula {cedula} está duplicada en el formulario (fila {i})', 'danger')
                            return redirect(url_for('registro_jefe'))
                            
                        if cedula_existe(cedula):
                            flash(f'La cédula {cedula} ya está registrada como patrullero o jefe (fila {i})', 'danger')
                            return redirect(url_for('registro_jefe'))
                            
                        cedulas_registradas.add(cedula)
                    
                    patrullero = Patrullero(
                        jefe_id=jefe.id,
                        numero=i,
                        cedula=cedula,
                        nombres_apellidos=nombres,
                        telefono=request.form.get(f'telefono_{i}', ''),
                        direccion=request.form.get(f'direccion_{i}', ''),
                        centro_votacion=request.form.get(f'centro_votacion_{i}', '')
                    )
                    db.session.add(patrullero)
            
            # Asociar el jefe al usuario actual
            current_user.jefe_id = jefe.id
            db.session.commit()
            
            flash('¡Registro de patrulla completado exitosamente!', 'success')
            return redirect(url_for('ver_patrulla', jefe_id=jefe.id))
        
        except IntegrityError:
            db.session.rollback()
            flash('Error: La cédula del jefe ya está registrada', 'danger')
            return redirect(url_for('registro_jefe'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error inesperado: {str(e)}', 'danger')
            return redirect(url_for('registro_jefe'))
    
    return render_template('registrar_jefe.html', usuario=current_user)

@app.route('/ver_patrulla/<int:jefe_id>')
@login_required
def ver_patrulla(jefe_id):
    # Verificar que el usuario tenga acceso a esta patrulla
    if not current_user.is_admin and (not current_user.jefe or current_user.jefe.id != jefe_id):
        flash('No tienes permiso para ver esta patrulla', 'danger')
        return redirect(url_for('dashboard'))
    
    jefe = JefePatrulla.query.get_or_404(jefe_id)
    patrulleros = Patrullero.query.filter_by(jefe_id=jefe_id).order_by(Patrullero.numero).all()
    
    return render_template('ver_patrulla.html', jefe=jefe, patrulleros=patrulleros)

@app.route('/agregar_patrullero/<int:jefe_id>', methods=['GET', 'POST'])
@login_required
def agregar_patrullero(jefe_id):
    # Verificar permisos
    if not current_user.is_admin and (not current_user.jefe or current_user.jefe.id != jefe_id):
        flash('No tienes permiso para agregar patrulleros a esta patrulla', 'danger')
        return redirect(url_for('dashboard'))
    
    jefe = JefePatrulla.query.get_or_404(jefe_id)
    
    # Verificar que no se exceda el límite de 21 patrulleros
    if len(jefe.patrulleros) >= 21:
        flash('No se pueden agregar más de 21 patrulleros', 'danger')
        return redirect(url_for('ver_patrulla', jefe_id=jefe_id))
    
    if request.method == 'POST':
        try:
            cedula = request.form['cedula'].strip()
            nombres = request.form['nombres'].strip()
            
            # Verificar si la cédula es válida
            if not cedula_valida(cedula):
                flash(f'La cédula {cedula} ya está registrada en el sistema', 'danger')
                return render_template('form_patrullero.html', jefe=jefe)
            
            # Encontrar el próximo número disponible
            numeros = [p.numero for p in jefe.patrulleros]
            nuevo_numero = max(numeros) + 1 if numeros else 1
            
            # Crear nuevo patrullero
            patrullero = Patrullero(
                jefe_id=jefe.id,
                numero=nuevo_numero,
                cedula=cedula,
                nombres_apellidos=nombres,
                telefono=request.form.get('telefono', ''),
                direccion=request.form.get('direccion', ''),
                centro_votacion=request.form.get('centro_votacion', '')
            )
            db.session.add(patrullero)
            db.session.commit()
            
            flash('Patrullero agregado exitosamente', 'success')
            return redirect(url_for('ver_patrulla', jefe_id=jefe_id))
        except Exception as e:
            db.session.rollback()
            flash(f'Error al agregar patrullero: {str(e)}', 'danger')
    
    return render_template('form_patrullero.html', jefe=jefe)

@app.route('/editar_patrullero/<int:patrullero_id>', methods=['GET', 'POST'])
@login_required
def editar_patrullero(patrullero_id):
    patrullero = Patrullero.query.get_or_404(patrullero_id)
    jefe_id = patrullero.jefe_id
    
    # Verificar permisos
    if not current_user.is_admin and (not current_user.jefe or current_user.jefe.id != jefe_id):
        flash('No tienes permiso para editar este patrullero', 'danger')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        try:
            cedula = request.form['cedula'].strip()
            nombres = request.form['nombres'].strip()
            
            # Verificar si la cédula es válida
            if not cedula_valida(cedula, patrullero.id):
                flash(f'La cédula {cedula} ya está registrada en el sistema', 'danger')
                return render_template('form_patrullero.html', jefe=patrullero.jefe, patrullero=patrullero)
            
            # Actualizar datos
            patrullero.cedula = cedula
            patrullero.nombres_apellidos = nombres
            patrullero.telefono = request.form.get('telefono', '')
            patrullero.direccion = request.form.get('direccion', '')
            patrullero.centro_votacion = request.form.get('centro_votacion', '')
            
            db.session.commit()
            flash('Patrullero actualizado exitosamente', 'success')
            return redirect(url_for('ver_patrulla', jefe_id=jefe_id))
        except Exception as e:
            db.session.rollback()
            flash(f'Error al actualizar patrullero: {str(e)}', 'danger')
    
    return render_template('form_patrullero.html', jefe=patrullero.jefe, patrullero=patrullero)

@app.route('/eliminar_patrullero/<int:patrullero_id>', methods=['POST'])
@login_required
def eliminar_patrullero(patrullero_id):
    patrullero = Patrullero.query.get_or_404(patrullero_id)
    jefe_id = patrullero.jefe_id
    
    # Verificar permisos
    if not current_user.is_admin and (not current_user.jefe or current_user.jefe.id != jefe_id):
        flash('No tienes permiso para eliminar este patrullero', 'danger')
        return redirect(url_for('dashboard'))
    
    try:
        db.session.delete(patrullero)
        db.session.commit()
        flash('Patrullero eliminado exitosamente', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error al eliminar patrullero: {str(e)}', 'danger')
    
    return redirect(url_for('ver_patrulla', jefe_id=jefe_id))

@app.route('/exportar_pdf/<int:jefe_id>')
@login_required
def exportar_pdf(jefe_id):
    jefe = JefePatrulla.query.get_or_404(jefe_id)
    patrulleros = Patrullero.query.filter_by(jefe_id=jefe_id).order_by(Patrullero.numero).all()

    if not jefe:
        flash(f'Jefe de Patrulla con ID {jefe_id} no encontrado.', 'danger')
        return redirect(url_for('dashboard'))

    # Renderizar plantilla HTML
    # Asegúrate de que 'imprimir_patrulla.html' exista en tu carpeta 'templates'
    rendered = render_template('imprimir_patrulla.html', jefe=jefe, patrulleros=patrulleros)

    # Crear el archivo PDF en memoria
    pdf_buffer = BytesIO()
    try:
        # Pasa el HTML renderizado a pisa.CreatePDF
        # dest: el archivo de destino (en este caso, nuestro buffer en memoria)
        # link_callback: para manejar rutas de recursos (imágenes, CSS) si es necesario
        pisa_status = pisa.CreatePDF(
            rendered,                # el contenido HTML a convertir
            dest=pdf_buffer)         # el buffer de bytes para guardar el PDF

        # Si hubo errores en la generación del PDF
        if pisa_status.err:
            flash(f'Error al generar el PDF: {pisa_status.err}', 'danger')
            return redirect(url_for('ver_patrulla', jefe_id=jefe_id))

    except Exception as e:
        flash(f'Error inesperado al generar el PDF: {str(e)}', 'danger')
        return redirect(url_for('ver_patrulla', jefe_id=jefe_id))

    # Mover el puntero al inicio del buffer para leer su contenido
    pdf_buffer.seek(0)
    pdf = pdf_buffer.getvalue()

    # Crear respuesta con el PDF
    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    filename = f"patrulla_{jefe.responsable}_{jefe_id}.pdf".replace(" ", "_")
    response.headers['Content-Disposition'] = f'inline; filename={filename}'
    return response

# def exportar_pdf(jefe_id):
#     if not current_user.is_admin and (not current_user.jefe or current_user.jefe.id != jefe_id):
#         flash('No tienes permiso para exportar esta patrulla', 'danger')
#         return redirect(url_for('dashboard'))
    
#     jefe = JefePatrulla.query.get_or_404(jefe_id)
#     patrulleros = Patrullero.query.filter_by(jefe_id=jefe_id).order_by(Patrullero.numero).all()
    
#     # Renderizar plantilla HTML
#     rendered = render_template('imprimir_patrulla.html', jefe=jefe, patrulleros=patrulleros)
    
#     try:
#         # Crear PDF con pdfkit
#         pdf = pdfkit.from_string(rendered, False, configuration=app.config['PDFKIT_CONFIG'])
#     except Exception as e:
#         flash(f'Error al generar el PDF: {str(e)}', 'danger')
#         return redirect(url_for('ver_patrulla', jefe_id=jefe_id))
    
#     # Crear respuesta con el PDF
#     response = make_response(pdf)
#     response.headers['Content-Type'] = 'application/pdf'
#     filename = f"patrulla_{jefe.responsable}_{jefe_id}.pdf".replace(" ", "_")
#     response.headers['Content-Disposition'] = f'inline; filename={filename}'
#     return response

@app.route('/imprimir_patrulla/<int:jefe_id>')
@login_required
def imprimir_patrulla(jefe_id):
    if not current_user.is_admin and (not current_user.jefe or current_user.jefe.id != jefe_id):
        flash('No tienes permiso para imprimir esta patrulla', 'danger')
        return redirect(url_for('dashboard'))
    
    return redirect(url_for('exportar_pdf', jefe_id=jefe_id))

@app.route('/admin/crear_usuario', methods=['GET', 'POST'])
@login_required
def crear_usuario():
    if not current_user.is_admin:
        flash('Acceso no autorizado', 'danger')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        cedula = request.form['cedula']
        nombre = request.form['nombre']
        es_admin = 'es_admin' in request.form
        
        # Verificar si la cédula ya existe
        if User.query.filter_by(cedula=cedula).first():
            flash('El usuario con esta cédula ya existe', 'danger')
            return redirect(url_for('crear_usuario'))
        
        hashed_pw = generate_password_hash('123456', method='pbkdf2:sha256')
        nuevo_usuario = User(
            cedula=cedula,
            password=hashed_pw,
            nombre=nombre,
            is_admin=es_admin,
            first_login=True
        )
        db.session.add(nuevo_usuario)
        db.session.commit()
        
        flash(f'Usuario {nombre} creado exitosamente. Contraseña inicial: 123456', 'success')
        return redirect(url_for('crear_usuario'))
    
    return render_template('crear_usuario.html')

@app.route('/admin/exportar_excel')
@login_required
def exportar_excel():
    if not current_user.is_admin:
        flash('Acceso no autorizado', 'danger')
        return redirect(url_for('dashboard'))
    
    try:
        # Obtener todos los jefes de patrulla con sus patrulleros
        jefes = JefePatrulla.query.all()
        
        # Crear un DataFrame para los jefes
        jefes_data = []
        for jefe in jefes:
            jefe_data = {
                'ID Jefe': jefe.id,
                'Responsable': jefe.responsable,
                'Cédula Jefe': jefe.cedula,
                'Centro de Votación': jefe.centro_votacion,
                'Teléfono': jefe.telefono,
                'Sector': jefe.sector,
                'EPM': 'X' if jefe.epm else '0',
                'UBCH': 'X' if jefe.ubch else '0',
                'Comunidad': 'X' if jefe.comunidad else '0',
                'Calle': 'X' if jefe.calle else '0',
                'Militante': 'X' if jefe.militante else '0',
                'CLAP': 'X' if jefe.clap else '0',
                'MGM': 'X' if jefe.mgm else '0',
                'Mujeres': 'X' if jefe.mujeres else '0',
                'SV': 'X' if jefe.sv else '0',
                'Milicia': 'X' if jefe.milicia else '0',
                'Consejo Comunal': 'X' if jefe.consejo_comunal else '0',
                'Comuna': 'X' if jefe.comuna else '0',
                'CIR Comunal': 'X' if jefe.cir_comunal else '0',
                'GPPSB': 'X' if jefe.gppsb else '0',
                'Movimientos Sociales': 'X' if jefe.mov_sociales else '0',
                'Salud': 'X' if jefe.salud else '0',
                'Educación': 'X' if jefe.educacion else '0',
                'CORPOELEC': 'X' if jefe.corpoelec else '0',
                'H2O': 'X' if jefe.h2o else '0',
                'SAREN': 'X' if jefe.saren else '0',
                'Policía': 'X' if jefe.policia else '0',
                'FFM': 'X' if jefe.ffm else '0',
                'Linder': 'X' if jefe.linder else '0',
                'Otro': jefe.otro,
                'Usuario Asociado': jefe.user.nombre if jefe.user else 'Sin usuario'
            }
            jefes_data.append(jefe_data)
        
        jefes_df = pd.DataFrame(jefes_data)
        
        # Crear un DataFrame para los patrulleros
        patrulleros_data = []
        for jefe in jefes:
            for patrullero in jefe.patrulleros:
                patrulleros_data.append({
                    'ID Patrullero': patrullero.id,
                    'ID Jefe': patrullero.jefe_id,
                    'Responsable Jefe': jefe.responsable,
                    'Número': patrullero.numero,
                    'Cédula': patrullero.cedula,
                    'Nombres y Apellidos': patrullero.nombres_apellidos,
                    'Teléfono': patrullero.telefono,
                    'Dirección': patrullero.direccion,
                    'Centro de Votación': patrullero.centro_votacion
                })
        
        patrulleros_df = pd.DataFrame(patrulleros_data)
        
        # Crear un DataFrame para los usuarios
        usuarios = User.query.all()
        usuarios_data = [{
            'ID Usuario': u.id,
            'Cédula': u.cedula,
            'Nombre': u.nombre,
            'Es Administrador': 'Sí' if u.is_admin else 'No',
            'ID Jefe Asociado': u.jefe_id,
            'Responsable Asociado': u.jefe.responsable if u.jefe else 'Sin patrulla'
        } for u in usuarios]
        
        usuarios_df = pd.DataFrame(usuarios_data)
        
        # Crear un archivo Excel en memoria
        output = BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            jefes_df.to_excel(writer, sheet_name='Jefes de Patrulla', index=False)
            patrulleros_df.to_excel(writer, sheet_name='Patrulleros', index=False)
            usuarios_df.to_excel(writer, sheet_name='Usuarios', index=False)
        
        output.seek(0)
        
        # Crear nombre de archivo con fecha
        fecha = datetime.datetime.now().strftime("%Y%m%d_%H%M")
        filename = f"reporte_patrullas_{fecha}.xlsx"
        
        # Enviar el archivo como respuesta
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=filename
        )
    
    except Exception as e:
        flash(f'Error al generar el reporte Excel: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # Crear usuario admin si no existe
        if not User.query.filter_by(cedula='admin').first():
            hashed_pw = generate_password_hash('123456', method='pbkdf2:sha256')
            admin = User(
                cedula='admin', 
                password=hashed_pw, 
                is_admin=True, 
                nombre='Administrador',
                first_login=True
            )
            db.session.add(admin)
            db.session.commit()
            print('Usuario admin creado: cedula=admin, password=123456')
    
    app.run(debug=True)
