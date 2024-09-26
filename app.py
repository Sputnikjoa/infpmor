from flask import Flask, request, render_template, redirect, url_for, send_from_directory, jsonify, session, flash, send_file
import sqlite3
from flask_mail import Mail, Message
from datetime import datetime
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from fpdf import FPDF
from PIL import Image
import qrcode
import pandas as pd
import os
import random
import string
import time

app = Flask(__name__)
app.secret_key = 'super_secret_key'


# Configuración de Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'joaquin.ros.sed15@gmail.com'
app.config['MAIL_PASSWORD'] = 'zydf jaxb ijty iufc'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)





# Función para generar un token aleatorio
def generate_token(length=6):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

# Guardar el token y el tiempo de creación
def save_token(token):
    session['token'] = token
    session['token_time'] = time.time()

# Verificar si el token es válido y no ha expirado
def verify_token(token, expiration=300):  # 5 minutos de expiración
    saved_token = session.get('token')
    token_time = session.get('token_time')

    if saved_token and token_time:
        if saved_token == token and (time.time() - token_time) < expiration:
            return True
    return False


# Configuración de la contraseña y dirección de correo
AUTH_PASSWORD = "joakingamer1"
AUTHORIZED_EMAIL = "joaquin.rs.sd@gmail.com"

# Contraseña requerida para acceder a crud_cursos_usuario
ACCESS_PASSWORD = "DANA"  # Cambia esto a la contraseña deseada



@app.route('/test_email')
def test_email():
    try:
        msg = Message('Test Email', sender=app.config['MAIL_USERNAME'], recipients=[AUTHORIZED_EMAIL])
        msg.body = "Este es un correo de prueba."
        mail.send(msg)
        return "Correo enviado exitosamente"
    except Exception as e:
        return f"Error al enviar el correo: {str(e)}"



QR_TEMP_PATH = 'temp_qr.png'
PDF_TEMP_PATH = 'temp_pdf.pdf'
BACKGROUND_IMAGE_PATH = 'background.png'

def generar_qr(matricula):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(matricula)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    img.save(QR_TEMP_PATH)

def crear_pdf(nombre, apellido_paterno, apellido_materno, matricula):
    pdf = FPDF(format='letter')  # Tamaño carta
    pdf.add_page()

    # Añadir la imagen de fondo
    if os.path.exists(BACKGROUND_IMAGE_PATH):
        pdf.image(BACKGROUND_IMAGE_PATH, x=0, y=0, w=215.9, h=279.4)  # Tamaño carta en mm: 215.9x279.4
    else:
        print(f"Imagen de fondo no encontrada en {BACKGROUND_IMAGE_PATH}")

    # Añadir el texto (Nombre completo)
    pdf.set_font("Arial", 'B', 16)
    pdf.set_text_color(0, 0, 0)
    nombre_completo = f"{nombre} {apellido_paterno} {apellido_materno}"
    pdf.cell(0, 52, 'Certificado MATRICULA-INFP', ln=True, align='C')
    pdf.cell(0, 15, txt=nombre_completo, ln=True, align='L')

    # Añadir el texto (Matrícula)
    pdf.set_font("Arial", size=14)
    pdf.cell(0, 10, txt=f"Matrícula: {matricula}", ln=True, align='L')

    # Añadir el QR Code
    if os.path.exists(QR_TEMP_PATH):
        # Calcular posición para centrar el QR en la parte inferior
        qr_size = 130  # Tamaño del QR en mm
        x_position = (215.9 - qr_size) / 2
        y_position = 100  # Ajusta según tu diseño
        pdf.image(QR_TEMP_PATH, x=x_position, y=y_position, w=qr_size, h=qr_size)
    else:
        print(f"QR no encontrado en {QR_TEMP_PATH}")



    # Guardar el PDF temporalmente
    pdf.output(PDF_TEMP_PATH)


UPLOAD_FOLDER = 'uploads'
DOWNLOAD_FOLDER = 'downloads'
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), UPLOAD_FOLDER)
app.config['DOWNLOAD_FOLDER'] = os.path.join(os.getcwd(), DOWNLOAD_FOLDER)

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

if not os.path.exists(app.config['DOWNLOAD_FOLDER']):
    os.makedirs(app.config['DOWNLOAD_FOLDER'])

def init_db():
    conn = sqlite3.connect('matriculas.db')
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS USUARIOS (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre TEXT NOT NULL,
            apellido_paterno TEXT NOT NULL,
            apellido_materno TEXT NOT NULL,
            correo TEXT NOT NULL UNIQUE,
            curp TEXT NOT NULL,
            matricula TEXT NOT NULL UNIQUE,
            fecha_creacion TEXT NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS CURSOS_USUARIO (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre_curso TEXT NOT NULL,
            matricula_usuario TEXT NOT NULL,
            status TEXT NOT NULL,
            folio TEXT NOT NULL,
            fecha_inicio TEXT NOT NULL,
            fecha_fin TEXT NOT NULL,
            link TEXT,
            fecha_creacion TEXT NOT NULL,
            FOREIGN KEY(matricula_usuario) REFERENCES USUARIOS(matricula)
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_matricula ON USUARIOS(matricula);')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_correo ON USUARIOS(correo);')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_curp ON USUARIOS(curp);')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_matriculax ON CURSOS_USUARIO(matricula_usuario);')

    conn.commit()
    conn.close()

init_db()

def generar_matricula(nombre, apellido_paterno, apellido_materno, serie):
    letras_nombre = nombre[:3].upper()
    letras_apellido_paterno = apellido_paterno[:2].upper()
    letras_apellido_materno = apellido_materno[:2].upper()

    prefijo = chr(65 + (serie - 1) // 9999)
    numero = (serie - 1) % 9999 + 1

    matricula = f"INFP-{letras_nombre}{letras_apellido_paterno}{letras_apellido_materno}-{prefijo}{numero:04d}"
    return matricula

def enviar_correo(destinatario, asunto, cuerpo, nombre, apellido_paterno, apellido_materno, matricula):
    email_user = 'joaquin.ros.sed15@gmail.com'
    email_password = 'zydf jaxb ijty iufc'

    smtp_server = 'smtp.gmail.com'
    smtp_port = 465

    # Crear el mensaje
    mensaje = MIMEMultipart()
    mensaje['From'] = email_user
    mensaje['To'] = destinatario
    mensaje['Subject'] = asunto

    # Adjuntar el cuerpo del mensaje
    mensaje.attach(MIMEText(cuerpo, 'plain', 'utf-8'))

    # Generar el QR y el PDF
    generar_qr(matricula)
    crear_pdf(nombre, apellido_paterno, apellido_materno, matricula)

    # Adjuntar el PDF al correo
    if os.path.exists(PDF_TEMP_PATH):
        with open(PDF_TEMP_PATH, 'rb') as attachment:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(attachment.read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', f'attachment; filename=Certificado_{matricula}.pdf')
            mensaje.attach(part)
    else:
        print(f"PDF no encontrado en {PDF_TEMP_PATH}")

    # Conectar al servidor y enviar el correo
    try:
        server = smtplib.SMTP_SSL(smtp_server, smtp_port)
        server.login(email_user, email_password)
        texto = mensaje.as_string()
        server.sendmail(email_user, destinatario, texto.encode('utf-8'))  # Codificar el mensaje en UTF-8
        server.quit()
        print("Correo enviado con éxito")
    except Exception as e:
        print(f"Error al enviar el correo: {e}")
    finally:
        # Eliminar archivos temporales después de enviar el correo
        if os.path.exists(QR_TEMP_PATH):
            os.remove(QR_TEMP_PATH)
        if os.path.exists(PDF_TEMP_PATH):
            os.remove(PDF_TEMP_PATH)


@app.route('/crear_usuario', methods=['POST'])
def crear_usuario():
    received_json = request.get_json()
    data = received_json.get('data', {})

    nombre = data.get('nombre').strip()
    apellido_paterno = data.get('apellido_paterno').strip()
    apellido_materno = data.get('apellido_materno').strip()
    correo = data.get('correo').strip()
    curp = data.get('curp').strip()
    fecha_creacion = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    conn = sqlite3.connect('matriculas.db')
    cursor = conn.cursor()

    # Verificar si la CURP ya está registrada, excepto si es "NO"
    if curp != "NO":
        cursor.execute('SELECT nombre, apellido_paterno, apellido_materno, correo, matricula FROM USUARIOS WHERE curp = ?', (curp,))
        resultado = cursor.fetchone()

        if resultado:
            nombre_db, apellido_paterno_db, apellido_materno_db, correo_db, matricula_existente = resultado
            asunto = "Usuario ya registrado"
            cuerpo = f"Hola,\n\nEl CURP {curp} ya está registrado con la matrícula {matricula_existente}.\n\nSaludos,\nEquipo de Registro"
            enviar_correo(correo_db, asunto, cuerpo, nombre_db, apellido_paterno_db, apellido_materno_db, matricula_existente)
            return jsonify({"message": "CURP ya registrado", "matricula": matricula_existente}), 200

    # Verificar si el correo ya está registrado
    cursor.execute('SELECT nombre, apellido_paterno, apellido_materno, correo, matricula FROM USUARIOS WHERE correo = ?', (correo,))
    resultado = cursor.fetchone()

    if resultado:
        nombre_db, apellido_paterno_db, apellido_materno_db, correo_db, matricula_existente = resultado
        asunto = "Usuario ya registrado"
        cuerpo = f"Hola,\n\nEl correo {correo} ya está registrado con la matrícula {matricula_existente}.\n\nSaludos,\nEquipo de Registro"
        enviar_correo(correo_db, asunto, cuerpo, nombre_db, apellido_paterno_db, apellido_materno_db, matricula_existente)
        return jsonify({"message": "Correo ya registrado", "matricula": matricula_existente}), 200

    # Obtener el siguiente número de serie
    cursor.execute('SELECT COUNT(*) FROM USUARIOS')
    serie = cursor.fetchone()[0] + 1

    # Generar la matrícula
    matricula = generar_matricula(nombre, apellido_paterno, apellido_materno, serie)

    try:
        # Insertar el nuevo usuario en la base de datos
        cursor.execute('''
            INSERT INTO USUARIOS (nombre, apellido_paterno, apellido_materno, correo, matricula, curp, fecha_creacion)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (nombre, apellido_paterno, apellido_materno, correo, matricula, curp, fecha_creacion))
        conn.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "Correo o matrícula ya existe"}), 400

    conn.close()

    # Preparar y enviar el correo con el PDF adjunto
    asunto = "Registro Exitoso | MATRICULA INFP"
    cuerpo = f"Hola,\n\nTu registro al INFP ha sido exitoso. Tu matrícula es {matricula}.\n\nSaludos,\nEquipo de Registro"
    try:
        enviar_correo(correo, asunto, cuerpo, nombre, apellido_paterno, apellido_materno, matricula)
        print("Correo enviado exitosamente.")
    except Exception as e:
        print(f"Error al enviar el correo: {e}")

    print(f'Usuario creado para {nombre} {apellido_paterno} {apellido_materno} y matrícula {matricula}')
    return jsonify({"message": "Usuario creado exitosamente", "matricula": matricula}), 201


@app.route('/consultas', methods=['GET', 'POST'])
def consultas():
    usuario = None
    cursos_usuario = []
    error = None  # Variable para almacenar cualquier error

    if request.method == 'POST':
        busqueda = request.form.get('busqueda')

        if not busqueda:
            error = "Debe ingresar un correo, matrícula o CURP para buscar."
        else:
            conn = sqlite3.connect('matriculas.db')
            cursor = conn.cursor()

            try:
                cursor.execute('''
                    SELECT nombre, apellido_paterno, apellido_materno, correo, matricula, curp FROM USUARIOS
                    WHERE correo = ? OR matricula = ? OR curp = ?
                ''', (busqueda, busqueda, busqueda))
                usuario = cursor.fetchone()

                if usuario:
                    nombre, apellido_paterno, apellido_materno, correo, matricula, curp = usuario

                    cursor.execute('''
                        SELECT * FROM CURSOS_USUARIO
                        WHERE matricula_usuario = ?
                    ''', (matricula,))
                    cursos_usuario = cursor.fetchall()
                else:
                    error = "No se encontró ningún usuario con los datos proporcionados."
            except Exception as e:
                error = f"Error al realizar la consulta: {str(e)}"
            finally:
                conn.close()

    return render_template('consultas.html', usuario=usuario, cursos_usuario=cursos_usuario, error=error)




@app.route('/registrar_curso', methods=['GET', 'POST'])
def registrar_curso():
    if request.method == 'POST':
        if 'file' not in request.files:
            return "No se ha subido ningún archivo", 400

        file = request.files['file']

        if file.filename == '':
            return "No se ha seleccionado ningún archivo", 400

        if file and file.filename.endswith('.xlsx'):
            try:
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
                file.save(filepath)

                df = pd.read_excel(filepath)

                df['fecha_inicio'] = pd.to_datetime(df['fecha_inicio']).dt.strftime('%Y-%m-%d')
                df['fecha_fin'] = pd.to_datetime(df['fecha_fin']).dt.strftime('%Y-%m-%d')
                df['fecha_creacion'] = pd.to_datetime(df['fecha_creacion']).dt.strftime('%Y-%m-%d')

                required_columns = ['nombre_curso', 'matricula_usuario', 'status', 'folio', 'fecha_inicio', 'fecha_fin', 'fecha_creacion']
                if not all(column in df.columns for column in required_columns):
                    return "El archivo Excel no contiene las columnas requeridas", 400

                conn = sqlite3.connect('matriculas.db')
                cursor = conn.cursor()

                for _, row in df.iterrows():
                    cursor.execute('''
                        INSERT INTO CURSOS_USUARIO (nombre_curso, matricula_usuario, status, folio, fecha_inicio, fecha_fin, link, fecha_creacion)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        row['nombre_curso'],
                        row['matricula_usuario'],
                        row['status'],
                        row['folio'],
                        row['fecha_inicio'],
                        row['fecha_fin'],
                        row.get('link', ''),
                        row['fecha_creacion']
                    ))

                conn.commit()
                conn.close()

                return redirect(url_for('registrar_curso'))
            except Exception as e:
                return f"Error al procesar el archivo: {str(e)}", 500

    # Paginación
    page = request.args.get('page', 1, type=int)
    per_page = 10  # Número de registros por página
    offset = (page - 1) * per_page

    try:
        conn = sqlite3.connect('matriculas.db')
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM CURSOS_USUARIO')
        total_records = cursor.fetchone()[0]

        cursor.execute('SELECT * FROM CURSOS_USUARIO LIMIT ? OFFSET ?', (per_page, offset))
        cursos_usuario = cursor.fetchall()
        conn.close()

        total_pages = (total_records + per_page - 1) // per_page  # Redondeo hacia arriba

    except Exception as e:
        return f"Error al cargar los datos: {str(e)}", 500

    return render_template('registrar_curso.html', cursos_usuario=cursos_usuario, page=page, total_pages=total_pages)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/registrador', methods=['GET', 'POST'])
def registrador():
    matricula = None
    error = None

    if request.method == 'POST':
        nombre = request.form.get('nombre', '').strip()
        apellido_paterno = request.form.get('apellido_paterno', '').strip()
        apellido_materno = request.form.get('apellido_materno', '').strip()
        correo = request.form.get('correo', '').strip()
        curp = request.form.get('curp', '').strip()
        fecha_creacion = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        if not nombre or not apellido_paterno or not apellido_materno or not correo or not curp:
            error = "Todos los campos son obligatorios."
        else:
            conn = sqlite3.connect('matriculas.db')
            cursor = conn.cursor()

            try:
                # Verificar si la CURP ya está registrada
                cursor.execute('SELECT matricula FROM USUARIOS WHERE curp = ?', (curp,))
                resultado = cursor.fetchone()

                if resultado:
                    matricula_existente = resultado[0]
                    error = f"El CURP {curp} ya está registrado con la matrícula {matricula_existente}."
                    return render_template('registrador.html', error=error)

                # Verificar si el correo ya está registrado
                cursor.execute('SELECT matricula FROM USUARIOS WHERE correo = ?', (correo,))
                resultado = cursor.fetchone()

                if resultado:
                    matricula_existente = resultado[0]
                    error = f"El correo {correo} ya está registrado con la matrícula {matricula_existente}."
                    return render_template('registrador.html', error=error)

                # Obtener el siguiente número de serie
                cursor.execute('SELECT COUNT(*) FROM USUARIOS')
                serie = cursor.fetchone()[0] + 1

                # Generar la matrícula
                matricula = generar_matricula(nombre, apellido_paterno, apellido_materno, serie)

                # Insertar en la base de datos
                cursor.execute('''
                    INSERT INTO USUARIOS (nombre, apellido_paterno, apellido_materno, correo, matricula, curp, fecha_creacion)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (nombre, apellido_paterno, apellido_materno, correo, matricula, curp, fecha_creacion))
                conn.commit()

                # Enviar el correo con el PDF adjunto
                asunto = "Registro Exitoso | MATRICULA INFP"
                cuerpo = f"Hola,\n\nTu registro al INFP ha sido exitoso. Tu matrícula es {matricula}.\n\nSaludos,\nEquipo de Registro"
                enviar_correo(correo, asunto, cuerpo, nombre, apellido_paterno, apellido_materno, matricula)

            except sqlite3.IntegrityError:
                error = "Hubo un error al registrar el usuario. Inténtalo de nuevo."
            except Exception as e:
                error = f"Error inesperado: {str(e)}"
            finally:
                conn.close()

    return render_template('registrador.html', matricula=matricula, error=error)


@app.route('/login_crud_cursos', methods=['GET', 'POST'])
def login_crud_cursos():
    error = None
    if request.method == 'POST':
        password = request.form.get('password', '').strip()
        if password == ACCESS_PASSWORD:
            session['authenticated_crud_cursos'] = True
            return redirect(url_for('crud_cursos_usuario'))
        else:
            error = "Contraseña incorrecta. Inténtalo de nuevo."

    return render_template('login_crud_cursos.html', error=error)



@app.route('/crud_cursos_usuario', methods=['GET', 'POST'])
def crud_cursos_usuario():
    # Verificar si el usuario está autenticado
    if not session.get('authenticated_crud_cursos'):
        return redirect(url_for('login_crud_cursos'))
                        
    curso = None
    mensaje = None
    error = None

    if request.method == 'POST':
        # Si el formulario es para buscar por ID
        if 'buscar' in request.form:
            curso_id = request.form.get('curso_id').strip()

            if not curso_id:
                error = "Debe ingresar un ID para buscar."
            else:
                conn = sqlite3.connect('matriculas.db')
                cursor = conn.cursor()

                try:
                    cursor.execute('SELECT * FROM CURSOS_USUARIO WHERE id = ?', (curso_id,))
                    curso = cursor.fetchone()

                    if not curso:
                        error = f"No se encontró ningún curso con el ID {curso_id}."
                except Exception as e:
                    error = f"Error al realizar la búsqueda: {str(e)}"
                finally:
                    conn.close()

        # Si el formulario es para actualizar el curso
        elif 'actualizar' in request.form:
            curso_id = request.form.get('curso_id').strip()
            nombre_curso = request.form.get('nombre_curso').strip()
            matricula_usuario = request.form.get('matricula_usuario').strip()
            status = request.form.get('status').strip()
            folio = request.form.get('folio').strip()
            fecha_inicio = request.form.get('fecha_inicio').strip()
            fecha_fin = request.form.get('fecha_fin').strip()
            link = request.form.get('link').strip()

            if not curso_id or not nombre_curso or not matricula_usuario or not status or not folio or not fecha_inicio or not fecha_fin:
                error = "Todos los campos son obligatorios."
            else:
                conn = sqlite3.connect('matriculas.db')
                cursor = conn.cursor()

                try:
                    cursor.execute('''
                        UPDATE CURSOS_USUARIO
                        SET nombre_curso = ?, matricula_usuario = ?, status = ?, folio = ?, fecha_inicio = ?, fecha_fin = ?, link = ?
                        WHERE id = ?
                    ''', (nombre_curso, matricula_usuario, status, folio, fecha_inicio, fecha_fin, link, curso_id))
                    conn.commit()

                    mensaje = f"El curso con ID {curso_id} ha sido actualizado exitosamente."
                except Exception as e:
                    error = f"Error al actualizar el curso: {str(e)}"
                finally:
                    conn.close()

    return render_template('crud_cursos_usuario.html', curso=curso, mensaje=mensaje, error=error)


@app.route('/crud_usuarios', methods=['GET', 'POST'])
def crud_usuarios():
    usuario = None
    mensaje = None
    error = None

    if request.method == 'POST':
        # Si el formulario es para buscar por matrícula, correo o CURP
        if 'buscar' in request.form:
            busqueda = request.form.get('busqueda').strip()

            if not busqueda:
                error = "Debe ingresar una matrícula, correo o CURP para buscar."
            else:
                conn = sqlite3.connect('matriculas.db')
                cursor = conn.cursor()

                try:
                    cursor.execute('''
                        SELECT * FROM USUARIOS WHERE matricula = ? OR correo = ? OR curp = ?
                    ''', (busqueda, busqueda, busqueda))
                    usuario = cursor.fetchone()

                    if not usuario:
                        error = f"No se encontró ningún usuario con la matrícula, correo o CURP {busqueda}."
                except Exception as e:
                    error = f"Error al realizar la búsqueda: {str(e)}"
                finally:
                    conn.close()

        # Si el formulario es para actualizar el usuario
        elif 'actualizar' in request.form:
            usuario_id = request.form.get('usuario_id').strip()
            nombre = request.form.get('nombre')
            apellido_paterno = request.form.get('apellido_paterno').strip()
            apellido_materno = request.form.get('apellido_materno').strip()
            correo = request.form.get('correo').strip()
            curp = request.form.get('curp').strip()

            if not usuario_id or not nombre or not apellido_paterno or not apellido_materno or not correo or not curp:
                error = "Todos los campos son obligatorios."
            else:
                conn = sqlite3.connect('matriculas.db')
                cursor = conn.cursor()

                try:
                    cursor.execute('''
                        UPDATE USUARIOS
                        SET nombre = ?, apellido_paterno = ?, apellido_materno = ?, correo = ?, curp = ?
                        WHERE id = ?
                    ''', (nombre, apellido_paterno, apellido_materno, correo, curp, usuario_id))
                    conn.commit()

                    mensaje = f"El usuario con ID {usuario_id} ha sido actualizado exitosamente."
                except Exception as e:
                    error = f"Error al actualizar el usuario: {str(e)}"
                finally:
                    conn.close()

    return render_template('crud_usuarios.html', usuario=usuario, mensaje=mensaje, error=error)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        password = request.form.get('password').strip()

        if password == AUTH_PASSWORD:
            print("Contraseña correcta, generando token...")  # Depuración

            try:
                # Generar un token y enviarlo por correo electrónico
                token = generate_token()
                save_token(token)

                print("Token generado: ", token)  # Depuración

                # Enviar el token al correo
                msg = Message('Token de acceso', sender=app.config['MAIL_USERNAME'], recipients=[AUTHORIZED_EMAIL])
                msg.body = f"Tu token de acceso es: {token}. Este token expira en 5 minutos."
                mail.send(msg)

                print("Correo enviado correctamente.")  # Depuración

                flash('Se ha enviado un token a tu correo electrónico.')
                return redirect(url_for('verify_token_page'))  # Redirección a la verificación del token
            except Exception as e:
                print(f"Error al enviar el correo: {str(e)}")  # Depuración
                flash('Error al enviar el correo.')
                return redirect(url_for('login'))
        else:
            flash('Contraseña incorrecta.')

    return render_template('login.html')




@app.route('/verify_token', methods=['GET', 'POST'])
def verify_token_page():
    if request.method == 'POST':
        token = request.form.get('token').strip()

        if verify_token(token):
            session['authenticated'] = True
            return redirect(url_for('ejecutor_sql'))  # Redirección al ejecutor SQL
        else:
            flash('Token inválido o expirado.')

    return render_template('verify_token.html')



@app.route('/ejecutor_sql', methods=['GET', 'POST'])
def ejecutor_sql():
    if not session.get('authenticated'):
        return redirect(url_for('login'))

    resultado = None
    error = None

    if request.method == 'POST':
        consulta_sql = request.form.get('consulta_sql').strip()
        print(f"Consulta SQL recibida: {consulta_sql}")  # Verificar que se recibe la consulta

        if not consulta_sql:
            error = "Debe ingresar una consulta SQL."
        else:
            conn = sqlite3.connect('matriculas.db')
            cursor = conn.cursor()

            try:
                print("Ejecutando consulta SQL...")  # Depuración
                cursor.execute(consulta_sql)

                if consulta_sql.strip().lower().startswith("select"):
                    resultado = cursor.fetchall()
                    if not resultado:
                        resultado = "La consulta no devolvió ningún resultado."
                    else:
                        print(f"Resultados: {resultado}")  # Depuración
                else:
                    conn.commit()
                    resultado = f"La consulta '{consulta_sql}' se ejecutó correctamente."
            except sqlite3.Error as e:
                error = f"Error al ejecutar la consulta: {str(e)}"
                print(f"Error al ejecutar la consulta: {str(e)}")  # Depuración
            except Exception as e:
                error = f"Error inesperado: {str(e)}"
                print(f"Error inesperado: {str(e)}")  # Depuración
            finally:
                conn.close()

    return render_template('ejecutor_sql.html', resultado=resultado, error=error)



@app.route('/procesar_matriculas', methods=['GET', 'POST'])
def procesar_matriculas():
    if request.method == 'POST':
        try:
            if 'file' not in request.files:
                return "No se ha subido ningún archivo", 400

            file = request.files['file']

            if file.filename == '':
                return "No se ha seleccionado ningún archivo", 400

            if file and file.filename.endswith('.xlsx'):
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
                file.save(filepath)

                # Leer el archivo Excel
                df = pd.read_excel(filepath)

                # Verificar si existe la columna de matrículas con diferentes posibles nombres
                columnas_validas = ['matricula', 'MATRICULA', 'Matricula', 'Matrícula', 'MATRÍCULA']
                if not any(col in df.columns for col in columnas_validas):
                    return "El archivo Excel no contiene una columna válida para 'matricula'", 400

                # Identificar la columna correcta para usar
                columna_matricula = next(col for col in columnas_validas if col in df.columns)

                # Conectarse a la base de datos y obtener los datos
                conn = sqlite3.connect('matriculas.db')
                cursor = conn.cursor()

                # Crear columnas para el nombre, apellido paterno y apellido materno
                df['nombre'] = ""
                df['apellido_paterno'] = ""
                df['apellido_materno'] = ""

                # Para cada matrícula en el archivo Excel, buscar los datos en la base de datos
                for index, row in df.iterrows():
                    cursor.execute('SELECT nombre, apellido_paterno, apellido_materno FROM USUARIOS WHERE matricula = ?', (row[columna_matricula],))
                    resultado = cursor.fetchone()

                    if resultado:
                        df.at[index, 'nombre'] = resultado[0]
                        df.at[index, 'apellido_paterno'] = resultado[1]
                        df.at[index, 'apellido_materno'] = resultado[2]

                conn.close()

                # Guardar el archivo procesado
                processed_filepath = os.path.join(app.config['DOWNLOAD_FOLDER'], f'procesado_{file.filename.replace(".xlsx", ".csv")}')
                df.to_csv(processed_filepath, index=False, encoding='utf-8-sig')

                return send_file(processed_filepath, as_attachment=True)

            return "Formato de archivo no soportado. Solo se aceptan archivos .xlsx", 400
        except Exception as e:
            print(f"Error al procesar el archivo: {str(e)}")
            return f"Error interno del servidor: {str(e)}", 500

    return render_template('upload_matriculas.html')




if __name__ == '__main__':
    app.run(debug=True)
