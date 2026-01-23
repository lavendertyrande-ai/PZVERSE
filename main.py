from flask import Flask, render_template, request, jsonify, redirect, url_for, session, abort
from models import (
    LoggedUser,
    MonthlyUserLog,
    db,
    init_db,
    get_twitch_status_patz,
    get_twitch_status_zhoomn,
    get_twitch_status,
    get_latest_videos,
    get_events,
)
from authlib.integrations.flask_client import OAuth
from functools import wraps
from datetime import datetime, timedelta
import requests
import os
import json
import re
import matplotlib.pyplot as plt
from flask_socketio import SocketIO, emit, join_room, leave_room
import firebase_admin
from firebase_admin import credentials, messaging
import platform
from dotenv import load_dotenv

load_dotenv()

# Debug de variables de entorno
print("TEST_VAR:", os.getenv("TEST_VAR"))
print("DEBUG TEST_VAR:", os.getenv("TEST_VAR"))
print("DEBUG GOOGLE_JSON:", os.getenv("GOOGLE_APPLICATION_CREDENTIALS_JSON"))

# ============================================================
# FLASK + BASE DE DATOS (NEON / POSTGRESQL)
# ============================================================

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")

# Conexión a PostgreSQL usando la variable de entorno (Neon)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ["DATABASE_URL"]
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

print("DEBUG DB URI:", app.config["SQLALCHEMY_DATABASE_URI"])

# Inicializar SQLAlchemy con esta app
init_db(app)

# Crear tablas si no existen
with app.app_context():
    db.create_all()
    print("📦 Tablas creadas/verificadas")
    print("📌 Tablas registradas por SQLAlchemy:", db.metadata.tables.keys())

# ============================================================
# FIREBASE (NOTIFICACIONES PUSH)
# ============================================================

cred_json = os.getenv("GOOGLE_APPLICATION_CREDENTIALS_JSON")
if not cred_json:
    raise RuntimeError("GOOGLE_APPLICATION_CREDENTIALS_JSON no está definida")

cred_dict = json.loads(cred_json)
cred = credentials.Certificate(cred_dict)
firebase_admin.initialize_app(cred)

# ============================================================
# CONTEXT PROCESSORS
# ============================================================

@app.context_processor
def inject_user():
    """Hace disponible current_user en las plantillas (por compatibilidad futura)."""
    return dict(current_user=None)

# ============================================================
# CONFIGURACIÓN YOUTUBE (VIDEOS RECIENTES)
# ============================================================

YOUTUBE_CHANNEL_ID = "UCnt9ud1ghqOsRPEun5p3RQQ"
YOUTUBE_API_KEY = os.getenv("YOUTUBE_API_KEY")

# ============================================================
# OAUTH TWITCH
# ============================================================

oauth = OAuth(app)

oauth.register(
    name='twitch',
    client_id=os.getenv("TWITCH_CLIENT_ID"),
    client_secret=os.getenv("TWITCH_CLIENT_SECRET"),
    access_token_url='https://id.twitch.tv/oauth2/token',
    authorize_url='https://id.twitch.tv/oauth2/authorize',
    api_base_url='https://api.twitch.tv/helix/',
    client_kwargs={'scope': 'user:read:email'}
)

# ============================================================
# SOCKET.IO
# ============================================================

socketio = SocketIO(app, async_mode='threading')
usuarios_conectados = set()

@socketio.on('connect')
def handle_connect():
    usuario = request.args.get('usuario', 'Anónimo')
    usuarios_conectados.add(usuario)
    emit('usuario_conectado', {'usuario': usuario}, broadcast=True)
    emit('lista_usuarios', list(usuarios_conectados), broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    usuario = request.args.get('usuario', 'Anónimo')
    usuarios_conectados.discard(usuario)
    emit('lista_usuarios', list(usuarios_conectados), broadcast=True)

# ============================================================
# FUNCIONES AUXILIARES USUARIOS + ONLINE
# ============================================================

def save_logged_user(user_data):
    """Guarda o actualiza un usuario logueado en la tabla LoggedUser."""
    existing_user = LoggedUser.query.filter_by(email=user_data['email']).first()

    if existing_user:
        existing_user.last_seen = datetime.utcnow()
    else:
        new_user = LoggedUser(
            name=user_data['name'],
            email=user_data['email'],
            platform=user_data['platform'],
            picture=user_data['picture'],
            last_seen=datetime.utcnow()
        )
        db.session.add(new_user)

    db.session.commit()

def get_online_users():
    """Devuelve cuántos usuarios han estado activos en los últimos 5 minutos."""
    five_minutes_ago = datetime.utcnow() - timedelta(minutes=5)
    return LoggedUser.query.filter(LoggedUser.last_seen >= five_minutes_ago).count()

@app.context_processor
def inject_online_users():
    """Hace disponible {{ online_users }} en TODAS las plantillas."""
    return {"online_users": get_online_users()}

# ============================================================
# YOUTUBE: OBTENER VIDEOS RECIENTES
# ============================================================

def obtener_playlist_uploads():
    url = "https://www.googleapis.com/youtube/v3/channels"
    params = {
        "key": YOUTUBE_API_KEY,
        "id": YOUTUBE_CHANNEL_ID,
        "part": "contentDetails"
    }
    response = requests.get(url, params=params).json()
    return response["items"][0]["contentDetails"]["relatedPlaylists"]["uploads"]

def obtener_videos_recientes():
    playlist_id = obtener_playlist_uploads()

    url = "https://www.googleapis.com/youtube/v3/playlistItems"
    params = {
        "key": YOUTUBE_API_KEY,
        "playlistId": playlist_id,
        "part": "snippet",
        "maxResults": 6
    }

    response = requests.get(url, params=params).json()

    videos = []
    for item in response.get("items", []):
        snippet = item["snippet"]
        video_id = snippet["resourceId"]["videoId"]
        videos.append({
            "video_id": video_id,
            "titulo": snippet["title"],
            "miniatura": snippet["thumbnails"]["high"]["url"],
            "fecha": snippet["publishedAt"]
        })

    return videos

# ============================================================
# ARCHIVADO MENSUAL + GRÁFICA
# ============================================================

def archive_and_reset_users():
    """Guarda los usuarios del mes en MonthlyUserLog y resetea LoggedUser."""
    current_month = datetime.utcnow().strftime("%Y-%m")
    users = LoggedUser.query.all()

    for user in users:
        archived = MonthlyUserLog(
            name=user.name,
            email=user.email,
            platform=user.platform,
            picture=user.picture,
            month=current_month
        )
        db.session.add(archived)

    LoggedUser.query.delete()
    db.session.commit()

def generar_grafica_mensual():
    """Genera una gráfica de usuarios por mes usando MonthlyUserLog."""
    registros = MonthlyUserLog.query.all()
    conteo_por_mes = {}

    for r in registros:
        if r.month not in conteo_por_mes:
            conteo_por_mes[r.month] = 0
        conteo_por_mes[r.month] += 1

    if not conteo_por_mes:
        return None

    meses = sorted(conteo_por_mes.keys())
    valores = [conteo_por_mes[m] for m in meses]

    carpeta_graficas = "graficas"
    if not os.path.exists(carpeta_graficas):
        os.makedirs(carpeta_graficas)

    plt.figure(figsize=(10, 5))
    plt.bar(meses, valores, color="#FF00CC")
    plt.title("Usuarios por mes")
    plt.xlabel("Mes")
    plt.ylabel("Número de usuarios")
    plt.grid(axis="y", alpha=0.3)

    nombre_archivo = f"usuarios_{datetime.utcnow().strftime('%Y-%m')}.png"
    ruta_completa = os.path.join(carpeta_graficas, nombre_archivo)

    plt.savefig(ruta_completa, dpi=200, bbox_inches="tight")
    plt.close()

    return ruta_completa

# ============================================================
# RUTAS PRINCIPALES
# ============================================================

@app.route("/")
def home():
    """Página principal con Twitch, vídeos, eventos y usuario en sesión."""
    user = session.get('user')
    twitch = get_twitch_status()
    videos = get_latest_videos()
    events = get_events()

    return render_template(
        "index.html",
        twitch=twitch,
        videos=videos,
        events=events,
        user=user
    )


# ============================================================
# LOGIN TWITCH
# ============================================================

@app.route("/login/twitch")
def login_twitch():
    """Redirige al usuario a Twitch para iniciar sesión."""
    TWITCH_CLIENT_ID = os.getenv("TWITCH_CLIENT_ID")
    TWITCH_REDIRECT_URI = os.getenv("TWITCH_REDIRECT_URI")

    auth_url = (
        "https://id.twitch.tv/oauth2/authorize"
        "?client_id=" + TWITCH_CLIENT_ID +
        "&redirect_uri=" + TWITCH_REDIRECT_URI +
        "&response_type=code"
        "&scope=user:read:email"
    )

    return redirect(auth_url)


@app.route("/authorize/twitch")
def authorize_twitch():
    """Recibe el código de Twitch, obtiene token y datos del usuario."""
    try:
        code = request.args.get("code")

        # 1. Intercambiar código por token
        token_data = get_token_from_twitch(code)

        # 2. Obtener datos del usuario
        user_data = get_user_info_from_twitch(token_data['access_token'])

        # 3. Guardar en sesión
        session['user'] = {
            'name': user_data.get('display_name'),
            'email': user_data.get('email'),
            'picture': user_data.get('profile_image_url'),
            'platform': 'twitch'
        }

        # 4. Guardar en Neon
        save_logged_user(session['user'])

        return redirect('/')

    except Exception as e:
        print(f"Error en login de Twitch: {str(e)}")
        return f"Error en login de Twitch: {str(e)}"



# ============================================================
# TWITCH OAUTH — FUNCIONES NECESARIAS
# ============================================================

def get_token_from_twitch(code):
    """Intercambia el código de Twitch por un token de acceso."""
    TWITCH_CLIENT_ID = os.getenv("TWITCH_CLIENT_ID")
    TWITCH_CLIENT_SECRET = os.getenv("TWITCH_CLIENT_SECRET")
    TWITCH_REDIRECT_URI = os.getenv("TWITCH_REDIRECT_URI")

    url = "https://id.twitch.tv/oauth2/token"
    payload = {
        "client_id": TWITCH_CLIENT_ID,
        "client_secret": TWITCH_CLIENT_SECRET,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": TWITCH_REDIRECT_URI
    }

    response = requests.post(url, data=payload)
    data = response.json()

    if "access_token" not in data:
        raise Exception(f"Error obteniendo token: {data}")

    return data


def get_user_info_from_twitch(access_token):
    """Obtiene los datos del usuario desde la API de Twitch."""
    TWITCH_CLIENT_ID = os.getenv("TWITCH_CLIENT_ID")

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Client-Id": TWITCH_CLIENT_ID
    }

    url = "https://api.twitch.tv/helix/users"
    response = requests.get(url, headers=headers)
    data = response.json()

    if "data" not in data or len(data["data"]) == 0:
        raise Exception(f"Error obteniendo usuario: {data}")

    return data["data"][0]


# ============================================================
# LOGOUT
# ============================================================

@app.route('/logout')
def logout():
    """Cierra sesión del usuario."""
    session.clear()
    return redirect('/')


# ============================================================
# DECORADOR LOGIN
# ============================================================

def login_required(f):
    """Protege rutas que requieren usuario logueado."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login_twitch'))
        return f(*args, **kwargs)
    return decorated


# ============================================================
# RUTAS PROTEGIDAS
# ============================================================

@app.route("/twitch-mio")
@login_required
def twitch_mio():
    twitch = get_twitch_status_patz()
    return render_template("patz_twitch.html", twitch=twitch)


@app.route("/twitch-pareja")
@login_required
def twitch_pareja():
    twitch = get_twitch_status_zhoomn()
    return render_template("zhoomn_twitch.html", twitch=twitch)


@app.route("/youtube")
@login_required
def youtube_page():
    videos = obtener_videos_recientes()
    return render_template("youtube.html", videos=videos)




# ============================================================
# BLOG — LISTADO Y VISUALIZACIÓN
# ============================================================

@app.route("/blog")
@login_required
def blog():
    """Lista paginada de posts del blog."""
    page = int(request.args.get("page", 1))
    per_page = 12

    all_posts = []

    # Cargar todos los posts desde /posts
    for filename in os.listdir("./posts"):
        if filename.endswith(".json"):
            with open(f"./posts/{filename}", "r", encoding="utf-8") as f:
                data = json.load(f)
                data["slug"] = filename.replace(".json", "")
                all_posts.append(data)

    # Ordenar por fecha descendente
    all_posts.sort(key=lambda x: x["date"], reverse=True)

    # Paginación
    total_pages = (len(all_posts) + per_page - 1) // per_page
    start = (page - 1) * per_page
    end = start + per_page
    posts = all_posts[start:end]

    return render_template("blog.html", posts=posts, page=page, total_pages=total_pages)


@app.route("/blog/<slug>")
@login_required
def blog_post(slug):
    """Muestra un post individual."""
    try:
        with open(f"./posts/{slug}.json", "r", encoding="utf-8") as f:
            post = json.load(f)
    except:
        return "Post no encontrado", 404

    return render_template("post.html", post=post)



# ============================================================
# ADMIN BLOG — LOGIN
# ============================================================

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    """Login simple para administrar el blog."""
    if request.method == "POST":
        password = request.form.get("password")

        if password == "PZVERSE2060":
            session["admin"] = True
            return redirect("/admin/blog?inicio=1")

        return "Contraseña incorrecta", 403

    return render_template("admin_login.html")


@app.route('/admin/logout')
def admin_logout():
    """Cerrar sesión del admin."""
    session.pop('admin', None)
    return redirect('/blog')


# ============================================================
# PANEL ADMIN BLOG
# ============================================================

@app.route("/admin/blog")
def admin_blog():
    """Panel principal del blog (solo admin)."""
    if not session.get("admin"):
        return redirect("/admin/login")

    return render_template("admin_blog.html")


# ============================================================
# PUBLICAR POST
# ============================================================

@app.route("/admin/blog/publicar", methods=["POST"])
def publicar_post():
    """Publica un nuevo post en formato JSON."""
    if not session.get("admin"):
        return redirect("/admin/login")

    title = request.form.get("title")
    summary = request.form.get("summary")
    content = request.form.get("content")

    # Imagen opcional
    image_file = request.files.get("image")
    image_path = None

    if image_file and image_file.filename != "":
        image_path = f"/static/blog/{image_file.filename}"
        image_file.save("." + image_path)

    # Crear slug
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", title.lower()).strip("-")
    date = datetime.today().strftime("%d-%m-%Y")

    # Crear carpeta si no existe
    if not os.path.exists("posts"):
        os.makedirs("posts")

    post_data = {
        "title": title,
        "date": date,
        "image": image_path,
        "summary": summary,
        "content": content
    }

    # Guardar archivo JSON
    with open(f"./posts/{date}-{slug}.json", "w", encoding="utf-8") as f:
        json.dump(post_data, f, ensure_ascii=False, indent=4)

    return redirect("/admin/blog?publicado=1")


# ============================================================
# GESTIONAR POSTS
# ============================================================

@app.route("/admin/blog/gestionar")
def gestionar_posts():
    """Lista todos los posts para editarlos o eliminarlos."""
    if not session.get("admin"):
        return redirect("/admin/login")

    posts = []

    for filename in os.listdir("./posts"):
        if filename.endswith(".json"):
            with open(f"./posts/{filename}", "r", encoding="utf-8") as f:
                data = json.load(f)
                data["slug"] = filename.replace(".json", "")
                posts.append(data)

    posts.sort(key=lambda x: x["date"], reverse=True)

    return render_template("gestionar_blog.html", posts=posts)



# ============================================================
# ELIMINAR POST
# ============================================================

@app.route("/admin/blog/eliminar/<slug>")
def eliminar_post(slug):
    """Elimina un post del blog."""
    if not session.get("admin"):
        return redirect("/admin/login")

    ruta = f"./posts/{slug}.json"
    if os.path.exists(ruta):
        os.remove(ruta)

    return redirect("/admin/blog/gestionar")



# ============================================================
# EDITAR POST
# ============================================================

@app.route("/admin/blog/editar/<slug>", methods=["GET", "POST"])
def editar_post(slug):
    """Editar un post existente."""
    if not session.get("admin"):
        return redirect("/admin/login")

    ruta = f"./posts/{slug}.json"

    if request.method == "POST":
        title = request.form.get("title")
        summary = request.form.get("summary")
        content = request.form.get("content")

        image_file = request.files.get("image")
        image_path = request.form.get("current_image")

        if image_file and image_file.filename != "":
            image_path = f"/static/blog/{image_file.filename}"
            image_file.save("." + image_path)

        post_data = {
            "title": title,
            "date": datetime.today().strftime("%d-%m-%Y"),
            "image": image_path,
            "summary": summary,
            "content": content
        }

        with open(ruta, "w", encoding="utf-8") as f:
            json.dump(post_data, f, ensure_ascii=False, indent=4)

        return redirect("/admin/blog/gestionar")

    # GET: cargar datos
    with open(ruta, "r", encoding="utf-8") as f:
        post = json.load(f)

    return render_template("editar_blog.html", post=post, slug=slug)



# ============================================================
# FORO — FUNCIONES AUXILIARES
# ============================================================

RUTA_TEMAS = "temas.json"

def cargar_temas():
    """Carga todos los temas desde temas.json."""
    if os.path.exists(RUTA_TEMAS):
        with open(RUTA_TEMAS, "r", encoding="utf-8") as f:
            return json.load(f)
    return []

def guardar_temas(lista):
    """Guarda la lista completa de temas en temas.json."""
    with open(RUTA_TEMAS, "w", encoding="utf-8") as f:
        json.dump(lista, f, indent=2, ensure_ascii=False)

def cargar_tema(id):
    """Carga un tema individual por ID."""
    temas = cargar_temas()
    for t in temas:
        if t["id"] == id:
            return t
    return None

def guardar_tema(titulo, contenido, imagen=None):
    """Crea un nuevo tema y lo guarda en temas.json."""
    temas = cargar_temas()

    nuevo_id = 1 if not temas else temas[-1]["id"] + 1

    tema = {
        "id": nuevo_id,
        "titulo": titulo,
        "contenido": contenido,
        "imagen": imagen,
        "autor": session['user']['name'],
        "fecha": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "respuestas": []
    }

    temas.append(tema)
    guardar_temas(temas)

def guardar_respuesta(id_tema, texto):
    """Guarda una respuesta dentro de un tema."""
    temas = cargar_temas()

    for t in temas:
        if t["id"] == id_tema:

            nuevo_id = 1 if not t["respuestas"] else t["respuestas"][-1]["id"] + 1

            respuesta = {
                "id": nuevo_id,
                "autor": session['user']['name'],
                "texto": texto,
                "fecha": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            }

            t["respuestas"].append(respuesta)
            break

    guardar_temas(temas)


# ============================================================
# RUTA PRINCIPAL DEL FORO
# ============================================================

@app.route("/interactivo")
@login_required
def interactivo():
    """Página principal del foro."""
    temas = cargar_temas()
    return render_template(
        "interactivo.html",
        temas=temas,
        firebase_api_key=os.getenv("FIREBASE_API_KEY"),
        firebase_vapid_key=os.getenv("FIREBASE_VAPID_KEY")
    )



# ============================================================
# CREAR NUEVO TEMA — FORMULARIO
# ============================================================

@app.route("/nuevo-tema")
@login_required
def nuevo_tema():
    """Muestra el editor para crear un nuevo tema."""
    return render_template("nuevo_tema.html")




# ============================================================
# PUBLICAR TEMA — PROCESAR FORMULARIO
# ============================================================

@app.route("/publicar-tema", methods=["POST"])
@login_required
def publicar_tema():
    """Procesa el formulario y crea un nuevo tema."""
    titulo = request.form["titulo"]
    contenido = request.form["contenido"]

    imagen = None
    if "imagen" in request.files:
        archivo = request.files["imagen"]
        if archivo.filename != "":
            ruta = f"/static/uploads/{archivo.filename}"
            archivo.save("." + ruta)
            imagen = ruta

    guardar_tema(titulo, contenido, imagen)
    return redirect("/interactivo")



# ============================================================
# VER UN TEMA INDIVIDUAL
# ============================================================

@app.route("/tema/<int:id>")
@login_required
def ver_tema(id):
    """Muestra un tema individual."""
    tema = cargar_tema(id)
    if not tema:
        return "Tema no encontrado", 404

    return render_template("tema.html", tema=tema)



# ============================================================
# RESPONDER A UN TEMA
# ============================================================

@app.route("/responder/<int:id>")
@login_required
def mostrar_editor(id):
    """Muestra el editor para responder a un tema."""
    tema = cargar_tema(id)
    return render_template("responder.html", tema=tema)


@app.route("/responder/<int:id>", methods=["POST"])
@login_required
def guardar_respuesta_post(id):
    """Guarda la respuesta enviada por el usuario."""
    texto = request.form["respuesta"]
    guardar_respuesta(id, texto)
    return redirect(f"/tema/{id}")


# ============================================================
# ELIMINAR TEMA
# ============================================================

@app.route("/eliminar-tema/<int:id>", methods=["POST"])
@login_required
def eliminar_tema(id):
    """Elimina un tema si el autor coincide con el usuario actual."""
    temas = cargar_temas()

    for t in temas:
        if t["id"] == id:

            if t["autor"].lower() != session['user']['name'].lower():
                abort(403)

            temas.remove(t)
            break

    guardar_temas(temas)
    return redirect("/interactivo#foro")




# ============================================================
# ELIMINAR RESPUESTA
# ============================================================

@app.route("/eliminar-respuesta/<int:tema_id>/<int:respuesta_id>", methods=["POST"])
@login_required
def eliminar_respuesta(tema_id, respuesta_id):
    """Elimina una respuesta si el autor coincide con el usuario actual."""
    temas = cargar_temas()

    for t in temas:
        if t["id"] == tema_id:

            for r in t["respuestas"]:
                if r["id"] == respuesta_id:

                    if r["autor"].lower() != session['user']['name'].lower():
                        abort(403)

                    t["respuestas"].remove(r)
                    break

    guardar_temas(temas)
    return redirect(f"/tema/{tema_id}")



# ============================================================
# CHAT — ARCHIVO DE MENSAJES
# ============================================================

RUTA_MENSAJES = "mensajes.json"

def cargar_mensajes():
    """Lee los mensajes desde mensajes.json."""
    if os.path.exists(RUTA_MENSAJES):
        with open(RUTA_MENSAJES, "r", encoding="utf-8") as f:
            return json.load(f)
    return []

def guardar_mensajes(lista):
    """Guarda la lista completa de mensajes en mensajes.json."""
    with open(RUTA_MENSAJES, "w", encoding="utf-8") as f:
        json.dump(lista, f, indent=2, ensure_ascii=False)



# ============================================================
# ENVIAR MENSAJE DESDE LA WEB
# ============================================================

@app.route("/enviar_mensaje", methods=["POST"])
def enviar_mensaje():
    """
    Recibe un mensaje desde la web.
    Lo guarda en mensajes.json y lo envía a Telegram.
    """
    data = request.get_json()
    texto = data.get("mensaje", "").strip()

    if not texto:
        return "Mensaje vacío", 400

    usuario = session.get("user", {}).get("name", "Anónimo")

    # Guardar en el chat web
    mensajes = cargar_mensajes()
    mensajes.append({
        "usuario": usuario,
        "texto": texto,
        "fecha": datetime.utcnow().strftime("%H:%M:%S")
    })
    guardar_mensajes(mensajes)

    print(f"💬 Mensaje desde web: {usuario}: {texto}")

    # Enviar a Telegram
    enviar_telegram(f"{usuario}: {texto}")

    return "OK", 200



# ============================================================
# OBTENER MENSAJES DEL CHAT
# ============================================================

@app.route("/mensajes")
def mensajes():
    """Devuelve todos los mensajes del chat."""
    return jsonify(cargar_mensajes())



# ============================================================
# REGISTRO DE TOKEN PARA NOTIFICACIONES PUSH
# ============================================================

@app.route("/registrar-token", methods=["POST"])
def registrar_token():
    """Guarda el token FCM del móvil para enviar notificaciones push."""
    data = request.get_json()
    token = data.get("token")

    with open("token_fcm.txt", "w") as f:
        f.write(token)

    return "Token guardado", 200



# ============================================================
# TELEGRAM — CONFIGURACIÓN INICIAL
# ============================================================

TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
print("🔑 TOKEN TELEGRAM cargado:", "OK" if TELEGRAM_TOKEN else "VACÍO")

TELEGRAM_CHAT_ID = None

# Precargar chat_id si existe
try:
    with open("chat_id.txt") as f:
        TELEGRAM_CHAT_ID = f.read().strip()
    print("♻️ CHAT_ID precargado al iniciar:", TELEGRAM_CHAT_ID)
except:
    print("⚠️ No se pudo precargar chat_id.txt (aún no existe)")




# ============================================================
# FUNCIÓN PARA ENVIAR MENSAJES A TELEGRAM
# ============================================================

def enviar_telegram(mensaje):
    """
    Envía un mensaje al bot de Telegram.
    Si Railway reinicia y la variable global se pierde,
    se recarga automáticamente desde chat_id.txt.
    """
    global TELEGRAM_CHAT_ID

    # Si no está cargado, intentar leerlo del archivo
    if TELEGRAM_CHAT_ID is None:
        try:
            with open("chat_id.txt") as f:
                TELEGRAM_CHAT_ID = f.read().strip()
                print("♻️ CHAT_ID cargado desde archivo:", TELEGRAM_CHAT_ID)
        except FileNotFoundError:
            print("⚠️ No existe chat_id.txt — Telegram aún no ha enviado ningún mensaje.")
            return
        except Exception as e:
            print("❌ Error leyendo chat_id.txt:", e)
            return

    # Enviar mensaje
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": mensaje
    }

    try:
        r = requests.post(url, json=payload)
        print("📨 Respuesta de Telegram:", r.text)
    except Exception as e:
        print("❌ Error enviando mensaje a Telegram:", e)




# ============================================================
# WEBHOOK DE TELEGRAM — RECIBIR MENSAJES
# ============================================================

@app.route("/telegram-webhook", methods=["POST"])
def telegram_webhook():
    """
    Recibe mensajes desde Telegram.
    Guarda el chat_id en archivo para persistencia.
    Guarda el mensaje en el chat web.
    """
    global TELEGRAM_CHAT_ID

    data = request.get_json()
    print("📩 Mensaje recibido desde Telegram:", data)

    # Extraer texto
    try:
        texto = data["message"]["text"]
    except:
        texto = ""

    # Extraer chat_id
    try:
        TELEGRAM_CHAT_ID = data["message"]["chat"]["id"]
        print("✅ CHAT_ID DETECTADO:", TELEGRAM_CHAT_ID)

        # Guardar chat_id
        with open("chat_id.txt", "w") as f:
            f.write(str(TELEGRAM_CHAT_ID))
        print("💾 chat_id.txt guardado correctamente")

    except Exception as e:
        print("❌ Error extrayendo CHAT_ID:", e)

    # Guardar mensaje en el chat web
    mensajes = cargar_mensajes()
    mensajes.append({
        "usuario": "PZVerse",
        "texto": texto,
        "fecha": datetime.utcnow().strftime("%H:%M:%S")
    })
    guardar_mensajes(mensajes)

    return "OK"




# ============================================================
# RUTA PARA PROBAR NOTIFICACIONES PUSH
# ============================================================

@app.route("/probar-push")
def probar_push():
    enviar_notificacion("🔔 Prueba de notificación", "Todo funciona correctamente.")
    return "Notificación enviada"



# ============================================================
# ARCHIVADO MENSUAL — GUARDAR USUARIOS Y RESETEAR TABLA
# ============================================================

@app.route("/admin/reset_mes")
def reset_mes():
    """Archiva los usuarios del mes y resetea la tabla LoggedUser."""
    archivo = generar_grafica_mensual()
    archive_and_reset_users()

    if archivo:
        return f"Usuarios archivados, tabla reseteada y gráfica generada: {archivo}"
    else:
        return "Usuarios archivados y tabla reseteada, pero no había datos para generar gráfica."




# ============================================================
# ESTADÍSTICAS DE USUARIOS — MOSTRAR GRÁFICA EN HTML
# ============================================================

@app.route("/admin/estadisticas_usuarios")
def estadisticas_usuarios():
    """Genera datos para la página de estadísticas de usuarios."""
    registros = MonthlyUserLog.query.all()

    conteo_por_mes = {}

    for r in registros:
        if r.month not in conteo_por_mes:
            conteo_por_mes[r.month] = 0
        conteo_por_mes[r.month] += 1

    meses = sorted(conteo_por_mes.keys())
    valores = [conteo_por_mes[m] for m in meses]

    return render_template(
        "estadisticas.html",
        meses=meses,
        valores=valores
    )



# ============================================================
# NOTIFICACIONES PUSH — FIREBASE CLOUD MESSAGING
# ============================================================

def enviar_notificacion(titulo, cuerpo):
    """
    Envía una notificación push al dispositivo móvil usando FCM.
    Requiere que el usuario haya registrado su token en /registrar-token.
    """
    try:
        # Leer token guardado
        if not os.path.exists("token_fcm.txt"):
            print("⚠️ No existe token_fcm.txt — ningún dispositivo ha registrado token aún.")
            return

        with open("token_fcm.txt", "r") as f:
            token = f.read().strip()

        if not token:
            print("⚠️ El token FCM está vacío.")
            return

        # Crear mensaje
        message = messaging.Message(
            notification=messaging.Notification(
                title=titulo,
                body=cuerpo
            ),
            token=token
        )

        # Enviar notificación
        response = messaging.send(message)
        print("📨 Notificación enviada correctamente:", response)

    except Exception as e:
        print("❌ Error enviando notificación:", e)



# ============================================================
# CABECERA SCP
# ============================================================

@app.after_request
def fix_csp(response):
    response.headers['Content-Security-Policy'] = (
        "frame-ancestors 'self' https://www.pz-verse.com https://player.twitch.tv https://www.twitch.tv"
    )
    return response


# ============================================================
# ARRANQUE
# ============================================================


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    socketio.run(app, host="0.0.0.0", port=port, allow_unsafe_werkzeug=True)




