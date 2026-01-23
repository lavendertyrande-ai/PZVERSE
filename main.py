from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from models import LoggedUser, MonthlyUserLog, db, init_db, get_twitch_status_patz, get_twitch_status_zhoomn
from models import get_twitch_status, get_latest_videos, get_events
from authlib.integrations.flask_client import OAuth
from functools import wraps
from datetime import datetime, timedelta
import requests, os, json, re
import matplotlib.pyplot as plt  # Para generar la gráfica
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_login import current_user, login_required
import firebase_admin
from firebase_admin import credentials, messaging
import platform


from dotenv import load_dotenv
load_dotenv()

print("TEST_VAR:", os.getenv("TEST_VAR"))
import os
print("DEBUG TEST_VAR:", os.getenv("TEST_VAR"))
print("DEBUG GOOGLE_JSON:", os.getenv("GOOGLE_APPLICATION_CREDENTIALS_JSON"))


# ============================================================
# CREACIÓN AUTOMÁTICA DE TABLAS EN LA BASE DE DATOS
# ============================================================
# Este bloque se ejecuta al iniciar la aplicación y garantiza que
# todas las tablas definidas en los modelos de SQLAlchemy existan
# en la base de datos. Si alguna tabla no existe, SQLAlchemy la crea.


from models import init_db, db


app = Flask(__name__)

# Conexión a PostgreSQL usando la variable de entorno
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}


init_db(app)

with app.app_context():
    db.create_all()
    print("📦 Tablas creadas/verificadas")

# ============================================================
# Leer el JSON desde el archivo local
# ============================================================


cred_json = os.getenv("GOOGLE_APPLICATION_CREDENTIALS_JSON")

if not cred_json:
    raise RuntimeError("GOOGLE_APPLICATION_CREDENTIALS_JSON no está definida")

cred_dict = json.loads(cred_json)

cred = credentials.Certificate(cred_dict)
firebase_admin.initialize_app(cred)



# ============================================================
# CONFIGURACIÓN INICIAL
# ============================================================


app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")


@app.context_processor
def inject_user():
    return dict(current_user=current_user)



# Configuración de YouTube para obtener videos recientes
params = {
    "key": os.getenv("YOUTUBE_API_KEY"),
    "channelId": "UCnt9ud1ghqOsRPEun5p3RQQ",
    "part": "snippet",
    "order": "date",
    "maxResults": 6,
    "q": ".",
    "type": "video"
}

# Configuración de SQLite
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///pzverse.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Inicializar base de datos
init_db(app)

# Crear tablas si no existen
with app.app_context():
    db.create_all()

# Inicializar OAuth
oauth = OAuth(app)



# ============================================================
# CONFIGURACIÓN OAUTH TWITCH
# ============================================================

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
# CONFIGURACIÓN SOCKET.IO
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
# FUNCIONES AUXILIARES
# ============================================================

def save_logged_user(user):
    """Guarda o actualiza un usuario logueado en la tabla del mes actual."""
    existing = LoggedUser.query.filter_by(email=user["email"]).first()

    if existing:
        existing.last_seen = datetime.utcnow()
    else:
        new_user = LoggedUser(
            name=user["name"],
            email=user["email"],
            platform=user["platform"],
            picture=user["picture"],
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


def obtener_videos_recientes():
    playlist_id = obtener_playlist_uploads()

    url = "https://www.googleapis.com/youtube/v3/playlistItems"
    params = {
        "key": os.getenv("YOUTUBE_API_KEY"),
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



def obtener_playlist_uploads():
    url = "https://www.googleapis.com/youtube/v3/channels"
    params = {
        "key": os.getenv("YOUTUBE_API_KEY"),
        "id": "UCnt9ud1ghqOsRPEun5p3RQQ",
        "part": "contentDetails"
    }

    response = requests.get(url, params=params).json()
    return response["items"][0]["contentDetails"]["relatedPlaylists"]["uploads"]


# ============================================================
# ARCHIVADO MENSUAL
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

    # Vaciar tabla del mes actual
    LoggedUser.query.delete()
    db.session.commit()


@app.route("/admin/reset_mes")
def reset_mes():
    archive_and_reset_users()
    archivo = generar_grafica_mensual()
    return f"Usuarios archivados, tabla reseteada y gráfica guardada en: {archivo}"



@app.route("/admin/estadisticas_usuarios")
def estadisticas_usuarios():
    # Obtener todos los meses registrados
    registros = MonthlyUserLog.query.all()

    # Diccionario: { "2026-01": 34, "2026-02": 21, ... }
    conteo_por_mes = {}

    for r in registros:
        if r.month not in conteo_por_mes:
            conteo_por_mes[r.month] = 0
        conteo_por_mes[r.month] += 1

    # Ordenar por mes
    meses = sorted(conteo_por_mes.keys())
    valores = [conteo_por_mes[m] for m in meses]

    return render_template(
        "estadisticas.html",
        meses=meses,
        valores=valores
    )

def generar_grafica_mensual():
    """
    Genera una gráfica de barras con el número de usuarios por mes
    usando los datos de la tabla MonthlyUserLog y la guarda como imagen
    en la carpeta 'graficas'.
    """

    # 1. Obtener todos los registros históricos de usuarios
    registros = MonthlyUserLog.query.all()

    # 2. Contar cuántos usuarios hay por cada mes
    #    Ejemplo: {"2026-01": 34, "2026-02": 21, ...}
    conteo_por_mes = {}

    for r in registros:
        if r.month not in conteo_por_mes:
            conteo_por_mes[r.month] = 0
        conteo_por_mes[r.month] += 1

    # Si no hay datos, no tiene sentido generar gráfica
    if not conteo_por_mes:
        return None

    # 3. Ordenar los meses y preparar listas para la gráfica
    meses = sorted(conteo_por_mes.keys())
    valores = [conteo_por_mes[m] for m in meses]

    # 4. Crear carpeta 'graficas' si no existe
    carpeta_graficas = "graficas"
    if not os.path.exists(carpeta_graficas):
        os.makedirs(carpeta_graficas)

    # 5. Crear la gráfica con matplotlib
    plt.figure(figsize=(10, 5))
    plt.bar(meses, valores, color="#FF00CC")
    plt.title("Usuarios por mes")
    plt.xlabel("Mes")
    plt.ylabel("Número de usuarios")
    plt.grid(axis="y", alpha=0.3)

    # 6. Definir nombre del archivo con el mes actual
    nombre_archivo = f"usuarios_{datetime.utcnow().strftime('%Y-%m')}.png"
    ruta_completa = os.path.join(carpeta_graficas, nombre_archivo)

    # 7. Guardar la imagen en disco
    plt.savefig(ruta_completa, dpi=200, bbox_inches="tight")
    plt.close()

    # 8. Devolver la ruta del archivo
    return ruta_completa

# ============================================================
# RUTAS PRINCIPALES
# ============================================================

@app.route("/")
def home():
    user = session.get('user')
    twitch = get_twitch_status()
    videos = get_latest_videos()
    events = get_events()
    return render_template("index.html", twitch=twitch, videos=videos, events=events, user=user)

# ============================================================
# LOGIN TWITCH
# ============================================================

@app.route('/login/twitch')
def login_twitch():
    redirect_uri = "https://www.pz-verse.com/authorize/twitch"
    print("TWITCH REDIRECT V2:", redirect_uri)
    return oauth.twitch.authorize_redirect(redirect_uri)


# probando prints para ver qué llega

@app.route('/authorize/twitch')
def authorize_twitch():
    try:
        code = request.args.get('code')
        if not code:
            return "Error: falta el código de autorización de Twitch."

        # MISMA URI EXACTA que en /login/twitch
        redirect_uri = "https://www.pz-verse.com/authorize/twitch"

        token_url = "https://id.twitch.tv/oauth2/token"
        data = {
            "client_id": os.getenv("TWITCH_CLIENT_ID"),
            "client_secret": os.getenv("TWITCH_CLIENT_SECRET"),
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri,
        }

        resp = requests.post(token_url, data=data)
        token = resp.json()

        if "access_token" not in token:
            return f"Error al autorizar con Twitch. Token recibido: {token}"

        access_token = token["access_token"]

        headers = {
            "Client-ID": os.getenv("TWITCH_CLIENT_ID"),
            "Authorization": f"Bearer {access_token}",
        }

        user_resp = requests.get("https://api.twitch.tv/helix/users", headers=headers)
        user_data = user_resp.json()

        if "data" not in user_data or not user_data["data"]:
            return f"Error al obtener usuario de Twitch. Respuesta: {user_data}"

        user = user_data["data"][0]

        session['user'] = {
            'name': user['display_name'],
            'email': user.get('email'),
            'picture': user.get('profile_image_url'),
            'platform': 'twitch'
        }

        save_logged_user(session['user'])
        return redirect('/')

    except Exception as e:
        print(f"Error en login de Twitch: {str(e)}")
        return f"Error en login de Twitch: {str(e)}"


# ============================================================
# LOGOUT
# ============================================================

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')


# ============================================================
# DECORADOR LOGIN
# ============================================================

def login_required(f):
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
    print("Videos recibidos:", videos)
    return render_template("youtube.html", videos=videos)



@app.route("/blog")
@login_required
def blog():
    page = int(request.args.get("page", 1))
    per_page = 12

    all_posts = []

    for filename in os.listdir("./posts"):
        if filename.endswith(".json"):
            with open(f"./posts/{filename}", "r", encoding="utf-8") as f:
                data = json.load(f)
                data["slug"] = filename.replace(".json", "")
                all_posts.append(data)

    all_posts.sort(key=lambda x: x["date"], reverse=True)

    total_pages = (len(all_posts) + per_page - 1) // per_page
    start = (page - 1) * per_page
    end = start + per_page
    posts = all_posts[start:end]

    return render_template("blog.html", posts=posts, page=page, total_pages=total_pages)



@app.route("/blog/<slug>")
@login_required
def blog_post(slug):
    try:
        with open(f"./posts/{slug}.json", "r", encoding="utf-8") as f:
            post = json.load(f)
    except:
        return "Post no encontrado", 404

    return render_template("post.html", post=post)



# ============================================================
# RUTA PRINCIPAL DEL FORO — SE MUESTRA DENTRO DE /interactivo
# ============================================================
@app.route("/interactivo")
@login_required
def interactivo():
    temas = cargar_temas()
    return render_template(
        "interactivo.html",
        temas=temas,
        firebase_api_key=os.getenv("FIREBASE_API_KEY"),
        firebase_vapid_key=os.getenv("FIREBASE_VAPID_KEY")
    )

# ============================================================
# RUTA PARA CREAR NUEVO TEMA — MUESTRA EL EDITOR
# ============================================================
@app.route("/nuevo-tema")
@login_required
def nuevo_tema():
    return render_template("nuevo_tema.html")


# ============================================================
# RUTA PARA PUBLICAR TEMA — PROCESA EL FORMULARIO
# ============================================================
@app.route("/publicar-tema", methods=["POST"])
@login_required
def publicar_tema():
    titulo = request.form["titulo"]
    contenido = request.form["contenido"]

    # Imagen opcional
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
# RUTA PARA VER UN TEMA INDIVIDUAL
# ============================================================
@app.route("/tema/<int:id>")
@login_required
def ver_tema(id):
    tema = cargar_tema(id)
    return render_template("tema.html", tema=tema)


# ============================================================
# RUTA PARA RESPONDER A UN TEMA
# ============================================================
# Mostrar editor (GET)
@app.route("/responder/<int:id>")
@login_required
def mostrar_editor(id):
    tema = cargar_tema(id)
    return render_template("responder.html", tema=tema)


# Guardar respuesta (POST)
@app.route("/responder/<int:id>", methods=["POST"])
@login_required
def guardar_respuesta_post(id):
    texto = request.form["respuesta"]
    guardar_respuesta(id, texto)
    return redirect(f"/tema/{id}")



# ============================================================
# RUTA PARA ELIMINAR TEMA
# ============================================================
@app.route("/eliminar-tema/<int:id>", methods=["POST"])
@login_required
def eliminar_tema(id):
    temas = cargar_temas()

    for t in temas:
        if t["id"] == id:

            if t["autor"].lower() != session['user']['name'].lower():
                abort(403)

            temas.remove(t)
            break

    with open(RUTA_TEMAS, "w", encoding="utf-8") as f:
        json.dump(temas, f, indent=2, ensure_ascii=False)

    return redirect("/interactivo#foro")


# ============================================================
# RUTA PARA ELIMINAR RESPUESTA
# ============================================================
@app.route("/eliminar-respuesta/<int:tema_id>/<int:respuesta_id>", methods=["POST"])
@login_required
def eliminar_respuesta(tema_id, respuesta_id):
    temas = cargar_temas()

    for t in temas:
        if t["id"] == tema_id:

            for r in t["respuestas"]:
                if r["id"] == respuesta_id:

                    if r["autor"].lower() != session['user']['name'].lower():
                        abort(403)

                    t["respuestas"].remove(r)
                    break

    with open(RUTA_TEMAS, "w", encoding="utf-8") as f:
        json.dump(temas, f, indent=2, ensure_ascii=False)

    return redirect(f"/tema/{tema_id}")



# ============================================================
# PÁGINA DE ADMINISTRACIÓN BLOG
# ============================================================

# LOGIN ADMIN
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        password = request.form.get("password")

        if password == "PZVERSE2060":
            session["admin"] = True
            return redirect("/admin/blog?inicio=1")

        return "Contraseña incorrecta", 403

    return render_template("admin_login.html")


@app.route('/admin/logout')
def admin_logout():
    session.pop('admin', None)
    return redirect('/blog')


# PANEL ADMIN BLOG
@app.route("/admin/blog")
def admin_blog():
    if not session.get("admin"):
        return redirect("/admin/login")

    return render_template("admin_blog.html")


# PUBLICAR POST
@app.route("/admin/blog/publicar", methods=["POST"])
def publicar_post():
    print("🔔 POST recibido en /admin/blog/publicar")

    if not session.get("admin"):
        print("❌ No estás logueada como admin")
        return redirect("/admin/login")

    print("✅ Sesión admin activa — procesando publicación")


    title = request.form.get("title")
    summary = request.form.get("summary")
    content = request.form.get("content")

    image_file = request.files.get("image")
    image_path = None

    if image_file and image_file.filename != "":
        image_path = f"/static/blog/{image_file.filename}"
        image_file.save("." + image_path)

    slug = re.sub(r"[^a-zA-Z0-9]+", "-", title.lower()).strip("-")
    date = datetime.today().strftime("%d-%m-%Y")

    if not os.path.exists("posts"):
        os.makedirs("posts")

    post_data = {
        "title": title,
        "date": date,
        "image": image_path,
        "summary": summary,
        "content": content
    }

    print("📁 Guardando post en:", f"./posts/{date}-{slug}.json")

    with open(f"./posts/{date}-{slug}.json", "w", encoding="utf-8") as f:
        json.dump(post_data, f, ensure_ascii=False, indent=4)

    return redirect("/admin/blog?publicado=1")


@app.route("/admin/blog/gestionar")
def gestionar_posts():
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



@app.route("/admin/blog/eliminar/<slug>")
def eliminar_post(slug):
    if not session.get("admin"):
        return redirect("/admin/login")

    ruta = f"./posts/{slug}.json"
    if os.path.exists(ruta):
        os.remove(ruta)

    return redirect("/admin/blog/gestionar")


@app.route("/admin/blog/editar/<slug>", methods=["GET", "POST"])
def editar_post(slug):
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
# CHAT REST API
# ============================================================

RUTA_MENSAJES = "mensajes.json"


def cargar_mensajes():
    """Lee los mensajes desde mensajes.json"""
    if os.path.exists(RUTA_MENSAJES):
        with open(RUTA_MENSAJES, "r", encoding="utf-8") as f:
            return json.load(f)
    return []


def guardar_mensajes(lista):
    """Guarda la lista completa de mensajes en mensajes.json"""
    with open(RUTA_MENSAJES, "w", encoding="utf-8") as f:
        json.dump(lista, f, indent=2, ensure_ascii=False)


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



@app.route("/mensajes")
def mensajes():
    """Devuelve todos los mensajes del chat"""
    return jsonify(cargar_mensajes())



# ============================================================
# RUTA MENSAJES CHAT - MOVIL
# ============================================================
@app.route("/registrar-token", methods=["POST"])
def registrar_token():
    data = request.get_json()
    token = data.get("token")

    # Guardamos el token en un archivo simple
    with open("token_fcm.txt", "w") as f:
        f.write(token)

    return "Token guardado", 200


# ============================================================
# 🔔 SISTEMA DE NOTIFICACIONES TELEGRAM — PZVERSE
# ============================================================

import requests

# TOKEN DEL BOT (DE BOTFATHER)
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
print("🔑 TOKEN TELEGRAM cargado:", "OK" if TELEGRAM_TOKEN else "VACÍO")

# CHAT_ID DEL USUARIO (SE RELLENA AUTOMÁTICAMENTE CUANDO ESCRIBAS AL BOT)
TELEGRAM_CHAT_ID = None

# 🌸 PRECARGAR CHAT_ID AL INICIAR EL SERVIDOR
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

    # Si la variable global está vacía, cargar desde archivo
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

    # Enviar mensaje a Telegram
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
# WEBHOOK PARA CAPTURAR TU CHAT_ID AUTOMÁTICAMENTE
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

    # EXTRAER TEXTO DEL MENSAJE
    try:
        texto = data["message"]["text"]
    except:
        texto = ""

    # EXTRAER CHAT_ID
    try:
        TELEGRAM_CHAT_ID = data["message"]["chat"]["id"]
        print("✅ CHAT_ID DETECTADO:", TELEGRAM_CHAT_ID)

        # Guardar chat_id en archivo
        try:
            with open("chat_id.txt", "w") as f:
                f.write(str(TELEGRAM_CHAT_ID))
            print("💾 chat_id.txt guardado correctamente")
        except Exception as e:
            print("❌ Error guardando chat_id.txt:", e)

    except Exception as e:
        print("❌ Error extrayendo CHAT_ID:", e)

    # GUARDAR EL MENSAJE EN EL CHAT DE LA WEB
    mensajes = cargar_mensajes()
    mensajes.append({
        "usuario": "PZVerse",  # Nombre que aparecerá en el chat web
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
# RUTA PARA TOKEN
# ============================================================
@app.route("/ver-token")
def ver_token():
    try:
        with open("token_fcm.txt", "r") as f:
            return f"<pre>{f.read()}</pre>"
    except Exception as e:
        return f"Error: {e}"


# ============================================================
# SISTEMA DE FORO — FUNCIONES Y UTILIDADES
# ============================================================

# Archivo donde se guardan los temas del foro
RUTA_TEMAS = "temas.json"


def cargar_temas():
    """
    Carga todos los temas del foro desde el archivo JSON.
    Si no existe, devuelve una lista vacía.
    """
    if os.path.exists(RUTA_TEMAS):
        with open(RUTA_TEMAS, "r", encoding="utf-8") as f:
            return json.load(f)
    return []

# ============================================================

def cargar_tema(id):
    """
    Carga un tema concreto por ID.
    Devuelve None si no existe.
    """
    temas = cargar_temas()
    for t in temas:
        if t["id"] == id:
            return t
    return None

# ============================================================

def guardar_tema(titulo, contenido, imagen=None):
    temas = cargar_temas()

    nuevo_tema = {
        "id": len(temas) + 1,
        "titulo": titulo,
        "contenido": contenido.replace("\r", ""),
        "imagen": imagen,
        "autor": session['user']['name'],   # AUTOR REAL
        "respuestas": []
    }

    temas.append(nuevo_tema)

    with open(RUTA_TEMAS, "w", encoding="utf-8") as f:
        json.dump(temas, f, indent=2, ensure_ascii=False)



# ============================================================

def guardar_respuesta(id, texto):
    temas = cargar_temas()

    for t in temas:
        if t["id"] == id:

            nueva_respuesta = {
                "id": len(t["respuestas"]) + 1,
                "texto": texto,
                "autor": session['user']['name'],   # AUTOR REAL
                "fecha": datetime.utcnow().strftime("%d/%m/%Y %H:%M")
            }

            t["respuestas"].append(nueva_respuesta)

    with open(RUTA_TEMAS, "w", encoding="utf-8") as f:
        json.dump(temas, f, indent=2, ensure_ascii=False)


# ============================================================
# FUNCIONES ENVIAR NOTIFICACIONES PUSH
# ============================================================

def enviar_notificacion(titulo, mensaje):
    try:
        with open("token_fcm.txt") as f:
            token = f.read().strip()
    except:
        print("⚠️ No hay token registrado todavía")
        return

    # Crear el mensaje
    message = messaging.Message(
        notification=messaging.Notification(
            title=titulo,
            body=mensaje
        ),
        token=token
    )

    # Enviar notificación
    try:
        response = messaging.send(message)
        print("📨 Notificación enviada:", response)
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




