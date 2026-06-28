from flask import Flask, render_template, request, jsonify, redirect, url_for, session, abort
from flask import send_from_directory
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
from flask_socketio import SocketIO, emit
import firebase_admin
from firebase_admin import credentials, messaging
from dotenv import load_dotenv

load_dotenv()

# ============================================================
# BASE DE DATOS SEGÚN ENTORNO
# ============================================================

if os.environ.get("RAILWAY_ENVIRONMENT") == "production":
    DATABASE_URL = os.environ.get("DATABASE_URL")
else:
    DATABASE_URL = "sqlite:///local.db"

# ============================================================
# FLASK + BASE DE DATOS
# ============================================================

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

init_db(app)

with app.app_context():
    db.create_all()

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
    """Hace disponible current_user en las plantillas."""
    return dict(current_user=None)

# ============================================================
# YOUTUBE
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
# USUARIOS ONLINE
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
    """Usuarios activos en los últimos 5 minutos."""
    five_minutes_ago = datetime.utcnow() - timedelta(minutes=5)
    return LoggedUser.query.filter(LoggedUser.last_seen >= five_minutes_ago).count()

@app.context_processor
def inject_online_users():
    """Hace disponible {{ online_users }} en todas las plantillas."""
    return {"online_users": get_online_users()}

# ============================================================
# YOUTUBE: VÍDEOS RECIENTES
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
    for user in LoggedUser.query.all():
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
    """Genera una gráfica de usuarios por mes."""
    registros = MonthlyUserLog.query.all()
    conteo_por_mes = {}
    for r in registros:
        conteo_por_mes[r.month] = conteo_por_mes.get(r.month, 0) + 1

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
# RUTA PRINCIPAL
# ============================================================

@app.route("/")
def home():
    """Página principal."""
    user = session.get('user')
    twitch = get_twitch_status()
    videos = get_latest_videos()
    events = get_events()
    return render_template("index.html", twitch=twitch, videos=videos, events=events, user=user)

# ============================================================
# LOGIN / LOGOUT TWITCH
# ============================================================

@app.route("/login/twitch")
def login_twitch():
    """Redirige a Twitch para iniciar sesión."""
    TWITCH_CLIENT_ID = os.getenv("TWITCH_CLIENT_ID")
    TWITCH_REDIRECT_URI = "https://www.pz-verse.com/authorize/twitch"
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
    """Recibe el código de Twitch y autentica al usuario."""
    try:
        code = request.args.get("code")
        token_data = get_token_from_twitch(code)
        user_data = get_user_info_from_twitch(token_data['access_token'])
        session['user'] = {
            'name': user_data.get('display_name'),
            'email': user_data.get('email'),
            'picture': user_data.get('profile_image_url'),
            'platform': 'twitch'
        }
        save_logged_user(session['user'])
        return redirect('/')
    except Exception as e:
        return f"Error en login de Twitch: {str(e)}"

def get_token_from_twitch(code):
    TWITCH_CLIENT_ID = os.getenv("TWITCH_CLIENT_ID")
    TWITCH_CLIENT_SECRET = os.getenv("TWITCH_CLIENT_SECRET")
    TWITCH_REDIRECT_URI = "https://www.pz-verse.com/authorize/twitch"
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
    """Obtiene los datos del usuario desde Twitch."""
    TWITCH_CLIENT_ID = os.getenv("TWITCH_CLIENT_ID")
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Client-Id": TWITCH_CLIENT_ID
    }
    response = requests.get("https://api.twitch.tv/helix/users", headers=headers)
    data = response.json()
    if "data" not in data or len(data["data"]) == 0:
        raise Exception(f"Error obteniendo usuario: {data}")
    return data["data"][0]

@app.route('/logout')
def logout():
    """Cierra sesión."""
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

@app.route("/calendarios")
@login_required
def calendarios():
    return render_template("calendarios.html")

@app.route("/galeria")
@login_required
def galeria():
    return render_template("galeria.html")

@app.route("/tienda")
@login_required
def tienda():
    return render_template("tienda.html")

@app.route("/contacto")
@login_required
def contacto():
    return render_template("contacto.html")

@app.route("/foro")
@login_required
def foro():
    return redirect("/interactivo")

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

    for filename in os.listdir("./posts"):
        if filename.endswith(".json"):
            with open(f"./posts/{filename}", "r", encoding="utf-8") as f:
                data = json.load(f)
                data["slug"] = filename.replace(".json", "")
                all_posts.append(data)

    all_posts.sort(key=lambda x: x["date"], reverse=True)
    total_pages = (len(all_posts) + per_page - 1) // per_page
    start = (page - 1) * per_page
    posts = all_posts[start:start + per_page]

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
# ADMIN BLOG
# ============================================================

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    """Login del panel de administración."""
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

@app.route("/admin/blog")
def admin_blog():
    if not session.get("admin"):
        return redirect("/admin/login")
    return render_template("admin_blog.html")

@app.route("/admin/blog/publicar", methods=["POST"])
def publicar_post():
    if not session.get("admin"):
        return redirect("/admin/login")

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

    post_data = {"title": title, "date": date, "image": image_path, "summary": summary, "content": content}

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

    with open(ruta, "r", encoding="utf-8") as f:
        post = json.load(f)
    return render_template("editar_blog.html", post=post, slug=slug)

# ============================================================
# FORO
# ============================================================

RUTA_TEMAS = "temas.json"

def cargar_temas():
    if os.path.exists(RUTA_TEMAS):
        with open(RUTA_TEMAS, "r", encoding="utf-8") as f:
            return json.load(f)
    return []

def guardar_temas(lista):
    with open(RUTA_TEMAS, "w", encoding="utf-8") as f:
        json.dump(lista, f, indent=2, ensure_ascii=False)

def cargar_tema(id):
    for t in cargar_temas():
        if t["id"] == id:
            return t
    return None

def guardar_tema(titulo, contenido, imagen=None):
    temas = cargar_temas()
    nuevo_id = 1 if not temas else temas[-1]["id"] + 1
    temas.append({
        "id": nuevo_id,
        "titulo": titulo,
        "contenido": contenido,
        "imagen": imagen,
        "autor": session['user']['name'],
        "fecha": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "respuestas": []
    })
    guardar_temas(temas)

def guardar_respuesta(id_tema, texto):
    temas = cargar_temas()
    for t in temas:
        if t["id"] == id_tema:
            nuevo_id = 1 if not t["respuestas"] else t["respuestas"][-1]["id"] + 1
            t["respuestas"].append({
                "id": nuevo_id,
                "autor": session['user']['name'],
                "texto": texto,
                "fecha": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            })
            break
    guardar_temas(temas)

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

@app.route("/nuevo-tema")
@login_required
def nuevo_tema():
    return render_template("nuevo_tema.html")

@app.route("/publicar-tema", methods=["POST"])
@login_required
def publicar_tema():
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

@app.route("/tema/<int:id>")
@login_required
def ver_tema(id):
    tema = cargar_tema(id)
    if not tema:
        return "Tema no encontrado", 404
    return render_template("tema.html", tema=tema)

@app.route("/responder/<int:id>")
@login_required
def mostrar_editor(id):
    return render_template("responder.html", tema=cargar_tema(id))

@app.route("/responder/<int:id>", methods=["POST"])
@login_required
def guardar_respuesta_post(id):
    guardar_respuesta(id, request.form["respuesta"])
    return redirect(f"/tema/{id}")

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
    guardar_temas(temas)
    return redirect("/interactivo#foro")

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
    guardar_temas(temas)
    return redirect(f"/tema/{tema_id}")

# ============================================================
# CHAT
# ============================================================

RUTA_MENSAJES = "mensajes.json"

def cargar_mensajes():
    if os.path.exists(RUTA_MENSAJES):
        with open(RUTA_MENSAJES, "r", encoding="utf-8") as f:
            return json.load(f)
    return []

def guardar_mensajes(lista):
    with open(RUTA_MENSAJES, "w", encoding="utf-8") as f:
        json.dump(lista, f, indent=2, ensure_ascii=False)

@app.route("/enviar_mensaje", methods=["POST"])
def enviar_mensaje():
    data = request.get_json()
    texto = data.get("mensaje", "").strip()
    if not texto:
        return "Mensaje vacío", 400

    usuario = session.get("user", {}).get("name", "Anónimo")
    mensajes = cargar_mensajes()
    mensajes.append({
        "usuario": usuario,
        "texto": texto,
        "fecha": datetime.utcnow().strftime("%H:%M:%S")
    })
    guardar_mensajes(mensajes)
    enviar_telegram(f"{usuario}: {texto}")
    return "OK", 200

@app.route("/mensajes")
def mensajes():
    return jsonify(cargar_mensajes())

@app.route("/registrar-token", methods=["POST"])
def registrar_token():
    data = request.get_json()
    token = data.get("token")
    with open("token_fcm.txt", "w") as f:
        f.write(token)
    return "Token guardado", 200

# ============================================================
# TELEGRAM
# ============================================================

TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = None

try:
    with open("chat_id.txt") as f:
        TELEGRAM_CHAT_ID = f.read().strip()
except:
    pass

def enviar_telegram(mensaje):
    global TELEGRAM_CHAT_ID
    if TELEGRAM_CHAT_ID is None:
        try:
            with open("chat_id.txt") as f:
                TELEGRAM_CHAT_ID = f.read().strip()
        except:
            return

    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
            json={"chat_id": TELEGRAM_CHAT_ID, "text": mensaje}
        )
    except Exception as e:
        print("❌ Error enviando mensaje a Telegram:", e)

@app.route("/telegram-webhook", methods=["POST"])
def telegram_webhook():
    global TELEGRAM_CHAT_ID
    data = request.get_json()
    try:
        texto = data["message"]["text"]
    except:
        texto = ""
    try:
        TELEGRAM_CHAT_ID = data["message"]["chat"]["id"]
        with open("chat_id.txt", "w") as f:
            f.write(str(TELEGRAM_CHAT_ID))
    except:
        pass

    mensajes = cargar_mensajes()
    mensajes.append({
        "usuario": "PZVerse",
        "texto": texto,
        "fecha": datetime.utcnow().strftime("%H:%M:%S")
    })
    guardar_mensajes(mensajes)
    return "OK"

# ============================================================
# NOTIFICACIONES PUSH — FIREBASE
# ============================================================

def enviar_notificacion(titulo, cuerpo):
    try:
        if not os.path.exists("token_fcm.txt"):
            return
        with open("token_fcm.txt", "r") as f:
            token = f.read().strip()
        if not token:
            return
        message = messaging.Message(
            notification=messaging.Notification(title=titulo, body=cuerpo),
            token=token
        )
        messaging.send(message)
    except Exception as e:
        print("❌ Error enviando notificación:", e)

@app.route("/probar-push")
def probar_push():
    enviar_notificacion("🔔 Prueba de notificación", "Todo funciona correctamente.")
    return "Notificación enviada"

# ============================================================
# ADMIN — ESTADÍSTICAS Y RESET MENSUAL
# ============================================================

@app.route("/admin/reset_mes")
def reset_mes():
    archivo = generar_grafica_mensual()
    archive_and_reset_users()
    if archivo:
        return f"Usuarios archivados y gráfica generada: {archivo}"
    return "Usuarios archivados, sin datos para gráfica."

@app.route("/admin/estadisticas_usuarios")
def estadisticas_usuarios():
    registros = MonthlyUserLog.query.all()
    conteo_por_mes = {}
    for r in registros:
        conteo_por_mes[r.month] = conteo_por_mes.get(r.month, 0) + 1

    meses_completos = [f"2026-{str(m).zfill(2)}" for m in range(1, 13)]
    valores = [conteo_por_mes.get(m, 0) for m in meses_completos]
    return render_template("estadisticas.html", meses=meses_completos, valores=valores)

@app.route("/graficas/<filename>")
def graficas(filename):
    return send_from_directory("graficas", filename)

# ============================================================
# CABECERA CSP
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