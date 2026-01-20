from flask_sqlalchemy import SQLAlchemy
import os
import requests
from datetime import datetime

# Instancia global de SQLAlchemy
db = SQLAlchemy()

# Modelo de usuario logueado
class LoggedUser(db.Model):
    __tablename__ = 'logged_users'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    platform = db.Column(db.String(50), nullable=False)
    picture = db.Column(db.String(300))
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)

# Función para vincular la base de datos al Flask app
def init_db(app):
    db.init_app(app)


class MonthlyUserLog(db.Model):
    __tablename__ = 'monthly_user_logs'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150))
    email = db.Column(db.String(150))
    platform = db.Column(db.String(50))
    picture = db.Column(db.String(300))
    month = db.Column(db.String(7))  # formato '2026-01'
    saved_at = db.Column(db.DateTime, default=datetime.utcnow)



def get_twitch_status():
    # Más adelante añadiremos la API real
    return {
        "live": False,
        "title": "Stream offline por ahora"
    }



# ---------------------------------------------------------
# FUNCIÓN PARA SABER SI PATZ ESTÁ ONLINE
# ---------------------------------------------------------
def get_twitch_status_patz():
    """
    Consulta la API de Twitch para saber si el canal 'patzoficial' está en directo.
    Devuelve un diccionario con:
    - online: True/False
    - title: título del directo (si está online)
    """

    client_id = os.getenv("TWITCH_CLIENT_ID")
    client_secret = os.getenv("TWITCH_CLIENT_SECRET")

    # 1. Obtener token de acceso de Twitch
    token_url = "https://id.twitch.tv/oauth2/token"
    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "client_credentials"
    }
    token_resp = requests.post(token_url, data=data).json()
    access_token = token_resp["access_token"]

    # 2. Headers obligatorios para consultar la API
    headers = {
        "Client-ID": client_id,
        "Authorization": f"Bearer {access_token}"
    }

    # 3. Consultar si el canal está en directo
    stream_url = "https://api.twitch.tv/helix/streams?user_login=patzoficial"
    stream_resp = requests.get(stream_url, headers=headers).json()

    # 4. Si hay datos → está online
    if stream_resp["data"]:
        return {
            "online": True,
            "title": stream_resp["data"][0]["title"]
        }

    # Si no hay datos → está offline
    return {"online": False}


# ---------------------------------------------------------
# FUNCIÓN PARA SABER SI ZHOOMN ESTÁ ONLINE
# ---------------------------------------------------------
def get_twitch_status_zhoomn():
    """
    Igual que la anterior, pero para el canal 'zhoomnoficial'.
    """

    client_id = os.getenv("TWITCH_CLIENT_ID")
    client_secret = os.getenv("TWITCH_CLIENT_SECRET")

    token_url = "https://id.twitch.tv/oauth2/token"
    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "client_credentials"
    }
    token_resp = requests.post(token_url, data=data).json()
    access_token = token_resp["access_token"]

    headers = {
        "Client-ID": client_id,
        "Authorization": f"Bearer {access_token}"
    }

    stream_url = "https://api.twitch.tv/helix/streams?user_login=zhoomnoficial"
    stream_resp = requests.get(stream_url, headers=headers).json()

    if stream_resp["data"]:
        return {
            "online": True,
            "title": stream_resp["data"][0]["title"]
        }

    return {"online": False}

def get_latest_videos():
    # Luego conectaremos YouTube API
    return [
        {"title": "Video 1"},
        {"title": "Video 2"},
        {"title": "Video 3"}
    ]

def get_events():
    # Luego añadiremos Google Calendar API
    return [
        "Evento 1",
        "Evento 2",
        "Evento 3"
    ]
