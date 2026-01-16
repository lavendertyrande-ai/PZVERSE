import sqlite3
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def get_connection():
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    return conn
