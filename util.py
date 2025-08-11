# utils.py
import os
import random
from contextlib import contextmanager
import mysql.connector
from flask import current_app
from functools import wraps
from flask import request, jsonify
import jwt

def get_db_connection():
    return mysql.connector.connect(
        host=os.getenv('DB_HOST'),
        port=int(os.getenv('DB_PORT', 3306)),
        user=os.getenv('DB_USER'),
        password=os.getenv('DB_PASSWORD'),
        database=os.getenv('DB_NAME')
    )

@contextmanager
def mysql_cursor(dictionary=False):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=dictionary)
    try:
        yield cursor
        conn.commit()
    finally:
        cursor.close()
        conn.close()

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization")
        if not token:
            return jsonify({"message": "Token is missing!"}), 403
        try:
            token = token.replace("Bearer ", "")
            data = jwt.decode(token, os.getenv("SECRET_KEY"), algorithms=["HS256"])
            return f(data["email"], *args, **kwargs)
        except Exception:
            return jsonify({"message": "Token is invalid!"}), 403
    return decorated

def pick_team(match_id):
    try:
        with mysql_cursor(dictionary=True) as cursor:
            cursor.execute("""
                SELECT * FROM players
                WHERE match_id = %s
                ORDER BY RAND()
                LIMIT 11
            """, (match_id,))
            players = cursor.fetchall()

        if len(players) != 11:
            return None

        captain_index = random.randint(0, 10)
        vice_captain_index = (captain_index + 1) % 11

        for i, player in enumerate(players):
            player['is_captain'] = (i == captain_index)
            player['is_vice_captain'] = (i == vice_captain_index)

        return players
    except Exception as e:
        print(f"Error in pick_team(): {e}")
        return None
