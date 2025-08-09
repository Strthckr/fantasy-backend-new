# ─── MODULE IMPORTS ─────────────────────────────────────────────────────────────
from datetime import datetime, timedelta
from flask_cors import CORS
import jwt
from functools import wraps
from flask import Flask, request, jsonify, make_response
import mysql.connector
from flask_mysqldb import MySQL
import json
from decimal import Decimal
from dotenv import load_dotenv
import os
import bcrypt
import traceback
import re
from celery import Celery
from contextlib import contextmanager
import random




# ─── LOAD ENVIRONMENT VARIABLES ────────────────────────────────────────────────
# Load variables from a .env file (good for DB credentials, secret keys, etc.)
load_dotenv()

# ✅ Debug print to confirm variables are loaded correctly
print("✅ DB_HOST:", os.getenv("DB_HOST"))
print("✅ DB_USER:", os.getenv("DB_USER"))
print("✅ DB_PASSWORD:", os.getenv("DB_PASSWORD"))
print("✅ DB_NAME:", os.getenv("DB_NAME"))
print("✅ SECRET_KEY:", os.getenv("SECRET_KEY"))

# ─── FLASK APP INITIALIZATION ──────────────────────────────────────────────────
app = Flask(__name__)
db = MySQL(app)

# CORS setup: Allow frontend on localhost:3000 to access this backend
CORS(app, origins=["http://localhost:3000"], supports_credentials=True)

# ─── CELERY SETUP ──────────────────────────────────────────────────────────────
# ─── CELERY SETUP ──────────────────────────────────────────────────────────────
def make_celery(app):
    celery = Celery(
        app.import_name,
        broker='redis://localhost:6379/0',
        backend='redis://localhost:6379/0'
    )
    celery.conf.update(app.config)
    return celery

celery = make_celery(app)


@app.before_request
def handle_preflight():
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers['Access-Control-Allow-Origin'] = 'http://localhost:3000'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        response.status_code = 200
        return response


# Load secret key into Flask config from .env (used for JWT)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret_key')
print("✅ SECRET_KEY loaded:", app.config['SECRET_KEY'])

# ─── DATABASE CONNECTION SETUP ─────────────────────────────────────────────────
# Connect to MySQL using credentials from .env file
# ─── DATABASE CONNECTION SETUP ────────────────────────────────────────────────

def get_db_connection():
    return mysql.connector.connect(
        host=os.getenv('DB_HOST'),
        port=int(os.getenv('DB_PORT', 3306)),
        user=os.getenv('DB_USER'),
        password=os.getenv('DB_PASSWORD'),
        database=os.getenv('DB_NAME')
    )
    db = MySQL(app)

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


# 🧠 Updated: pick_team using context-managed MySQL connection
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

        # Randomly assign captain/vice
        captain_index = random.randint(0, 10)
        vice_captain_index = (captain_index + 1) % 11

        for i, player in enumerate(players):
            player['is_captain'] = (i == captain_index)
            player['is_vice_captain'] = (i == vice_captain_index)
            player['player_id'] = player['id']  # Ensure compatibility

        return players

    except Exception as e:
        print(f"Error in pick_team(): {e}")
        return None



# ─── JWT TOKEN PROTECTION DECORATOR ────────────────────────────────────────────
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Step 1: Allow CORS preflight requests without checking JWT
        if request.method == 'OPTIONS':
            resp = make_response('', 204)  # No Content
            # Allow headers for cross-origin support
            resp.headers['Access-Control-Allow-Origin'] = 'http://localhost:3000'
            resp.headers['Access-Control-Allow-Methods'] = 'GET,POST,OPTIONS'
            resp.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization'
            return resp

        # Step 2: Check for Authorization header and extract token
        token = None
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1]  # Extract token after 'Bearer'

        # Step 3: If token missing, deny access
        if not token:
            return jsonify({'message': 'Token is missing!'}), 403

        try:
            # Step 4: Decode the token using the app's secret key
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user_email = data['email']  # Extract email from token
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired! Please login again.'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token!'}), 401

        # Step 5: Proceed to the actual route, passing email to it
        return f(current_user_email, *args, **kwargs)

    return decorated

# ─── ADMIN CHECK FUNCTION ──────────────────────────────────────────────────────
# Helper to check if a given user email belongs to an admin
def is_admin_user(email):
    with mysql_cursor() as cursor:
        cursor.execute("SELECT is_admin FROM users WHERE email = %s", (email,))
        result = cursor.fetchone()
        return result and result[0] == 1  # Return True if is_admin == 1

# ─── CORS PREFLIGHT HELPER (OPTIONAL) ──────────────────────────────────────────
# Used to return proper headers in preflight responses manually
def _build_cors_preflight_response():
    response = jsonify({})
    h = response.headers
    h['Access-Control-Allow-Origin'] = 'http://localhost:3000'
    h['Access-Control-Allow-Methods'] = 'GET,POST,OPTIONS'
    h['Access-Control-Allow-Headers'] = 'Content-Type,Authorization'
    return response

@app.route('/')
def home():
    return "Hello, World!"

# Signup API
import bcrypt
print("🔔 /login route is registered")

# Login API
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email    = data.get('email')
    password = data.get('password')

    with mysql_cursor(dictionary=True) as cursor:
        cursor.execute("SELECT id, email, password FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

    if not user:
        return jsonify({"message": "User not found"}), 404

    stored_hash = user["password"]
    if not bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8")):
        return jsonify({"message": "Invalid credentials"}), 401

    token = jwt.encode(
        {"email": email, "exp": datetime.utcnow() + timedelta(days=7)},
        app.config["SECRET_KEY"],
        algorithm="HS256",
    )
    if isinstance(token, bytes):
        token = token.decode("utf-8")

    return jsonify({
        "token": token,
        "id":    user["id"],
        "email": user["email"]
    }), 200



@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data['username']
    email = data['email']
    password = data['password']

    # Hash password before storing
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    try:
        with mysql_cursor() as cursor:
            cursor.execute(
                "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                (username, email, hashed_password.decode('utf-8'))
            )
            user_id = cursor.lastrowid

            cursor.execute(
                "INSERT INTO wallets (user_id, balance) VALUES (%s, %s)",
                (user_id, 200.00)
            )

        return jsonify({"message": "User registered and wallet created!"}), 201
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 400

@app.route('/dashboard', methods=['GET'])
@token_required
def dashboard(current_user_email):
    try:
        with mysql_cursor() as cursor:
            cursor.execute("SELECT username FROM users WHERE email = %s", (current_user_email,))
            user = cursor.fetchone()

        if user:
            return jsonify({"message": f"Welcome to your dashboard, {user[0]}!"})
        else:
            return jsonify({"message": "User not found"}), 404
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500


@app.route('/create_team', methods=['POST'])
@token_required
def create_team(current_user_email):
    try:
        data       = request.get_json()
        team_name  = data.get('team_name')
        players    = data.get('players', [])
        contest_id = data.get('contest_id')

        if not team_name or len(players) != 11 or not contest_id:
            return jsonify({"message": "team_name, 11 players & contest_id required"}), 400

        # user ID lookup
        cur = db.cursor()
        cur.execute("SELECT id FROM users WHERE email=%s", (current_user_email,))
        row = cur.fetchone()
        if not row:
            return jsonify({"message": "User not found"}), 404
        user_id = row[0]

        # max teams check
        cur.execute("SELECT max_teams_per_user FROM contests WHERE id=%s", (contest_id,))
        max_teams = cur.fetchone()[0] or 0

        cur.execute("""
            SELECT COUNT(*) FROM teams
            WHERE user_id=%s AND contest_id=%s
        """, (user_id, contest_id))
        already = cur.fetchone()[0]
        if max_teams and already >= max_teams:
            return jsonify({"message": f"Only {max_teams} teams allowed"}), 403

        # current combination to check against duplicates
        current_names = sorted([p['player_name'] for p in players])

        cur.execute("""
            SELECT players FROM teams
            WHERE user_id=%s AND contest_id=%s
        """, (user_id, contest_id))

        for (js,) in cur.fetchall():
            existing = json.loads(js) if js else []
            if not existing:
                continue

            # safe handling based on structure
            if isinstance(existing[0], dict) and 'player_name' in existing[0]:
                existing_names = sorted([p['player_name'] for p in existing])
            elif isinstance(existing[0], str):
                existing_names = sorted(existing)
            else:
                continue  # unknown structure, skip

            if existing_names == current_names:
                return jsonify({"message": "Same combination used"}), 400

        # insert the new team
        cur.execute("""
            INSERT INTO teams
                (team_name, players, user_id, contest_id)
            VALUES (%s, %s, %s, %s)
        """, (team_name, json.dumps(players), user_id, contest_id))
        db.commit()

        return jsonify({"message": "Team created ✔"}), 200

    except Exception as e:
        app.logger.exception(e)
        return jsonify({"message": "Internal Server Error"}), 500

if __name__ == '__main__':
    app.run(debug=True)
# Join Contest API
now = datetime.utcnow()



# ----------  JOIN CONTEST  ----------
@app.route('/contest/<int:contest_id>/join', methods=['OPTIONS', 'POST'])
@token_required
def join_contest_by_url(current_user_email, contest_id):
    # 1) Handle CORS preflight
    if request.method == 'OPTIONS':
        # token_required already adds the correct CORS headers
        return '', 204

    # 2) Parse body (only team_id required—the contest_id comes from the URL)
    data = request.get_json() or {}
    team_id = data.get('team_id')
    if not team_id:
        return jsonify({"message": "Team ID required"}), 400

    cur = cursor

    # 3) Get user_id from email
    cur.execute("SELECT id FROM users WHERE email=%s", (current_user_email,))
    row = cur.fetchone()
    if not row:
        return jsonify({"message": "User not found"}), 404
    user_id = row[0]

    # 4) Validate team ownership
    cur.execute("""
        SELECT id FROM teams
        WHERE id = %s AND user_id = %s AND contest_id = %s
    """, (team_id, user_id, contest_id))
    if not cur.fetchone():
        return jsonify({"message": "Invalid team for this user and contest"}), 400

    # 5) Contest details & capacity check
    cur.execute(
        "SELECT entry_fee, joined_users, max_users FROM contests WHERE id=%s",
        (contest_id,)
    )
    row = cur.fetchone()
    if not row:
        return jsonify({"message": "Contest not found"}), 404
    entry_fee, joined, max_users = row
    if joined >= max_users:
        return jsonify({"message": "Contest full"}), 400

    # 6) Wallet balance check
    cur.execute("SELECT balance FROM wallets WHERE user_id=%s", (user_id,))
    balance = cur.fetchone()[0]
    if balance < entry_fee:
        return jsonify({"message": "Insufficient balance"}), 403

    # 7) Deduct fee, increment joined_users, insert entry & transaction
    cur.execute(
        "UPDATE wallets SET balance = balance - %s WHERE user_id=%s",
        (entry_fee, user_id)
    )
    cur.execute(
        "UPDATE contests SET joined_users = joined_users + 1 WHERE id=%s",
        (contest_id,)
    )
    cur.execute(
        "INSERT INTO entries (user_id, team_id, contest_id) VALUES (%s, %s, %s)",
        (user_id, team_id, contest_id)
    )
    cur.execute(
        "INSERT INTO transactions (user_id, amount, type, description) "
        "VALUES (%s, %s, 'debit', 'Joined contest')",
        (user_id, entry_fee)
    )

    db.commit()
    return jsonify({"message": f"Joined! ₹{entry_fee} deducted."}), 200

# # Create Contest API
# @app.route('/admin/create_contest', methods=['POST'])
# @token_required
# def create_contest(current_user_email):
#     if not is_admin_user(current_user_email):
#         return jsonify({"message": "Unauthorized"}), 403

#     data = request.get_json()
#     contest_name = data.get('contest_name')
#     match_id = data.get('match_id')
#     entry_fee = data.get('entry_fee')
#     total_spots = data.get('total_spots')
#     commission_percentage = data.get('commission_percentage', 15)
#     max_teams_per_user = data.get('max_teams_per_user', 1)

#     if not contest_name or not match_id or not entry_fee or not total_spots:
#         return jsonify({"message": "Missing required fields"}), 400

#     try:
#         cursor = db.cursor()
#         total_collection = float(entry_fee) * int(total_spots)
#         commission_amount = total_collection * (float(commission_percentage) / 100)
#         prize_pool = total_collection - commission_amount

#         cursor.execute("""
#             INSERT INTO contests 
#             (contest_name, match_id, entry_fee, prize_pool,
#              start_time, end_time, status, max_teams_per_user,
#              commission_percentage, total_spots)
#             VALUES (%s, %s, %s, %s, NOW(), NOW(), 'active', %s, %s, %s)
#         """, (contest_name, match_id, entry_fee, prize_pool,
#               max_teams_per_user, commission_percentage, total_spots))

#         db.commit()
#         return jsonify({"message": "Contest created successfully!"})
#     except mysql.connector.Error as err:
#         return jsonify({"error": str(err)}), 500


# List Contests API
# 1️⃣  List ALL contests  -------------------
@app.route('/contests', methods=['GET'])
def list_all_contests():
    """Return every contest in the system (ordered by soonest start)."""
    try:
        with mysql_cursor(dictionary=True) as cursor:
            cursor.execute("""
                SELECT id,
                       name,               -- contest name
                       match_id,
                       entry_fee,
                       prize_pool,
                       max_users,
                       joined_users,
                       status,
                       start_time,
                       end_time
                FROM contests
                ORDER BY start_time ASC
            """)
            return jsonify(cursor.fetchall())
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500
    

# User’s contests
@app.route('/my_contests/<int:user_id>', methods=['GET'])
def my_contests(user_id):
    """
    Return every contest the given user has joined, with prize-pool, time,
    and computed status (UPCOMING/LIVE/COMPLETED).

    Output → { "contests": [ {...}, … ] }
    """
    try:
        with mysql_cursor(dictionary=True) as cursor:
            query = """
                SELECT  c.id,
                        c.contest_name,
                        c.entry_fee,
                        c.prize_pool,
                        c.joined_users,
                        c.max_users,
                        m.start_time,
                        m.end_time,
                        CASE
                            WHEN NOW() <  m.start_time           THEN 'UPCOMING'
                            WHEN NOW() BETWEEN m.start_time
                                           AND m.end_time         THEN 'LIVE'
                            ELSE                                     'COMPLETED'
                        END AS status
                FROM    contests  c
                JOIN    entries   e ON c.id = e.contest_id
                JOIN    matches   m ON m.id = c.match_id
                WHERE   e.user_id = %s
                ORDER BY m.start_time DESC;
            """
            cursor.execute(query, (user_id,))
            contests = cursor.fetchall()
            return jsonify({"contests": contests}), 200

    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500


# Leaderboard API
@app.route('/leaderboard/<int:contest_id>', methods=['GET'])
def leaderboard(contest_id):
    try:
        with mysql_cursor(dictionary=True) as cursor:
            query = """
                SELECT t.team_name, SUM(s.points) AS total_points
                FROM teams t
                JOIN entries e ON t.id = e.team_id
                JOIN scores s ON e.id = s.entry_id
                WHERE e.contest_id = %s
                GROUP BY t.team_name
                ORDER BY total_points DESC
                LIMIT 10
            """
            cursor.execute(query, (contest_id,))
            results = cursor.fetchall()
            return jsonify(results)
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500


# Add Points API
@app.route('/add_points', methods=['POST'])
def add_points():
    data = request.get_json()
    entry_id = data.get('entry_id')
    points = data.get('points')

    if not entry_id or points is None:
        return jsonify({"message": "Missing entry_id or points"}), 400

    try:
        with mysql_cursor() as cursor:
            cursor.execute(
                "INSERT INTO scores (entry_id, points) VALUES (%s, %s)",
                (entry_id, points)
            )
        return jsonify({"message": "Points added successfully!"}), 201
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500


# Update Team API
@app.route('/update_team/<int:team_id>', methods=['POST'])  # Can change to PUT later
@token_required
def update_team(current_user_email, team_id):
    data = request.get_json()
    team_name = data.get('team_name')
    players = data.get('players')

    if not team_name or not players:
        return jsonify({"message": "Missing team_name or players"}), 400

    try:
        players_json = json.dumps(players)
        with mysql_cursor() as cursor:
            cursor.execute(
                "UPDATE teams SET team_name = %s, players = %s WHERE id = %s",
                (team_name, players_json, team_id)
            )
        return jsonify({"message": "Team updated successfully!"})
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500


# Delete Team API
@app.route('/delete_team/<int:team_id>', methods=['POST'])
@token_required
def delete_team(current_user_email, team_id):
    try:
        with mysql_cursor() as cursor:
            # Delete scores linked to entries of this team
            cursor.execute("""
                DELETE scores FROM scores
                JOIN entries ON scores.entry_id = entries.id
                WHERE entries.team_id = %s
            """, (team_id,))

            # Delete entries linked to this team
            cursor.execute("DELETE FROM entries WHERE team_id = %s", (team_id,))

            # Delete the team
            cursor.execute("DELETE FROM teams WHERE id = %s", (team_id,))
            
        return jsonify({"message": "Team and related entries deleted successfully!"})
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500



# Delete Contest API
@app.route('/delete_contest/<int:contest_id>', methods=['POST'])
@token_required
def delete_contest(current_user_email, contest_id):
    try:
        with mysql_cursor() as cursor:
            # Delete scores linked to entries in this contest
            cursor.execute("""
                DELETE scores FROM scores
                JOIN entries ON scores.entry_id = entries.id
                WHERE entries.contest_id = %s
            """, (contest_id,))

            # Delete entries linked to this contest
            cursor.execute("DELETE FROM entries WHERE contest_id = %s", (contest_id,))

            # Delete the contest
            cursor.execute("DELETE FROM contests WHERE id = %s", (contest_id,))
            
        return jsonify({"message": "Contest and all related data deleted successfully!"})
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500



# This route handles adding points for multiple entries at once
@app.route('/add_points_bulk', methods=['POST'])
@token_required
def add_points_bulk(current_user_email):
    data = request.get_json()
    print("Received JSON:", data)  # Debug print

    entries_points = data.get('entries')

    if not entries_points or not isinstance(entries_points, list):
        return jsonify({"message": "Input must be a list of entry_id and points"}), 400

    try:
        with mysql_cursor() as cursor:
            for item in entries_points:
                entry_id = item.get('entry_id')
                points = item.get('points')

                if entry_id is None or points is None:
                    return jsonify({"message": "Each entry must have 'entry_id' and 'points'"}), 400

                cursor.execute(
                    "INSERT INTO scores (entry_id, points) VALUES (%s, %s)",
                    (entry_id, points)
                )
        return jsonify({"message": "Points added successfully for all entries!"}), 201
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500




@app.route('/declare_winners/<int:contest_id>', methods=['POST'])
@token_required
def declare_winners(current_user_email, contest_id):
    try:
        with mysql_cursor(dictionary=True) as cursor:
            query = """
                SELECT t.id AS team_id, SUM(s.points) AS total_points
                FROM teams t
                JOIN entries e ON t.id = e.team_id
                JOIN scores s ON e.id = s.entry_id
                WHERE e.contest_id = %s
                GROUP BY t.id
                ORDER BY total_points DESC
                LIMIT 3
            """
            cursor.execute(query, (contest_id,))
            winners = cursor.fetchall()

            for rank, winner in enumerate(winners, start=1):
                cursor.execute("""
                    INSERT INTO winners (contest_id, team_id, total_points, rank_position)
                    VALUES (%s, %s, %s, %s)
                """, (contest_id, winner['team_id'], winner['total_points'], rank))

            db.commit()
            return jsonify({"message": "Winners declared successfully!", "winners": winners})
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500


@app.route('/wallet_balance', methods=['GET'])
@token_required
def wallet_balance(current_user_email):
    try:
        with mysql_cursor() as cursor:
            cursor.execute("SELECT id FROM users WHERE email = %s", (current_user_email,))
            user = cursor.fetchone()
            if not user:
                return jsonify({"message": "User not found"}), 404
            user_id = user[0]

            cursor.execute("SELECT balance FROM wallets WHERE user_id = %s", (user_id,))
            wallet = cursor.fetchone()
            if not wallet:
                return jsonify({"message": "Wallet not found"}), 404

            return jsonify({"balance": float(wallet[0])})
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500




@app.route('/profile', methods=['GET'])
@token_required
def get_profile(current_user_email):
    try:
        with mysql_cursor(dictionary=True) as cur:
            cur.execute(
                "SELECT username, email FROM users WHERE email = %s",
                (current_user_email,)
            )
            user = cur.fetchone()
            if user:
                return jsonify(user)
            return jsonify({"message": "User not found"}), 404
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500


@app.route('/profile', methods=['PUT'])
@token_required
def update_profile(current_user_email):
    data = request.get_json() or {}
    new_username = data.get('username')

    if not new_username:
        return jsonify({"message": "Username is required"}), 400

    try:
        with mysql_cursor() as cur:
            cur.execute(
                "UPDATE users SET username = %s WHERE email = %s",
                (new_username, current_user_email)
            )
            db.commit()
            return jsonify({"message": "Profile updated successfully"})
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500


@app.route('/wallet', methods=['GET'])
@token_required
def wallet(current_user_email):
    try:
        with mysql_cursor(dictionary=True) as cursor:
            cursor.execute("""
                SELECT w.balance FROM wallets w
                JOIN users u ON w.user_id = u.id
                WHERE u.email = %s
            """, (current_user_email,))
            wallet = cursor.fetchone()
            if wallet:
                return jsonify({"balance": wallet['balance']})
            else:
                return jsonify({"message": "Wallet not found"}), 404
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500


@app.route('/transactions', methods=['GET'])
@token_required
def get_transactions(current_user_email):
    try:
        with mysql_cursor(dictionary=True) as cursor:
            cursor.execute("SELECT id FROM users WHERE email = %s", (current_user_email,))
            user = cursor.fetchone()
            if not user:
                return jsonify({"message": "User not found"}), 404

            user_id = user['id']

            cursor.execute("""
                SELECT amount, type, description, created_at
                FROM transactions
                WHERE user_id = %s
                ORDER BY created_at DESC
            """, (user_id,))
            transactions = cursor.fetchall()

            return jsonify({"transactions": transactions})
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500


@app.route('/admin/distribute_prizes/<int:contest_id>', methods=['POST'])
@token_required
def distribute_prizes(current_user_email, contest_id):
    if not is_admin_user(current_user_email):
        return jsonify({"message": "Unauthorized"}), 403

    try:
        with mysql_cursor(dictionary=True) as cursor:
            cursor.execute("SELECT prize_pool, status, commission_percentage FROM contests WHERE id = %s", (contest_id,))
            contest = cursor.fetchone()

            if not contest:
                return jsonify({"message": "Contest not found"}), 404
            if contest['status'] == 'prizes_distributed':
                return jsonify({"message": "Prizes already distributed"}), 400

            prize_pool = float(contest['prize_pool'])
            commission_percentage = contest['commission_percentage'] or 0
            commission_amount = prize_pool * (commission_percentage / 100)
            prize_pool -= commission_amount

            cursor.execute("""
                INSERT INTO platform_earnings (contest_id, commission_amount)
                VALUES (%s, %s)
            """, (contest_id, commission_amount))

            cursor.execute("""
                SELECT rank_position, percentage
                FROM prize_distributions
                WHERE contest_id = %s
                ORDER BY rank_position ASC
            """, (contest_id,))
            distributions = cursor.fetchall()

            if not distributions:
                return jsonify({"message": "No prize distribution set for this contest"}), 400

            cursor.execute("""
                SELECT t.id as team_id, t.user_id, t.total_points
                FROM teams t
                WHERE t.contest_id = %s
                ORDER BY t.total_points DESC
                LIMIT %s
            """, (contest_id, len(distributions)))
            teams = cursor.fetchall()

            if not teams:
                return jsonify({"message": "No teams found for this contest"}), 400

            for idx, team in enumerate(teams):
                rank = idx + 1
                prize_percentage = float(next((d['percentage'] for d in distributions if d['rank_position'] == rank), 0))
                prize_amount = prize_pool * (prize_percentage / 100)

                cursor.execute("SELECT balance FROM wallets WHERE user_id = %s", (team['user_id'],))
                wallet = cursor.fetchone()
                if wallet is None:
                    return jsonify({"message": f"Wallet not found for user_id {team['user_id']}"}), 404

                new_balance = Decimal(str(wallet['balance'])) + Decimal(str(prize_amount))
                cursor.execute("UPDATE wallets SET balance = %s WHERE user_id = %s", (new_balance, team['user_id']))

                cursor.execute("""
                    INSERT INTO transaction_history (user_id, amount, transaction_type, description)
                    VALUES (%s, %s, 'credit', %s)
                """, (team['user_id'], prize_amount, f'Prize for rank {rank} in contest {contest_id}'))

                cursor.execute("""
                    INSERT INTO notifications (user_id, message)
                    VALUES (%s, %s)
                """, (team['user_id'], f"🎉 You won ₹{prize_amount:.2f} in contest ID {contest_id} (Rank {rank})!"))

            cursor.execute("UPDATE contests SET status = 'prizes_distributed' WHERE id = %s", (contest_id,))
            db.commit()

            return jsonify({
                "message": f"Prizes distributed for contest {contest_id}",
                "commission_collected": commission_amount
            })

    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500











@app.route('/declare_winner', methods=['POST'])
@token_required
def declare_winner_api(current_user_email):
    data = request.get_json()
    contest_id = data.get('contest_id')
    user_id = data.get('user_id')
    amount = data.get('amount')

    if not contest_id or not user_id or amount is None:
        return jsonify({"message": "Missing contest_id, user_id, or amount"}), 400

    try:
        with mysql_cursor() as cursor:
            cursor.execute("SELECT id FROM contests WHERE id = %s", (contest_id,))
            contest = cursor.fetchone()
            if not contest:
                return jsonify({"message": "Contest not found"}), 404

            cursor.execute("SELECT id FROM users WHERE id = %s", (user_id,))
            user = cursor.fetchone()
            if not user:
                return jsonify({"message": "User not found"}), 404

            cursor.execute("SELECT balance FROM wallets WHERE user_id = %s", (user_id,))
            wallet = cursor.fetchone()
            if not wallet:
                return jsonify({"message": "Wallet not found"}), 404

            new_balance = wallet[0] + amount
            cursor.execute("UPDATE wallets SET balance = %s WHERE user_id = %s", (new_balance, user_id))

        db.commit()
        return jsonify({"message": f"Prize money ₹{amount} added to user {user_id} wallet!"})
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500








@app.route('/wallet/topup', methods=['POST'])
@token_required
def wallet_topup(current_user_email):
    data = request.get_json()
    
    try:
        amount = Decimal(str(data.get('amount', 0)))  # Safely cast to Decimal
    except Exception:
        return jsonify({"message": "Invalid amount"}), 400

    if amount <= 0:
        return jsonify({"message": "Invalid amount"}), 400

    try:
        with mysql_cursor(dictionary=False) as cursor:
            cursor.execute("SELECT id FROM users WHERE email = %s", (current_user_email,))
            user = cursor.fetchone()
            if not user:
                return jsonify({"message": "User not found"}), 404
            user_id = user[0]

            # Update wallet balance
            cursor.execute("UPDATE wallets SET balance = balance + %s WHERE user_id = %s", (amount, user_id))

            # Log transaction
            cursor.execute("""
                INSERT INTO transactions (user_id, amount, type, description)
                VALUES (%s, %s, 'credit', 'Wallet top-up')
            """, (user_id, amount))

            # Optional notification
            cursor.execute("""
                INSERT INTO notifications (user_id, message)
                VALUES (%s, %s)
            """, (user_id, f"₹{amount:.2f} added to your wallet successfully."))

        return jsonify({"message": f"Wallet topped up with ₹{amount} successfully."})

    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500


@app.route('/admin/statistics', methods=['GET', 'OPTIONS'])
@token_required
def admin_statistics(current_user_email):
    # 1) CORS preflight
    if request.method == 'OPTIONS':
        return make_response('', 204)

    # 2) Only admins allowed
    if not is_admin_user(current_user_email):
        return jsonify({"message": "Unauthorized"}), 403

    try:
        with mysql_cursor() as cursor:
            # Total users
            cursor.execute("SELECT COUNT(*) FROM users")
            total_users = cursor.fetchone()[0] or 0

            # Total matches
            cursor.execute("SELECT COUNT(*) FROM matches")
            total_matches = cursor.fetchone()[0] or 0

            # Total contests & active contests
            cursor.execute("SELECT COUNT(*), SUM(status='active') FROM contests")
            total_contests, active_contests = cursor.fetchone()
            total_contests  = total_contests or 0
            active_contests = active_contests or 0

            # Prize distributed
            cursor.execute("SELECT COALESCE(SUM(prize_pool), 0) FROM contests")
            total_prize_distributed = float(cursor.fetchone()[0])

            # Commission earned
            cursor.execute("""
                SELECT COALESCE(SUM(entry_fee * joined_users * commission_percentage / 100), 0)
                FROM contests
            """)
            total_commission_earned = float(cursor.fetchone()[0])

        return jsonify({
            "total_users":               total_users,
            "total_matches":             total_matches,
            "total_contests":            total_contests,
            "active_contests":           active_contests,
            "total_prize_distributed":   round(total_prize_distributed, 2),
            "total_commission_earned":   round(total_commission_earned, 2)
        }), 200

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500



@app.route('/admin/commission_report', methods=['GET'])
@token_required
def commission_report(current_user_email):
    if not is_admin_user(current_user_email):
        return jsonify({"message": "Unauthorized"}), 403

    try:
        with mysql_cursor(dictionary=True) as cursor:
            cursor.execute("""
                SELECT 
                    c.id AS contest_id,
                    c.name AS contest_name,
                    c.entry_fee,
                    c.commission_percentage,
                    COUNT(e.id) AS total_entries,
                    ROUND(COUNT(e.id) * c.entry_fee * (c.commission_percentage / 100), 2) AS commission_earned
                FROM contests c
                JOIN entries e ON c.id = e.contest_id
                GROUP BY c.id, c.name, c.entry_fee, c.commission_percentage
            """)
            data = cursor.fetchall()
        return jsonify(data)

    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500


@app.route('/admin/platform_stats', methods=['GET'])
@token_required
def admin_platform_stats(current_user_email):
    # ✅ Check if user is admin
    if not is_admin_user(current_user_email):
        return jsonify({"message": "Unauthorized"}), 403

    try:
        with mysql_cursor(dictionary=True) as cursor:
            # 🔹 Total registered users
            cursor.execute("SELECT COUNT(*) AS total_users FROM users")
            total_users = cursor.fetchone()['total_users']

            # 🔹 Total contests
            cursor.execute("SELECT COUNT(*) AS total_contests FROM contests")
            total_contests = cursor.fetchone()['total_contests']

            # 🔹 Total prize pool distributed (only from completed contests)
            cursor.execute("""
                SELECT IFNULL(SUM(prize_pool), 0) AS total_prize_distributed
                FROM contests
                WHERE status = 'prizes_distributed'
            """)
            total_prize_distributed = float(cursor.fetchone()['total_prize_distributed'])

            # 🔹 Total commission earned
            cursor.execute("""
                SELECT IFNULL(SUM(prize_pool * commission_percentage / 100), 0) AS total_commission
                FROM contests
                WHERE status = 'prizes_distributed'
            """)
            total_commission = float(cursor.fetchone()['total_commission'])

            # 🔹 Total wallet top-ups
            cursor.execute("""
                SELECT IFNULL(SUM(amount), 0) AS total_topups
                FROM transactions
                WHERE type = 'credit' AND description LIKE '%Top-up%'
            """)
            total_topups = float(cursor.fetchone()['total_topups'])

            # 🔹 Total withdrawal requests
            cursor.execute("SELECT COUNT(*) AS total_withdrawals FROM withdrawals")
            total_withdrawals = cursor.fetchone()['total_withdrawals']

            # 🔹 Total withdrawals approved
            cursor.execute("""
                SELECT IFNULL(SUM(amount), 0) AS approved_withdrawals
                FROM withdrawals
                WHERE status = 'approved'
            """)
            approved_withdrawals = float(cursor.fetchone()['approved_withdrawals'])

        return jsonify({
            "total_users": total_users,
            "total_contests": total_contests,
            "total_prize_distributed": total_prize_distributed,
            "total_commission_earned": total_commission,
            "total_wallet_topups": total_topups,
            "total_withdrawal_requests": total_withdrawals,
            "total_withdrawals_approved": approved_withdrawals
        })

    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500




@app.route('/my_contest_history', methods=['GET'])
@token_required
def my_contest_history(current_user_email):
    try:
        with mysql_cursor(dictionary=True) as cursor:
            # Get user ID
            cursor.execute("SELECT id FROM users WHERE email = %s", (current_user_email,))
            user = cursor.fetchone()
            if not user:
                return jsonify({"message": "User not found"}), 404
            user_id = user['id']

            # Get contests joined by user along with stats
            cursor.execute("""
                SELECT 
                    c.id AS contest_id,
                    c.name AS contest_name,
                    c.entry_fee,
                    c.prize_pool,
                    c.status AS contest_status,
                    m.match_name,
                    m.start_time,
                    t.id AS team_id,
                    t.total_points,
                    th.amount AS winning_amount,
                    th.description
                FROM entries e
                JOIN contests c ON e.contest_id = c.id
                JOIN teams t ON e.team_id = t.id
                JOIN matches m ON c.match_id = m.id
                LEFT JOIN transaction_history th 
                    ON th.user_id = e.user_id 
                    AND th.description LIKE CONCAT('%contest ', c.id)
                    AND th.transaction_type = 'credit'
                WHERE e.user_id = %s
                ORDER BY c.start_time DESC
            """, (user_id,))
            history = cursor.fetchall()

        return jsonify({"history": history})

    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500


@app.route('/contest_result/<int:contest_id>', methods=['GET'])
@token_required
def get_contest_result(current_user_email, contest_id):
    try:
        with mysql_cursor(dictionary=True) as cursor:
            # Get contest entries with user, team, and points
            query = """
                SELECT u.name as user_name, t.team_name, t.total_points
                FROM entries e
                JOIN users u ON e.user_id = u.id
                JOIN teams t ON e.team_id = t.id
                WHERE e.contest_id = %s
                ORDER BY t.total_points DESC
            """
            cursor.execute(query, (contest_id,))
            results = cursor.fetchall()

        # Add ranks
        for i, row in enumerate(results, start=1):
            row['rank'] = i

        return jsonify({"results": results}), 200

    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500

@app.route('/admin/dashboard', methods=['GET'])
@token_required
def admin_dashboard(current_user_email):
    if not is_admin_user(current_user_email):
        return jsonify({"message": "Unauthorized"}), 403

    try:
        with mysql_cursor(dictionary=True) as cursor:

            # Users, Matches, Contests
            cursor.execute("SELECT COUNT(*) AS count FROM users")
            total_users = cursor.fetchone()['count']

            cursor.execute("SELECT COUNT(*) AS count FROM matches")
            total_matches = cursor.fetchone()['count']

            cursor.execute("SELECT COUNT(*) AS count FROM contests")
            total_contests = cursor.fetchone()['count']

            cursor.execute("SELECT COUNT(*) AS count FROM contests WHERE status = 'active'")
            active_contests = cursor.fetchone()['count']

            # Total prize distributed (sum of all winning amounts)
            cursor.execute("SELECT SUM(prize) AS total FROM entries WHERE prize IS NOT NULL")
            prize_total = cursor.fetchone()['total'] or 0

            # Platform earnings from commissions
            cursor.execute("SELECT SUM(commission_amount) AS total FROM platform_earnings")
            commission_total = cursor.fetchone()['total'] or 0

        return jsonify({
            "total_users": total_users,
            "total_matches": total_matches,
            "total_contests": total_contests,
            "active_contests": active_contests,
            "total_prize_distributed": float(prize_total),
            "total_commission_earned": float(commission_total)
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/admin/get_matches', methods=['GET'])
@token_required
def admin_get_matches(current_user_email):
    if not is_admin_user(current_user_email):
        return jsonify({"message": "Unauthorized"}), 403

    try:
        with mysql_cursor(dictionary=True) as cursor:
            cursor.execute("SELECT * FROM matches ORDER BY start_time DESC")
            return jsonify(cursor.fetchall()), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500



@app.route('/admin/create_match', methods=['POST'])
@token_required
def admin_create_match(current_user_email):
    if not is_admin_user(current_user_email):
        return jsonify({"message": "Unauthorized"}), 403

    data = request.get_json()
    required_fields = ['match_name', 'start_time', 'end_time']
    if not all(data.get(k) for k in required_fields):
        return jsonify({"message": "Missing required fields"}), 400

    try:
        match_name = data['match_name']
        start_time = data['start_time']
        end_time = data['end_time']
        status = data.get('status', 'UPCOMING')

        with mysql_cursor(dictionary=True) as cur:

            # Step 1: Insert match
            cur.execute("""
                INSERT INTO matches (match_name, start_time, end_time, status)
                VALUES (%s, %s, %s, %s)
            """, (match_name, start_time, end_time, status))
            match_id = cur.lastrowid

            # Step 2: Parse teams
            sides = [s.strip().lower().replace(" ", "").replace("_", "") for s in re.split(r'vs|VS|Vs|vS', match_name) if s.strip()]
            if len(sides) != 2:
                return jsonify({"message": "❌ Could not parse 2 teams from match_name"}), 400

            team_map = {
                "ind": "India", "india": "India",
                "pak": "Pakistan", "pakistan": "Pakistan",
                "aus": "Australia", "australia": "Australia",
                "eng": "England", "england": "England",
                "sa": "South Africa", "southafrica": "South Africa", "south_africa": "South Africa",
                "nz": "New Zealand", "newzealand": "New Zealand", "new_zealand": "New Zealand",
                "sl": "Sri Lanka", "srilanka": "Sri Lanka", "sri_lanka": "Sri Lanka",
                "ban": "Bangladesh", "bangladesh": "Bangladesh",
                "afg": "Afghanistan", "afghanistan": "Afghanistan",
                "wi": "West Indies", "westindies": "West Indies", "west_indies": "West Indies",
                "zim": "Zimbabwe", "zimbabwe": "Zimbabwe",
                "nam": "Namibia", "namibia": "Namibia",
                "uae": "UAE", "nepal": "Nepal",
                "ire": "Ireland", "ireland": "Ireland",
                "sco": "Scotland", "scotland": "Scotland",
                "ned": "Netherlands", "netherlands": "Netherlands"
            }

            team1 = team_map.get(sides[0])
            team2 = team_map.get(sides[1])
            if not team1 or not team2:
                return jsonify({"message": f"❌ Unknown team(s) in match_name: {match_name}"}), 400

            # Step 3: Fetch players from template_players
            cur.execute("""
                SELECT * FROM template_players
                WHERE team_name IN (%s, %s)
            """, (team1, team2))
            template_players = cur.fetchall()

            if not template_players:
                return jsonify({"message": f"No template players found for teams {team1} and {team2}"}), 404

            # Step 4: Insert into players table
            for p in template_players:
                cur.execute("""
                    INSERT INTO players (
                        match_id, player_name, role, team_name, credit_value, is_playing, position,
                        fantasy_points, batting_style, bowling_style, nationality,
                        player_type, team_id, image, country
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    match_id,
                    p['player_name'], p['role'], p['team_name'], p['credit_value'], p['is_playing'],
                    p['position'], p['fantasy_points'], p['batting_style'], p['bowling_style'],
                    p['nationality'], p['player_type'], p['team_id'], p['image'], p['country']
                ))

        db.commit()
        return jsonify({"message": "✅ Match and players added successfully", "match_id": match_id}), 201

    except Exception as e:
        db.rollback()
        app.logger.exception("Error creating match")
        return jsonify({"error": str(e)}), 500


@app.route('/admin/delete_contest', methods=['POST'])
@token_required
def admin_delete_contest(current_user_email):
    if not is_admin_user(current_user_email):
        return jsonify({"message": "Unauthorized"}), 403

    data = request.get_json()
    contest_id = data.get('id')
    force = data.get('force', False)

    if not contest_id:
        return jsonify({"message": "Contest ID required"}), 400

    try:
        with mysql_cursor(dictionary=False) as cursor:
            if force:
                print(f"⚠️ Force deleting contest {contest_id} — including entries")
                cursor.execute("DELETE FROM entries WHERE contest_id = %s", (contest_id,))

            cursor.execute("DELETE FROM contests WHERE id = %s", (contest_id,))

        db.commit()
        return jsonify({"message": "✅ Contest deleted successfully!"})

    except Exception as err:
        db.rollback()
        print("❌ Delete contest error:", err)
        return jsonify({"error": str(err)}), 500


@app.route('/admin/contest/<int:contest_id>/entries', methods=['GET'])
@token_required
def admin_list_entries(current_user_email, contest_id):
    if not is_admin_user(current_user_email):
        return jsonify({"message": "Unauthorized"}), 403

    try:
        with mysql_cursor(dictionary=True) as cursor:
            cursor.execute("""
                SELECT e.id AS entry_id, e.team_id, e.user_id, e.joined_at,
                       u.username AS user_name,
                       t.team_name AS team_name
                FROM entries e
                LEFT JOIN users u ON e.user_id = u.id
                LEFT JOIN teams t ON e.team_id = t.id
                WHERE e.contest_id = %s
                ORDER BY e.joined_at ASC
            """, (contest_id,))
            entries = cursor.fetchall()

        return jsonify(entries), 200

    except Exception as err:
        print(f"🔥 Error loading entries for contest {contest_id}:", err)
        return jsonify({"error": str(err)}), 500

@app.route('/admin/delete_match', methods=['POST'])
@token_required
def delete_match(current_user_email):
    if not is_admin_user(current_user_email):
        return jsonify({"message": "Unauthorized"}), 403

    data = request.get_json()
    match_id = data.get('id')
    if not match_id:
        return jsonify({"message": "Missing match ID"}), 400

    try:
        with mysql_cursor() as cur:
            # Step 1: Get all contest_ids for this match
            cur.execute("SELECT id FROM contests WHERE match_id = %s", (match_id,))
            contest_ids = [row[0] for row in cur.fetchall()]

            if contest_ids:
                in_clause = ','.join(['%s'] * len(contest_ids))

                # Step 2: Delete entries
                cur.execute(f"DELETE FROM entries WHERE contest_id IN ({in_clause})", contest_ids)

                # Step 3: Delete prize distributions
                cur.execute(f"DELETE FROM prize_distributions WHERE contest_id IN ({in_clause})", contest_ids)

                # Step 4: Delete contests
                cur.execute(f"DELETE FROM contests WHERE id IN ({in_clause})", contest_ids)

            # Step 5: Delete players of this match
            cur.execute("DELETE FROM players WHERE match_id = %s", (match_id,))

            # Step 6: Delete match
            cur.execute("DELETE FROM matches WHERE id = %s", (match_id,))

        db.commit()
        return jsonify({"message": "✅ Match and all related data deleted successfully"}), 200

    except Exception as e:
        db.rollback()
        app.logger.exception("❌ Failed to delete match")
        return jsonify({"message": "Internal server error"}), 500


@app.route('/admin/team/<int:id>', methods=['GET'])
@token_required
def admin_team_details(current_user_email, id):
    if not is_admin_user(current_user_email):
        return jsonify({"message": "Unauthorized"}), 403

    try:
        with mysql_cursor(dictionary=True) as cursor:
            print("🔍 Fetching team with ID:", id)

            cursor.execute("SELECT team_name, players FROM teams WHERE id = %s", (id,))
            team = cursor.fetchone()
            print("🧠 Raw team:", team)

            if not team:
                return jsonify({"message": "Team not found"}), 404

            import json
            try:
                player_list = json.loads(team["players"])
            except json.JSONDecodeError as err:
                print("❌ JSON decode error:", err)
                player_list = []

            return jsonify({
                "id": id,
                "team_name": team["team_name"],
                "players": player_list
            }), 200

    except Exception as err:
        print("🔥 DB error:", err)
        return jsonify({"error": str(err)}), 500


@app.route('/admin/users', methods=['GET'])
@token_required
def get_admin_users(current_user_email):
    if not is_admin_user(current_user_email):
        return jsonify({"message": "Unauthorized"}), 403

    try:
        with mysql_cursor(dictionary=True) as cursor:
            # 1) Fetch user details and wallet summary
            cursor.execute("""
                SELECT 
                    u.id,
                    u.username,
                    u.email,
                    u.is_admin,
                    u.is_banned,
                    u.registered_at,
                    COALESCE(w.balance, 0) AS balance,
                    IFNULL((SELECT SUM(amount) FROM transactions 
                            WHERE user_id = u.id AND type = 'credit'), 0) AS total_earning,
                    IFNULL((SELECT SUM(amount) FROM transactions 
                            WHERE user_id = u.id AND type = 'debit'), 0) AS total_loss,
                    IFNULL((SELECT COUNT(*) FROM entries WHERE user_id = u.id), 0) AS contest_count,
                    (SELECT MAX(joined_at) FROM entries WHERE user_id = u.id) AS last_contest_date
                FROM users u
                LEFT JOIN wallets w ON u.id = w.user_id
            """)
            
            users = cursor.fetchall()

            # 2) Build each user's 7-day credit/debit net trend
            for u in users:
                cursor.execute("""
                    SELECT 
                        DATE(created_at) AS day,
                        SUM(
                            CASE 
                                WHEN type = 'credit' THEN amount
                                ELSE -amount
                            END
                        ) AS net
                    FROM transactions
                    WHERE user_id = %s
                      AND created_at >= NOW() - INTERVAL 7 DAY
                    GROUP BY day
                    ORDER BY day ASC
                """, (u["id"],))
                trend = cursor.fetchall()
                u["daily_trend"] = [
                    {
                        "day": row["day"].strftime("%a"),
                        "net": float(row["net"] or 0)
                    }
                    for row in trend
                ]

            # 3) Prepare JSON response for frontend
            return jsonify([
                {
                    "user_id":         u["id"],
                    "name":            u["username"],
                    "email":           u["email"],
                    "wallet":          float(u["balance"]),
                    "is_admin":        bool(u["is_admin"]),
                    "is_banned":       bool(u["is_banned"]),
                    "total_earning":   float(u["total_earning"]),
                    "total_loss":      float(u["total_loss"]),
                    "contest_count":   int(u["contest_count"]),
                    "last_contest_date": u["last_contest_date"],
                    "registered_at":   u["registered_at"],
                    "daily_trend":     u["daily_trend"]
                }
                for u in users
            ])

    except Exception as err:
        print("🔥 DB error:", err)
        return jsonify({"error": str(err)}), 500



@app.route('/admin/reset_password', methods=['POST'])
@token_required
def admin_password_reset(current_user_email):
    if not is_admin_user(current_user_email):
        return jsonify({'message': 'Unauthorized'}), 403

    data = request.get_json()
    user_id = data.get("user_id")
    new_password = data.get("new_password")

    hashed = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

    with mysql_cursor() as cursor:
        cursor.execute("UPDATE users SET password = %s WHERE id = %s", (hashed, user_id))
    db.commit()

    return jsonify({"message": f"Password for user #{user_id} has been reset ✅"})

@app.route('/admin/user_earnings/<int:user_id>', methods=['GET'])
@token_required
def get_user_earnings(user_id):
    try:
        with mysql_cursor(dictionary=True) as cursor:
            cursor.execute("""
                SELECT type, amount, message, timestamp
                FROM transactions
                WHERE user_id = %s
                ORDER BY timestamp DESC
            """, (user_id,))
            history = cursor.fetchall()

        total_earnings = sum(t["amount"] for t in history if t["type"] == "credit")
        total_losses = sum(t["amount"] for t in history if t["type"] == "debit")

        return jsonify({
            "total_earnings": round(total_earnings, 2),
            "total_losses": round(total_losses, 2),
            "history": history
        })
    except Exception as err:
        print("🔥 Earnings fetch error:", err)
        return jsonify({"error": str(err)}), 500


@app.route('/admin/wallet_adjust', methods=['POST', 'OPTIONS'])
@token_required
def adjust_wallet(current_user_email):
    if request.method == 'OPTIONS':
        return make_response('', 204)

    if not is_admin_user(current_user_email):
        return jsonify({"message": "Unauthorized"}), 403

    try:
        data    = request.get_json(force=True)
        user_id = data['user_id']
        amount  = float(data['amount'])
        note    = data.get('note', '')

        with mysql_cursor() as cursor:
            cursor.execute(
                "UPDATE wallets SET balance = balance + %s WHERE user_id = %s",
                (amount, user_id)
            )
            if cursor.rowcount == 0:
                cursor.execute(
                    "INSERT INTO wallets (user_id, balance) VALUES (%s, %s)",
                    (user_id, amount)
                )

            cursor.execute(
                "INSERT INTO transactions (user_id, type, amount, description) "
                "VALUES (%s, %s, %s, %s)",
                (user_id, "credit" if amount > 0 else "debit", abs(amount), note)
            )

        db.commit()
        return jsonify({"message": "Wallet adjusted"}), 200

    except Exception as e:
        db.rollback()
        print("❌ WALLET_ADJUST ERROR:", e)
        return jsonify({"error": str(e)}), 500


@app.route('/admin/toggle_admin', methods=['POST'])
@token_required
def toggle_admin(current_user_email):
    data = request.get_json()
    user_id = data['user_id']
    try:
        with mysql_cursor() as cursor:
            cursor.execute("""
                UPDATE users 
                SET is_admin = 1 - is_admin 
                WHERE id = %s
            """, (user_id,))
        db.commit()
        return jsonify({"message": "Admin status toggled"}), 200
    except Exception as e:
        db.rollback()
        return jsonify({"error": str(e)}), 500

@app.route('/admin/ban_user', methods=['POST'])
@token_required
def ban_user(current_user_email):
    if not is_admin_user(current_user_email):
        return jsonify({"message": "Unauthorized"}), 403

    data = request.get_json()
    user_id = data.get('user_id')
    if not user_id:
        return jsonify({"message": "user_id required"}), 400

    try:
        with mysql_cursor() as cursor:
            cursor.execute("SELECT is_banned FROM users WHERE id = %s", (user_id,))
            row = cursor.fetchone()
            if not row:
                return jsonify({"message": "User not found"}), 404

            new_flag = 1 - int(row[0])

            cursor.execute(
                "UPDATE users SET is_banned = %s WHERE id = %s",
                (new_flag, user_id)
            )
        db.commit()
        return jsonify({
            "message": "Ban status updated",
            "is_banned": bool(new_flag)
        }), 200

    except Exception as e:
        db.rollback()
        return jsonify({"message": str(e)}), 500

@app.route('/admin/user_transactions/<int:user_id>', methods=['GET','OPTIONS'])
@token_required
def get_user_transactions(current_user_email, user_id):
    if request.method == 'OPTIONS':
        return make_response('', 204)

    if not is_admin_user(current_user_email):
        return jsonify({"message": "Unauthorized"}), 403

    try:
        with mysql_cursor(dictionary=True) as cursor:
            cursor.execute("""
                SELECT created_at, type, amount, description
                FROM transactions
                WHERE user_id = %s
                ORDER BY created_at DESC
            """, (user_id,))
            rows = cursor.fetchall()

            total_earn = 0.0
            total_loss = 0.0
            enriched   = []

            for r in rows:
                amt = float(r['amount'] or 0)
                if r['type'] == 'credit':
                    total_earn += amt
                else:
                    total_loss += amt

                contest_name = ''
                match_title  = ''
                desc = r.get('description') or ''

                if r['type'] == 'debit' and 'Joined contest ID' in desc:
                    try:
                        cid = int(desc.split('Joined contest ID')[1].strip())

                        cursor.execute("""
                            SELECT contest_name, match_id
                            FROM contests
                            WHERE id = %s
                        """, (cid,))
                        cm = cursor.fetchone()
                        if cm:
                            contest_name = cm['contest_name'] or ''
                            mid = cm['match_id']
                            if mid:
                                cursor.execute("""
                                    SELECT match_name
                                    FROM matches
                                    WHERE id = %s
                                """, (mid,))
                                mm = cursor.fetchone()
                                if mm:
                                    match_title = mm['match_name'] or ''
                    except Exception:
                        pass  # skip if anything fails

                enriched.append({
                    "created_at":   r['created_at'].isoformat(),
                    "type":         r['type'],
                    "amount":       amt,
                    "description":  desc,
                    "contest_name": contest_name,
                    "match_title":  match_title
                })

        return jsonify({
            "transactions": enriched,
            "total_earn":   round(total_earn, 2),
            "total_loss":   round(total_loss, 2)
        }), 200

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500



    

@app.route('/admin/commissions', methods=['GET', 'OPTIONS'])
@token_required
def commissions(current_user_email):
    if request.method == 'OPTIONS':
        return make_response('', 204)

    if not is_admin_user(current_user_email):
        return jsonify({'message': 'Unauthorized'}), 403

    try:
        with mysql_cursor(dictionary=True) as cur:
            cur.execute("""
                SELECT
                    c.id                    AS contest_id,
                    c.contest_name,
                    c.entry_fee,
                    c.joined_users,
                    c.commission_percentage,
                    m.match_name            AS match_name,
                    (c.entry_fee * c.joined_users * c.commission_percentage / 100) AS commission
                FROM contests c
                JOIN matches m ON c.match_id = m.id
                ORDER BY commission DESC
            """)
            rows = cur.fetchall()

        result = [{
            'contest_id':             r['contest_id'],
            'contest_name':           r['contest_name'],
            'entry_fee':              float(r['entry_fee'] or 0),
            'joined_users':           int(r['joined_users'] or 0),
            'commission_percentage':  float(r['commission_percentage'] or 0),
            'match_name':             r['match_name'],
            'commission':             round(float(r['commission'] or 0), 2)
        } for r in rows]

        return jsonify(result), 200

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/admin/prize_distributions', methods=['GET', 'OPTIONS'])
@token_required
def prize_distributions(current_user_email):
    if request.method == 'OPTIONS':
        return make_response('', 204)

    if not is_admin_user(current_user_email):
        return jsonify({'message': 'Unauthorized'}), 403

    try:
        with mysql_cursor(dictionary=True) as cur:
            cur.execute("""
                SELECT
                  t.id,
                  t.user_id,
                  u.username,
                  t.amount,
                  t.description,
                  t.created_at AS date
                FROM transactions t
                JOIN users u ON t.user_id = u.id
                WHERE t.type = 'credit'
                ORDER BY t.created_at DESC
            """)
            rows = cur.fetchall()

        result = [{
            'id':          r['id'],
            'user_id':     r['user_id'],
            'username':    r['username'] or '',
            'amount':      float(r['amount'] or 0),
            'description': r['description'] or '',
            'date':        r['date'].isoformat()
        } for r in rows]

        return jsonify(result), 200

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500



# 2. Dashboard (upcomingMatches + user wallet)
from datetime import datetime, timedelta
from flask import jsonify, request
import mysql.connector

@app.route('/user/dashboard', methods=['GET'])
@token_required
def user_dashboard(current_user_email):
    try:
        days = int(request.args.get('range', 7))
        since = datetime.utcnow() - timedelta(days=days)

        conn = get_db_connection()
        try:
            with conn.cursor(dictionary=True) as cur:
                # 1) Get user_id
                cur.execute("SELECT id FROM users WHERE email=%s", (current_user_email,))
                user = cur.fetchone()
                if not user:
                    return jsonify({"message": "User not found"}), 404
                uid = user['id']

                # 2) Wallet balance
                cur.execute("SELECT balance FROM wallets WHERE user_id=%s", (uid,))
                row = cur.fetchone()
                wallet = float(row['balance'] or 0) if row else 0

                # 3) Earnings & spend & net in range
                cur.execute("""
                    SELECT 
                        SUM(CASE WHEN t.type='credit' THEN t.amount ELSE 0 END) AS earnings,
                        SUM(CASE WHEN t.type='debit'  THEN t.amount ELSE 0 END) AS spend
                    FROM transactions t
                    WHERE t.user_id=%s AND t.created_at >= %s
                """, (uid, since))
                stats = cur.fetchone()
                total_earnings = float(stats['earnings'] or 0)
                total_spend = float(stats['spend'] or 0)
                net_balance = total_earnings - total_spend

                # 4) Daily net history
                cur.execute("""
                    SELECT 
                        DATE(t.created_at) AS day,
                        SUM(CASE WHEN t.type='credit' THEN t.amount ELSE -t.amount END) AS net
                    FROM transactions t
                    WHERE t.user_id=%s AND t.created_at >= %s
                    GROUP BY day
                    ORDER BY day
                """, (uid, since))
                dailyNetHistory = [
                    {"day": r["day"].isoformat(), "net": float(r["net"])}
                    for r in cur.fetchall()
                ]

                # 5) Active contests
                cur.execute("""
                    SELECT 
                        uc.id AS entry_id,
                        c.id AS contest_id,
                        c.contest_name,
                        c.prize_pool
                    FROM user_contests uc
                    JOIN contests c ON uc.contest_id = c.id
                    JOIN matches m ON c.match_id = m.id
                    WHERE uc.user_id=%s 
                      AND UPPER(m.status) IN ('UPCOMING','LIVE')
                """, (uid,))
                activeContests = [
                    {
                        "entry_id": r["entry_id"],
                        "contest_id": r["contest_id"],
                        "contest_name": r["contest_name"],
                        "prize_pool": float(r["prize_pool"])
                    }
                    for r in cur.fetchall()
                ]

                # 6) Upcoming matches + contests
                cur.execute("""
                    SELECT
                        m.id AS match_id,
                        m.match_name,
                        m.start_time,
                        c.id AS contest_id,
                        c.contest_name,
                        c.prize_pool,
                        IFNULL(c.joined_users, 0) AS joined_users,
                        IFNULL(c.max_users, 0) AS max_users 
                    FROM matches m
                    JOIN contests c ON c.match_id = m.id
                    WHERE UPPER(m.status) = 'UPCOMING'
                    ORDER BY m.start_time, c.prize_pool DESC
                """)
                rows = cur.fetchall()
                matches = {}
                for r in rows:
                    mid = r["match_id"]
                    if mid not in matches:
                        matches[mid] = {
                            "id": mid,
                            "match_name": r["match_name"],
                            "start_time": r["start_time"].isoformat(),
                            "contests": []
                        }
                    matches[mid]["contests"].append({
                        "contest_id": r["contest_id"],
                        "contest_name": r["contest_name"],
                        "prize_pool": float(r["prize_pool"]),
                        "entries": int(r["joined_users"] or 0),
                        "max_entries": int(r["max_users"] or 0)
                    })

                # 7) User teams for upcoming matches
                cur.execute("""
                    SELECT 
                        t.id AS team_id,
                        t.team_name,
                        t.contest_id,
                        t.total_points,
                        t.players,
                        m.id AS match_id,
                        m.match_name
                    FROM teams t
                    JOIN contests c ON t.contest_id = c.id
                    JOIN matches m ON c.match_id = m.id
                    WHERE t.user_id = %s
                      AND UPPER(m.status) = 'UPCOMING'
                """, (uid,))
                userTeams = [
                    {
                        "team_id": r["team_id"],
                        "team_name": r["team_name"],
                        "match_id": r["match_id"],
                        "match_name": r["match_name"],
                        "contest_id": r["contest_id"],
                        "total_points": r["total_points"],
                        "players": r["players"]
                    }
                    for r in cur.fetchall()
                ]
        finally:
            conn.close()

        return jsonify({
            "wallet_balance": wallet,
            "total_earnings": total_earnings,
            "total_spend": total_spend,
            "net_balance": net_balance,
            "dailyNetHistory": dailyNetHistory,
            "activeContests": activeContests,
            "upcomingMatches": list(matches.values()),
            "userTeams": userTeams,
            "user_email": current_user_email
        }), 200

    except mysql.connector.Error as err:
        app.logger.error("DB error: %s", err)
        return jsonify({"message": "Database error", "error": str(err)}), 500

    except Exception as e:
        app.logger.exception("Server error")
        return jsonify({"message": "Internal server error", "error": str(e)}), 500



@app.route('/match/<int:match_id>/generate-team', methods=['POST', 'OPTIONS'])
@token_required
def generate_team(current_user_email, match_id):
    if request.method == 'OPTIONS':
        return '', 204

    # ─── AI SQUAD BUILDER ──────────────────────────────────────────────
    def pick_team(pool, must_have=None, captain=None, vice_captain=None):
        import random, time, logging
        from collections import Counter

        random.seed(f"{time.time_ns()}-{random.random()}")

        # 1) Role quotas
        quotas = {'batsman': 4, 'bowler': 3, 'allrounder': 2, 'keeper': 1}

        # 2) Partition pool by role
        batsmen     = [p for p in pool if p['role'] == 'batsman']
        bowlers     = [p for p in pool if p['role'] == 'bowler']
        allrounders = [p for p in pool if p['role'] == 'allrounder']
        keepers     = [p for p in pool if p['role'] == 'keeper']

        # 3) Pool sufficiency check
        if (len(batsmen) < quotas['batsman'] or
            len(bowlers) < quotas['bowler'] or
            len(allrounders) < quotas['allrounder'] or
            len(keepers) < quotas['keeper']):
            logging.error("🧠 pick_team: pool cannot satisfy base quotas")
            return None

        team            = []
        selected_names  = set()
        team_counter    = Counter()

        # 4) Force-captain
        if captain:
            cap = next((p for p in pool if p['player_name'] == captain), None)
            if not cap:
                return None
            team.append(cap)
            selected_names.add(captain)
            quotas[cap['role']] -= 1
            if cap.get('team_name'):
                team_counter[cap['team_name']] += 1

        # 5) Force-vice-captain
        if vice_captain:
            vc = next((p for p in pool if p['player_name'] == vice_captain), None)
            if not vc or vice_captain == captain:
                return None
            team.append(vc)
            selected_names.add(vice_captain)
            quotas[vc['role']] -= 1
            if vc.get('team_name'):
                team_counter[vc['team_name']] += 1

        # 6) Must-have picks
        for name in (must_have or []):
            if name in selected_names:
                continue
            m = next((p for p in pool if p['player_name'] == name), None)
            if not m:
                return None
            team.append(m)
            selected_names.add(name)
            quotas[m['role']] -= 1
            if m.get('team_name'):
                team_counter[m['team_name']] += 1

        # 7) Quota violation check
        if any(v < 0 for v in quotas.values()):
            logging.error("🧠 pick_team: forced picks exceed role quotas")
            return None

        # 8) Helper to fill remaining slots
        def fill(group, count):
            sel, attempts = [], 0
            while len(sel) < count and attempts < 30:
                p = random.choice(group)
                nm, tn = p['player_name'], p.get('team_name')
                if nm not in selected_names and (not tn or team_counter[tn] < 11):
                    sel.append(p)
                    selected_names.add(nm)
                    if tn:
                        team_counter[tn] += 1
                attempts += 1
            return sel

        # 9) Fill each role up to quota
        team += fill(batsmen,     quotas['batsman'])
        team += fill(bowlers,     quotas['bowler'])
        team += fill(allrounders, quotas['allrounder'])
        team += fill(keepers,     quotas['keeper'])

        # 10) Ensure 10 before final slot
        if len(team) < sum([4, 3, 2, 1]):
            logging.error("🧠 pick_team: couldn't reach base roster of 10")
            return None

        # 11) Final slot (no second keeper)
        import random as _r
        remaining = [p for p in pool if p['player_name'] not in selected_names]
        _r.shuffle(remaining)
        for p in remaining:
            if p['role'] == 'keeper':
                continue
            nm, tn = p['player_name'], p.get('team_name')
            if nm not in selected_names and (not tn or team_counter[tn] < 11):
                team.append(p)
                selected_names.add(nm)
                break

        # 12) Validate 11 players
        if len(team) != 11:
            logging.error("🧠 pick_team: final roster not size 11")
            return None

        # 13) Assign captain & vice-captain (forced or random)
        if not captain:
            cap = random.choice(team)
        if not vice_captain:
            candidates = [p for p in team if p['player_name'] != cap['player_name']]
            vc = random.choice(candidates) if candidates else cap

        for p in team:
            p['is_captain']      = (p['player_name'] == cap['player_name'])
            p['is_vice_captain'] = (p['player_name'] == vc['player_name'])

        logging.warning(f"✅ pick_team generated: {[p['player_name'] for p in team]}")
        return team

    # ─── Main Handler ─────────────────────────────────────────────────
    try:
        import json, traceback
        from collections import Counter

        data            = request.get_json() or {}
        contest_id      = data.get("contest_id")
        num_teams       = data.get("num_teams", 1)
        mode            = data.get("generation_mode", "auto")
        raw_must_have   = data.get("must_have", [])
        must_have       = [n.strip() for n in raw_must_have if n.strip()]
        captain         = data.get("captain")
        vice_captain    = data.get("vice_captain")

        # 1) Basic validation
        if not contest_id or not match_id:
            return jsonify({"message": "contest_id and match_id required"}), 400
        if num_teams > 100:
            return jsonify({"message": "Max 100 AI teams per request"}), 400

        # 2) Fetch user
        cur = db.cursor(dictionary=True)
        cur.execute(
            "SELECT id FROM users WHERE email=%s",
            (current_user_email,)
        )
        user = cur.fetchone()
        if not user:
            return jsonify({"message": "User not found"}), 404
        user_id = user["id"]

        # 3) Load player pool
        cur.execute(
            """
            SELECT 
                id, 
                player_name, 
                LOWER(
                    CASE 
                        WHEN role = 'Wicket-Keeper' THEN 'keeper'
                        WHEN role = 'All-Rounder' THEN 'allrounder'
                        ELSE role
                    END
                ) AS role,
                credit_value, 
                team_name
            FROM players 
            WHERE match_id=%s
            """,
            (match_id,)
        )

        pool = cur.fetchall()
        if not pool:
            return jsonify({"message": "No players found for this match"}), 404

        # 4) Must-have sanity (only for mustHave mode)
        if mode == "mustHave":
            mh_counts = Counter()
            missing   = []
            for name in must_have:
                p = next((pl for pl in pool if pl["player_name"] == name), None)
                if not p:
                    missing.append(name)
                else:
                    mh_counts[p["role"]] += 1

            violations = []
            if mh_counts["keeper"] > 1:     violations.append("keeper > 1")
            if mh_counts["batsman"] > 3:    violations.append("batsman > 3")
            if mh_counts["bowler"] > 3:     violations.append("bowler > 3")
            if mh_counts["allrounder"] > 3: violations.append("allrounder > 3")
            if missing:
                violations.append("not in match: " + ", ".join(missing))

            if violations:
                return jsonify({
                    "message": "Invalid must-have: " + "; ".join(violations)
                }), 400

        # 5) Count existing AI entries
        cur.execute(
            """
            SELECT COUNT(*) AS cnt 
            FROM entries 
            WHERE contest_id = %s AND user_id = %s
            """,
            (contest_id, user_id)
        )
        existing = cur.fetchone()["cnt"]

        # 6) Generate & insert teams
        existing_hashes = set()
        team_ids        = []
        last_strength   = 0

        for i in range(num_teams):
            squad = None
            for _ in range(50):
                squad = pick_team(
                    pool,
                    must_have=(must_have if mode == "mustHave" else []),
                    captain=(captain if mode == "capvice" else None),
                    vice_captain=(vice_captain if mode == "capvice" else None)
                )
                if not squad:
                    continue
                h = hash("".join(sorted(p["player_name"] for p in squad)))
                if h in existing_hashes:
                    continue
                existing_hashes.add(h)
                break

            if not squad:
                return jsonify({"message": "Could not build a valid squad"}), 400

            # normalize & compute strength
            for p in squad:
                p["credit_value"] = float(p["credit_value"])
                p["player_id"]    = p.get("id")
            last_strength = sum(p["credit_value"] for p in squad) + 2

            # insert team
            cur.execute(
                """
                INSERT INTO teams (team_name, players, user_id, contest_id, strength_score) 
                VALUES (%s, %s, %s, %s, %s)
                """,
                (f"AI Team {existing + i + 1}", json.dumps(squad, default=str), user_id, contest_id, last_strength)
            )
            team_id = cur.lastrowid

            # insert entry
            cur.execute(
                """
                INSERT INTO entries (contest_id, user_id, team_id) 
                VALUES (%s, %s, %s)
                """,
                (contest_id, user_id, team_id)
            )
            team_ids.append(team_id)

        db.commit()

        return jsonify({
            "success":            bool(team_ids),
            "team_ids":           team_ids,
            "team_id":            team_ids[0] if team_ids else None,
            "message":            f"{len(team_ids)} AI team(s) created ✔",
            "last_team_strength": last_strength
        }), (200 if team_ids else 400)

    except Exception as e:
        import traceback
        traceback.print_exc()
        app.logger.exception("🛑 AI team generation failed:")
        return jsonify({"message": "Internal Server Error"}), 500


# 3. List players for a match
@app.route('/match/<int:match_id>/players', methods=['GET'])
@token_required
def get_players_with_contest_stats(current_user_email, match_id):
    try:
        contest_id = request.args.get('contest_id', type=int)

        cur = db.cursor(dictionary=True)
        cur.execute("""
            SELECT id, player_name, role
            FROM players
            WHERE match_id = %s
        """, (match_id,))
        players = cur.fetchall()

        # Initialize counts
        for p in players:
            p['taken_count'] = 0
            p['taken_percent'] = 0

        if contest_id:
            cur.execute(
                "SELECT COUNT(*) AS total FROM entries WHERE contest_id = %s",
                (contest_id,)
            )
            total = cur.fetchone()['total'] or 0

            if total > 0:
                for p in players:
                    cur.execute("""
                        SELECT COUNT(*) AS cnt
                        FROM entries e
                        JOIN teams t ON e.team_id = t.id
                        WHERE e.contest_id = %s
                          AND JSON_CONTAINS(t.players, JSON_OBJECT('player_name', %s), '$')
                    """, (contest_id, p['player_name']))
                    cnt = cur.fetchone()['cnt'] or 0
                    p['taken_count'] = cnt
                    p['taken_percent'] = round(cnt * 100 / total)

        return jsonify({"players": players}), 200

    except Exception as e:
        app.logger.exception(e)
        return jsonify({"message": "Failed to load players"}), 500


@app.route('/user/contest/<int:contest_id>/entries')
@token_required
def user_entries(current_user_email, contest_id):
    try:
        cur = db.cursor(dictionary=True)

        # Get user ID and username
        cur.execute("SELECT id, username FROM users WHERE email = %s", (current_user_email,))
        user_row = cur.fetchone()
        if not user_row:
            return jsonify({"message": "User not found"}), 404

        user_id = user_row["id"]
        username = user_row["username"]

        # Fetch user entries
        cur.execute("""
            SELECT
                e.id,
                t.team_name,
                t.players,
                t.total_points,
                t.strength_score,
                t.rating, 
                e.joined_at,
                %s AS username,
                t.id AS team_id
            FROM entries e
            JOIN teams t ON e.team_id = t.id
            WHERE e.contest_id = %s AND e.user_id = %s
            ORDER BY e.joined_at DESC
        """, (username, contest_id, user_id))

        rows = cur.fetchall()
        return jsonify({"entries": rows})

    except Exception as e:
        app.logger.exception(e)
        return jsonify({"message": "Failed to load user entries"}), 500




@app.route('/user/team/<int:team_id>', methods=['GET', 'OPTIONS'])
@token_required
def get_user_team(current_user_email, team_id):
    if request.method == 'OPTIONS':
        return '', 204  # CORS preflight

    try:
        cur = db.cursor(dictionary=True)

        # Get user ID
        cur.execute("SELECT id FROM users WHERE email = %s", (current_user_email,))
        user_row = cur.fetchone()
        if not user_row:
            return jsonify({"message": "User not found"}), 404
        user_id = user_row["id"]

        # Get team only if belongs to user
        cur.execute("""
            SELECT team_name, players
            FROM teams
            WHERE id = %s AND user_id = %s
        """, (team_id, user_id))
        row = cur.fetchone()
        if not row:
            return jsonify({"message": "Team not found"}), 404

        import json
        players = json.loads(row["players"]) if row["players"] else []

        return jsonify({
            "team_name": row["team_name"],
            "players": players
        }), 200

    except Exception as e:
        app.logger.exception("🛑 Failed to load team:")
        return jsonify({"message": "Internal Server Error"}), 500


@app.route('/user/contest/<int:contest_id>/unjoined-teams')
@token_required
def unjoined_teams_for_user(current_user_email, contest_id):
    try:
        cur = db.cursor(dictionary=True)

        cur.execute("SELECT id FROM users WHERE email=%s", (current_user_email,))
        user = cur.fetchone()
        if not user:
            return jsonify({"message": "User not found"}), 404
        user_id = user["id"]

        cur.execute("""
            SELECT t.id AS team_id, t.team_name, t.strength_score, t.created_at
            FROM teams t
            WHERE t.user_id = %s
              AND NOT EXISTS (
                SELECT 1 FROM entries e
                WHERE e.team_id = t.id AND e.contest_id = %s
              )
        """, (user_id, contest_id))
        teams = cur.fetchall()

        return jsonify({"teams": teams})

    except Exception as e:
        app.logger.exception("🛑 Failed to fetch unjoined teams:")
        return jsonify({"message": "Internal Server Error"}), 500


@app.route('/join_contest_bulk', methods=['POST'])
@token_required
def join_contest_bulk(current_user_email):
    try:
        data = request.get_json() or {}
        contest_id = data.get("contest_id")
        team_ids = data.get("team_ids")  # expecting list

        if not contest_id or not team_ids or not isinstance(team_ids, list):
            return jsonify({"message": "contest_id and team_ids (list) required"}), 400

        cur = db.cursor()
        cur.execute("SELECT id FROM users WHERE email=%s", (current_user_email,))
        user = cur.fetchone()
        if not user:
            return jsonify({"message": "User not found"}), 404
        user_id = user[0]

        inserted = 0
        for team_id in team_ids:
            # Validate team ownership
            cur.execute("SELECT id FROM teams WHERE id = %s AND user_id = %s", (team_id, user_id))
            if not cur.fetchone():
                continue

            # Skip if already joined
            cur.execute("SELECT id FROM entries WHERE contest_id = %s AND team_id = %s", (contest_id, team_id))
            if cur.fetchone():
                continue

            # Insert entry
            cur.execute("INSERT INTO entries (user_id, team_id, contest_id) VALUES (%s, %s, %s)", (user_id, team_id, contest_id))
            inserted += 1

        db.commit()
        return jsonify({"message": f"{inserted} team(s) joined successfully."})

    except Exception as e:
        app.logger.exception("🛑 Failed to join contest bulk:")
        return jsonify({"message": "Internal Server Error"}), 500


@app.route('/match/<int:match_id>', methods=['GET'])
def get_match_by_id(match_id):
    try:
        cur = db.cursor(dictionary=True)
        cur.execute("SELECT id, match_name AS name, start_time FROM matches WHERE id = %s", (match_id,))
        match = cur.fetchone()
        if match:
            return jsonify(match), 200
        else:
            return jsonify({"message": "Match not found"}), 404
    except mysql.connector.Error as err:
        app.logger.exception("DB error in get_match_by_id")
        return jsonify({"error": str(err)}), 500


@app.route('/contest/<int:contest_id>', methods=['GET'])
def get_contest_by_id(contest_id):
    try:
        cur = db.cursor(dictionary=True)
        cur.execute("""
            SELECT 
                id, 
                contest_name AS name, 
                entry_fee, 
                prize_pool,
                start_time,
                end_time,
                match_id,
                max_teams_per_user,
                commission_percentage,
                max_users,
                joined_users
            FROM contests 
            WHERE id = %s
        """, (contest_id,))
        contest = cur.fetchone()
        if contest:
            return jsonify(contest), 200
        else:
            return jsonify({"message": "Contest not found"}), 404
    except mysql.connector.Error as err:
        app.logger.exception("DB error in get_contest_by_id")
        return jsonify({"error": str(err)}), 500


@app.route('/delete_teams', methods=['POST'])
@token_required
def delete_teams_bulk(current_user_email):
    try:
        data = request.get_json() or {}
        team_ids = data.get("team_ids")
        if not team_ids or not isinstance(team_ids, list):
            return jsonify({"message": "team_ids (list) required"}), 400

        cur = db.cursor()
        cur.execute("SELECT id FROM users WHERE email=%s", (current_user_email,))
        user = cur.fetchone()
        if not user:
            return jsonify({"message": "User not found"}), 404
        user_id = user[0]

        deleted = 0
        for team_id in team_ids:
            # Check ownership
            cur.execute("SELECT user_id FROM teams WHERE id=%s", (team_id,))
            team = cur.fetchone()
            if not team or team[0] != user_id:
                continue

            # Delete entries and related scores first (to avoid FK constraint issues)
            cur.execute("SELECT id FROM entries WHERE team_id=%s", (team_id,))
            entry_ids = [row[0] for row in cur.fetchall()]

            if entry_ids:
                format_strings = ",".join(["%s"] * len(entry_ids))
                cur.execute(f"DELETE FROM scores WHERE entry_id IN ({format_strings})", tuple(entry_ids))
                cur.execute(f"DELETE FROM entries WHERE id IN ({format_strings})", tuple(entry_ids))

            # Then delete the team
            cur.execute("DELETE FROM teams WHERE id=%s", (team_id,))
            deleted += 1

        db.commit()
        return jsonify({"message": f"{deleted} team(s) deleted."})

    except Exception as e:
        app.logger.exception("Error deleting teams")
        return jsonify({"message": "Internal Server Error"}), 500



@app.route('/contest/<int:contest_id>/user-teams', methods=['GET', 'OPTIONS'])
@token_required
def get_user_teams_for_contest(current_user_email, contest_id):
    if request.method == 'OPTIONS':
        return '', 204

    try:
        cur = db.cursor(dictionary=True)

        # Step 1: Get user ID from email
        cur.execute("SELECT id FROM users WHERE email = %s", (current_user_email,))
        user_row = cur.fetchone()
        if not user_row:
            return jsonify({"message": "User not found"}), 404
        user_id = user_row["id"]

        # Step 2: Fetch teams for this contest and user
        cur.execute("""
            SELECT id AS team_id, team_name, players, strength_score, rating, team_style
            FROM teams
            WHERE contest_id = %s AND user_id = %s
        """, (contest_id, user_id))
        rows = cur.fetchall()

        # Step 3: Format and return response
        teams = []
        for row in rows:
            teams.append({
                "team_id": row["team_id"],
                "team_name": row["team_name"],
                "players": json.loads(row["players"]) if row["players"] else [],
                "strength_score": row.get("strength_score"),
                "rating": row.get("rating"),
                "team_style": row.get("team_style")
            })

        return jsonify({"teams": teams}), 200

    except Exception as e:
        app.logger.exception("🛑 Error in get_user_teams_for_contest")
        return jsonify({"message": "Internal Server Error"}), 500


@app.route('/my_contest/<int:user_id>/<int:contest_id>', methods=['GET'])
def get_my_contest(user_id, contest_id):
    try:
        cursor = db.cursor(dictionary=True)
        query = """
            SELECT  c.id,
                    c.contest_name,
                    c.entry_fee,
                    c.prize_pool,
                    c.joined_users,
                    c.max_users,
                    m.start_time,
                    m.end_time,
                    CASE
                        WHEN NOW() < m.start_time THEN 'UPCOMING'
                        WHEN NOW() BETWEEN m.start_time AND m.end_time THEN 'LIVE'
                        ELSE 'COMPLETED'
                    END AS status
            FROM contests c
            JOIN matches m ON m.id = c.match_id
            WHERE c.id = %s
        """
        cursor.execute(query, (contest_id,))  # Only contest_id here
        contest = cursor.fetchone()
        if contest:
            return jsonify(contest), 200
        else:
            return jsonify({"message": "Contest not found for this user"}), 404
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500



@app.route('/api/my-contest-entries/<int:user_id>/<int:contest_id>', methods=['GET'])
def get_my_contest_entries(user_id, contest_id):
    try:
        with mysql_cursor(dictionary=True) as cursor:
            # 1) Fetch each joined team entry
            entries_sql = """
                SELECT
                    ce.team_id,
                    ce.entry_fee,
                    ce.joined_count
                FROM contest_entries ce
                WHERE ce.user_id    = %s
                  AND ce.contest_id = %s
            """
            cursor.execute(entries_sql, (user_id, contest_id))
            joined_teams = cursor.fetchall()  # [{team_id, entry_fee, joined_count}, …]

            # 2) Compute total bet money in the DB for accuracy
            total_sql = """
                SELECT IFNULL(SUM(entry_fee * joined_count), 0) AS total_bet_money
                FROM contest_entries
                WHERE user_id    = %s
                  AND contest_id = %s
            """
            cursor.execute(total_sql, (user_id, contest_id))
            total_bet_money = cursor.fetchone().get('total_bet_money', 0)

            # 3) (Optional) Fetch contest-level entry_fee if you need it on the front end
            contest_sql = """
                SELECT entry_fee
                FROM contests
                WHERE id = %s
            """
            cursor.execute(contest_sql, (contest_id,))
            contest = cursor.fetchone()
            contest_entry_fee = contest.get('entry_fee', 0) if contest else 0

        return jsonify({
            "joinedTeams": joined_teams,
            "totalBetMoney": float(total_bet_money),
            "contestEntryFee": float(contest_entry_fee)
        }), 200

    except Exception as err:
        app.logger.error(f"Error in get_my_contest_entries: {err}")
        return jsonify({"error": str(err)}), 500



@app.route('/match/<int:match_id>/players', methods=['GET'])
@token_required
def get_match_players_with_stats(current_user_email, match_id):
    """
    Returns all players for both sides of a match.
    Optional query param: ?contest_id=123 to get selection stats.
    """
    import re
    contest_id = request.args.get('contest_id', type=int)
    cur = db.cursor(dictionary=True)  # changed from mysql.connection.cursor

    # a) fetch match_name
    cur.execute("SELECT match_name FROM matches WHERE id = %s", (match_id,))
    match = cur.fetchone()
    if not match:
        return jsonify({'error': 'Match not found'}), 404

    # b) parse "TeamA vs TeamB"
    sides = [s.strip() for s in re.split(r'[^A-Za-z ]+', match['match_name']) if s.strip()]

    # c) load players for those sides (or fallback by match_id)
    if len(sides) == 2:
        sql = """
          SELECT id, player_name, role, team_name, is_playing, position
          FROM players
          WHERE team_name IN (%s, %s)
          ORDER BY is_playing DESC, position ASC
        """
        params = (sides[0], sides[1])
    else:
        sql = """
          SELECT id, player_name, role, team_name, is_playing, position
          FROM players
          WHERE match_id = %s
          ORDER BY is_playing DESC, position ASC
        """
        params = (match_id,)

    cur.execute(sql, params)
    players = cur.fetchall()

    # d) initialize stats
    for p in players:
        p['taken_count']   = 0
        p['taken_percent'] = 0

    # e) if contest_id supplied, compute counts & percentages
    if contest_id:
        cur.execute("SELECT COUNT(*) AS total FROM entries WHERE contest_id = %s", (contest_id,))
        total = cur.fetchone().get('total', 0) or 0

        if total:
            for p in players:
                cur.execute("""
                  SELECT COUNT(*) AS cnt
                  FROM entries e
                  JOIN teams t ON e.team_id = t.id
                  WHERE e.contest_id = %s
                    AND JSON_CONTAINS(
                          t.players,
                          JSON_OBJECT('player_name', %s),
                          '$'
                        )
                """, (contest_id, p['player_name']))
                cnt = cur.fetchone().get('cnt', 0) or 0
                p['taken_count']   = cnt
                p['taken_percent'] = round(cnt * 100 / total)

    return jsonify({'players': players}), 200



@app.route('/api/matches/<int:match_id>/contest/<int:contest_id>/players', methods=['GET'])
@token_required
def get_players_for_ai_page(current_user_email, match_id, contest_id):
    try:
        with mysql_cursor(dictionary=True) as cur:
            cur.execute("""
                SELECT id, player_name, role, team_name, credit_value, is_playing, position
                FROM players
                WHERE match_id = %s
            """, (match_id,))

            players = cur.fetchall()
            return jsonify(players), 200

    except Exception as e:
        import traceback
        traceback.print_exc()
        app.logger.error(f"🔴 Error fetching players: {e}")
        return jsonify({"message": "Internal Server Error"}), 500





@celery.task()
def generate_ai_teams_task(match_id, contest_id, user_id, count):
    created = 0

    for i in range(count):
        try:
            team = pick_team(match_id)

            if not team or len(team) != 11:
                continue

            captain = next((p['player_name'] for p in team if p.get('is_captain')), None)
            vice_captain = next((p['player_name'] for p in team if p.get('is_vice_captain')), None)

            with mysql_cursor() as cursor:
                insert_query = """
                    INSERT INTO teams (team_name, players, user_id, contest_id, total_points, captain, vice_captain)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """
                cursor.execute(insert_query, (
                    f"AI Team {i+1}",
                    json.dumps(team),
                    user_id,
                    contest_id,
                    0,
                    captain,
                    vice_captain
                ))
                db.commit()  # Assuming db is your MySQL connection object

            created += 1

        except Exception as e:
            print(f"[ERROR] Failed to create team {i+1}: {e}")
            traceback.print_exc()
            continue

    return {"message": f"{created} teams created successfully."}



@app.route('/api/ai/generate', methods=['POST'])
def trigger_ai_team_generation():
    data = request.json
    match_id = data.get('match_id')
    contest_id = data.get('contest_id')
    user_id = data.get('user_id')
    count = data.get('count', 1)

    if not all([match_id, contest_id, user_id]):
        return jsonify({"error": "Missing required fields"}), 400

    task = generate_ai_teams_task.delay(match_id, contest_id, user_id, count)
    return jsonify({"task_id": task.id, "status": "queued"}), 202


@app.route('/api/ai/generate_sync', methods=['POST'])
def trigger_ai_team_generation_sync():
    try:
        data = request.get_json()
        match_id = data.get('match_id')
        contest_id = data.get('contest_id')
        user_id = data.get('user_id')
        count = data.get('count', 1)

        if not all([match_id, contest_id, user_id]):
            return jsonify({'error': 'Missing parameters'}), 400

        task = generate_ai_teams_task.apply_async(args=[match_id, contest_id, user_id, count])

        return jsonify({'message': 'AI team generation started.', 'task_id': task.id}), 202

    except Exception as e:
        print(f"[ERROR] Failed to trigger task: {e}")
        traceback.print_exc()
        return jsonify({'error': 'Internal Server Error'}), 500


@app.route('/generate_ai_teams/status', methods=['GET'])
def check_ai_team_status():
    task_id = request.args.get('task_id')
    if not task_id:
        return jsonify({'error': 'Missing task_id'}), 400

    task = generate_ai_teams_task.AsyncResult(task_id)

    response = {
        'task_id': task_id,
        'status': task.status,
        'result': task.result if task.ready() else None
    }

    return jsonify(response), 200



@app.route('/test_env')
def test_env():
    return jsonify({
        "secret_key": app.config['SECRET_KEY'],
        "db_host": os.getenv("DB_HOST"),
        "db_user": os.getenv("DB_USER")
    })




if __name__ == '__main__':
    print("✅ Registered Routes:")
    for rule in app.url_map.iter_rules():
        print(f"{rule.endpoint}: {rule}")
    app.run(debug=True)