from datetime import datetime, timedelta
from flask_cors import CORS
import jwt
from functools import wraps
from flask import Flask, request, jsonify, make_response
import mysql.connector
import json
from decimal import Decimal
from dotenv import load_dotenv
import os
import bcrypt
import traceback

# Load environment variables from .env file
load_dotenv()

# ✅ Print to check if variables are loaded
print("✅ DB_HOST:", os.getenv("DB_HOST"))
print("✅ DB_USER:", os.getenv("DB_USER"))
print("✅ DB_PASSWORD:", os.getenv("DB_PASSWORD"))
print("✅ DB_NAME:", os.getenv("DB_NAME"))
print("✅ SECRET_KEY:", os.getenv("SECRET_KEY"))


app = Flask(__name__)
app = Flask(__name__)
CORS(app, origins=["http://localhost:3000"], supports_credentials=True)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret_key')  # Use env secret or fallback
print("✅ SECRET_KEY loaded:", app.config['SECRET_KEY'])


# MySQL Database Connection using env vars
db = mysql.connector.connect(
    host=os.getenv('DB_HOST'),
    port=int(os.getenv('DB_PORT', 3306)),
    user=os.getenv('DB_USER'),
    password=os.getenv('DB_PASSWORD'),
    database=os.getenv('DB_NAME')
)




cursor = db.cursor()
# Token decorator to protect routes
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # 1) Allow CORS preflight to pass un-checked
        if request.method == 'OPTIONS':
            resp = make_response('', 204)
            # These headers get added by flask-cors, but we re-declare to be safe
            resp.headers['Access-Control-Allow-Origin']  = 'http://localhost:3000'
            resp.headers['Access-Control-Allow-Methods'] = 'GET,POST,OPTIONS'
            resp.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization'
            return resp

        # 2) Now enforce JWT
        token = None
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1]

        if not token:
            return jsonify({'message': 'Token is missing!'}), 403

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user_email = data['email']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired! Please login again.'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token!'}), 401

        return f(current_user_email, *args, **kwargs)
    return decorated


# Function to check if user is admin
def is_admin_user(email):
    cursor = db.cursor()
    cursor.execute("SELECT is_admin FROM users WHERE email = %s", (email,))
    result = cursor.fetchone()
    return result and result[0] == 1

def _build_cors_preflight_response():
    response = jsonify({})
    h = response.headers
    h['Access-Control-Allow-Origin']  = 'http://localhost:3000'
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

    # use dict cursor so we can return id + email
    cursor = db.cursor(dictionary=True)
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

    # 👇 NEW: also return id & email
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
        cursor.execute(
            "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
            (username, email, hashed_password.decode('utf-8'))
        )
        user_id = cursor.lastrowid

        cursor.execute(
            "INSERT INTO wallets (user_id, balance) VALUES (%s, %s)",
            (user_id, 200.00)
        )

        db.commit()
        return jsonify({"message": "User registered and wallet created!"}), 201
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 400

@app.route('/dashboard', methods=['GET'])
@token_required
def dashboard(current_user_email):
    try:
        cursor = db.cursor()
        cursor.execute("SELECT username FROM users WHERE email = %s", (current_user_email,))
        user = cursor.fetchone()
        if user:
            return jsonify({"message": f"Welcome to your dashboard, {user[0]}!"})
        else:
            return jsonify({"message": "User not found"}), 404
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500



# ----------  CREATE TEAM  ----------
@app.route('/create_team', methods=['POST'])
@token_required
def create_team(current_user_email):
    """
    Body: {
      "contest_id": 8,
      "team_name": "Mighty XI",
      "players": [
        {
          "player_name": "PlayerA1",
          "role": "Bowler",
          "credit": 8.5,
          "captain": true,
          "vice_captain": false
        },
        ...
      ]
    }
    """
    try:
        data = request.get_json()
        print("✅ Incoming payload:", data)

        team_name  = data.get('team_name')
        players    = data.get('players')  # now a list of dicts
        contest_id = data.get('contest_id')

        if not team_name or not players or len(players) != 11 or not contest_id:
            return jsonify({"message": "team_name, 11 valid players & contest_id required"}), 400

        cur = cursor
        cur.execute("SELECT id FROM users WHERE email=%s", (current_user_email,))
        row = cur.fetchone()
        if not row:
            return jsonify({"message": "User not found"}), 404
        user_id = row[0]

        # Max teams per user check
        cur.execute("SELECT max_teams_per_user FROM contests WHERE id=%s", (contest_id,))
        max_teams = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM teams WHERE user_id=%s AND contest_id=%s", (user_id, contest_id))
        if max_teams and cur.fetchone()[0] >= max_teams:
            return jsonify({"message": f"Only {max_teams} teams allowed in this contest"}), 403

        # Duplicate team check (based on player_name only)
        submitted_names = sorted([p['player_name'] for p in players])
        cur.execute("SELECT players FROM teams WHERE user_id=%s AND contest_id=%s", (user_id, contest_id))
        for (js,) in cur.fetchall():
            try:
                existing = json.loads(js)
                existing_names = sorted([p['player_name'] for p in existing])
                if existing_names == submitted_names:
                    return jsonify({"message": "Same player combination already used"}), 400
            except Exception as e:
                continue  # ignore if existing row can't parse

        # Store full player objects as JSON
        cur.execute("""
            INSERT INTO teams (team_name, players, user_id, contest_id)
            VALUES (%s, %s, %s, %s)
        """, (team_name, json.dumps(players), user_id, contest_id))
        db.commit()

        return jsonify({"message": "Team created ✔"})
    
    except Exception as e:
        print("❌ Backend error during team creation:", str(e))
        return jsonify({"message": "Internal Server Error", "error": str(e)}), 500

# Join Contest API
now = datetime.utcnow()



# ----------  JOIN CONTEST  ----------
@app.route('/join_contest', methods=['POST'])
@token_required
def join_contest(current_user_email):
    """
    Body: { "contest_id": 8, "team_id": 36 }
    Deduct entry fee, add a row in entries (with timestamp), bump joined_users.
    """
    data = request.get_json()
    contest_id = data.get('contest_id')
    team_id = data.get('team_id')

    if not contest_id or not team_id:
        return jsonify({"message": "Contest ID and Team ID required"}), 400

    cur = cursor

    # Get user_id from email
    cur.execute("SELECT id FROM users WHERE email=%s", (current_user_email,))
    row = cur.fetchone()
    if not row:
        return jsonify({"message": "User not found"}), 404
    user_id = row[0]

    # Validate team ownership
    cur.execute("""
        SELECT id FROM teams
        WHERE id = %s AND user_id = %s AND contest_id = %s
    """, (team_id, user_id, contest_id))
    team = cur.fetchone()
    if not team:
        return jsonify({"message": "Invalid team for this user and contest"}), 400

    # Contest details
    cur.execute("SELECT entry_fee, joined_users, max_users FROM contests WHERE id=%s", (contest_id,))
    row = cur.fetchone()
    if not row:
        return jsonify({"message": "Contest not found"}), 404
    entry_fee, joined, max_users = row
    if joined >= max_users:
        return jsonify({"message": "Contest full"}), 400

    # Wallet balance
    cur.execute("SELECT balance FROM wallets WHERE user_id=%s", (user_id,))
    bal = cur.fetchone()[0]
    if bal < entry_fee:
        return jsonify({"message": "Insufficient balance"}), 403

    # Deduct and join contest
    cur.execute("UPDATE wallets SET balance = balance - %s WHERE user_id=%s", (entry_fee, user_id))
    cur.execute("UPDATE contests SET joined_users = joined_users + 1 WHERE id=%s", (contest_id,))
    cur.execute("""
        INSERT INTO entries (user_id, team_id, contest_id)
        VALUES (%s, %s, %s)
    """, (user_id, team_id, contest_id))  # joined_at is auto-filled by DB

    cur.execute("""
        INSERT INTO transactions (user_id, amount, type, description)
        VALUES (%s, %s, 'debit', 'Joined contest')
    """, (user_id, entry_fee))

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
        cursor = db.cursor(dictionary=True)
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
        contests = cursor.fetchall()         # list[dict]
        return jsonify({"contests": contests}), 200

    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500
# Leaderboard API
@app.route('/leaderboard/<int:contest_id>', methods=['GET'])
def leaderboard(contest_id):
    try:
        cursor = db.cursor(dictionary=True)
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
        cursor = db.cursor()
        cursor.execute(
            "INSERT INTO scores (entry_id, points) VALUES (%s, %s)",
            (entry_id, points)
        )
        db.commit()
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
        cursor = db.cursor()
        cursor.execute("UPDATE teams SET team_name = %s, players = %s WHERE id = %s",
                       (team_name, players_json, team_id))
        db.commit()
        return jsonify({"message": "Team updated successfully!"})
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500

# Delete Team API
@app.route('/delete_team/<int:team_id>', methods=['POST'])
@token_required
def delete_team(current_user_email, team_id):
    try:
        cursor = db.cursor()

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

        db.commit()
        return jsonify({"message": "Team and related entries deleted successfully!"})
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500

# Delete Contest API
@app.route('/delete_contest/<int:contest_id>', methods=['POST'])
@token_required
def delete_contest(current_user_email, contest_id):
    try:
        cursor = db.cursor()

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

        db.commit()
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
        cursor = db.cursor()
        for item in entries_points:
            entry_id = item.get('entry_id')
            points = item.get('points')

            if entry_id is None or points is None:
                return jsonify({"message": "Each entry must have 'entry_id' and 'points'"}), 400

            cursor.execute(
                "INSERT INTO scores (entry_id, points) VALUES (%s, %s)",
                (entry_id, points)
            )
        db.commit()
        return jsonify({"message": "Points added successfully for all entries!"}), 201
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500





@app.route('/declare_winners/<int:contest_id>', methods=['POST'])
@token_required
def declare_winners(current_user_email, contest_id):
    try:
        cursor = db.cursor(dictionary=True)

        # Get top 3 teams from the leaderboard
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

        # Insert winners into winners table
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
        cursor = db.cursor()
        # Get user_id
        cursor.execute("SELECT id FROM users WHERE email = %s", (current_user_email,))
        user = cursor.fetchone()
        if not user:
            return jsonify({"message": "User not found"}), 404
        user_id = user[0]

        # Get wallet balance
        cursor.execute("SELECT balance FROM wallets WHERE user_id = %s", (user_id,))
        wallet = cursor.fetchone()
        if not wallet:
            return jsonify({"message": "Wallet not found"}), 404

        return jsonify({"balance": float(wallet[0])})
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500





@app.route('/declare_winner', methods=['POST'])
@token_required
def declare_winner(current_user_email):
    data = request.get_json()
    contest_id = data.get('contest_id')
    user_id = data.get('user_id')
    amount = data.get('amount')

    if not contest_id or not user_id or amount is None:
        return jsonify({"message": "Missing contest_id, user_id, or amount"}), 400

    try:
        cursor = db.cursor()

        # Check if contest exists
        cursor.execute("SELECT id FROM contests WHERE id = %s", (contest_id,))
        contest = cursor.fetchone()
        if not contest:
            return jsonify({"message": "Contest not found"}), 404

        # Check if user exists
        cursor.execute("SELECT id FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        if not user:
            return jsonify({"message": "User not found"}), 404

        # Update wallet balance: add prize money
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



# ------------------  PROFILE ROUTES  ------------------

@app.route('/profile', methods=['GET'])
@token_required
def get_profile(current_user_email):
    """
    Return username & email of the logged-in user.
    """
    try:
        cur = db.cursor(dictionary=True)
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
    """
    Update username of the logged-in user.
    Body JSON → { "username": "new_name" }
    """
    data = request.get_json() or {}
    new_username = data.get('username')

    if not new_username:
        return jsonify({"message": "Username is required"}), 400

    try:
        cur = db.cursor()
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
        cursor = db.cursor(dictionary=True)
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
        cursor = db.cursor(dictionary=True)

        # ✅ Get user ID from current_user_email
        cursor.execute("SELECT id FROM users WHERE email = %s", (current_user_email,))
        user = cursor.fetchone()
        if not user:
            return jsonify({"message": "User not found"}), 404

        user_id = user['id']

        # ✅ Fetch transactions
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





from decimal import Decimal

@app.route('/admin/distribute_prizes/<int:contest_id>', methods=['POST'])
@token_required
def distribute_prizes(current_user_email, contest_id):
    # Check admin rights
    if not is_admin_user(current_user_email):
        return jsonify({"message": "Unauthorized"}), 403

    try:
        cursor = db.cursor(dictionary=True)

        # 1. Get contest and check status
        cursor.execute("SELECT prize_pool, status, commission_percentage FROM contests WHERE id = %s", (contest_id,))
        contest = cursor.fetchone()

        if not contest:
            return jsonify({"message": "Contest not found"}), 404
        if contest['status'] == 'prizes_distributed':
            return jsonify({"message": "Prizes already distributed"}), 400

        prize_pool = float(contest['prize_pool'])
        commission_percentage = contest['commission_percentage'] or 0
        commission_amount = prize_pool * (commission_percentage / 100)
        prize_pool -= commission_amount  # reduce commission from prize pool

        # 2. Insert platform earnings
        cursor.execute("""
            INSERT INTO platform_earnings (contest_id, commission_amount)
            VALUES (%s, %s)
        """, (contest_id, commission_amount))

        # 3. Get prize distribution
        cursor.execute("""
            SELECT rank_position, percentage
            FROM prize_distributions
            WHERE contest_id = %s
            ORDER BY rank_position ASC
        """, (contest_id,))
        distributions = cursor.fetchall()

        if not distributions:
            return jsonify({"message": "No prize distribution set for this contest"}), 400

        # 4. Get teams sorted by score
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

        # 5. Distribute prizes
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

            # Add transaction record
            cursor.execute("""
                INSERT INTO transaction_history (user_id, amount, transaction_type, description)
                VALUES (%s, %s, 'credit', %s)
            """, (team['user_id'], prize_amount, f'Prize for rank {rank} in contest {contest_id}'))

            # Add notification
            cursor.execute("""
                INSERT INTO notifications (user_id, message)
                VALUES (%s, %s)
            """, (team['user_id'], f"🎉 You won ₹{prize_amount:.2f} in contest ID {contest_id} (Rank {rank})!"))

        # 6. Update contest status
        cursor.execute("UPDATE contests SET status = 'prizes_distributed' WHERE id = %s", (contest_id,))
        db.commit()

        return jsonify({
            "message": f"Prizes distributed for contest {contest_id}",
            "commission_collected": commission_amount
        })

    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500







# Example: Admin-only route to view all withdrawal requests
@app.route('/admin/withdrawal_requests', methods=['GET'])
@token_required
def view_all_withdrawal_requests(current_user_email):
    if not is_admin_user(current_user_email):
        return jsonify({"message": "Unauthorized access"}), 403  # Forbidden

    try:
        cursor = db.cursor(dictionary=True)
        cursor.execute("""
            SELECT wr.id, u.username, u.email, wr.amount, wr.status, 
                   wr.requested_at, wr.processed_at, wr.admin_remark
            FROM withdrawal_requests wr
            JOIN users u ON wr.user_id = u.id
            ORDER BY wr.requested_at DESC
        """)
        results = cursor.fetchall()

        return jsonify(results)
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500








# Example: Admin-only route to process (approve/reject) withdrawal requests
@app.route('/admin/process_withdrawal/<int:request_id>', methods=['POST'])
@token_required
def process_withdrawal(current_user_email, request_id):
    if not is_admin_user(current_user_email):
        return jsonify({"message": "Unauthorized access"}), 403

    data = request.get_json()
    action = data.get('action')  # 'approve' or 'reject'
    admin_remark = data.get('remark', '')

    if action not in ['approve', 'reject']:
        return jsonify({"message": "Invalid action"}), 400

    try:
        cursor = db.cursor()

        # Get withdrawal request details
        cursor.execute("SELECT user_id, amount, status FROM withdrawal_requests WHERE id = %s", (request_id,))
        request_row = cursor.fetchone()

        if not request_row:
            return jsonify({"message": "Withdrawal request not found"}), 404

        user_id, amount, status = request_row
        if status != 'pending':
            return jsonify({"message": "Withdrawal request already processed"}), 400

        if action == 'approve':
            # Check wallet balance
            cursor.execute("SELECT balance FROM wallets WHERE user_id = %s", (user_id,))
            wallet = cursor.fetchone()
            if not wallet or wallet[0] < amount:
                return jsonify({"message": "Insufficient wallet balance"}), 400

            new_balance = wallet[0] - amount
            cursor.execute("UPDATE wallets SET balance = %s WHERE user_id = %s", (new_balance, user_id))

            # Update withdrawal request status
            cursor.execute("""
                UPDATE withdrawal_requests 
                SET status = 'approved', processed_at = NOW(), admin_remark = %s 
                WHERE id = %s
            """, (admin_remark, request_id))

            # Add transaction record (optional, if you have transaction_history table)
            cursor.execute("""
                INSERT INTO transaction_history (user_id, amount, transaction_type, description)
                VALUES (%s, %s, %s, %s)
            """, (user_id, amount, 'debit', 'Withdrawal approved by admin'))

        else:  # reject
            cursor.execute("""
                UPDATE withdrawal_requests 
                SET status = 'rejected', processed_at = NOW(), admin_remark = %s
                WHERE id = %s
            """, (admin_remark, request_id))

        db.commit()
        return jsonify({"message": f"Withdrawal request {action}d successfully!"})

    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500


@app.route('/admin/withdrawal_request/<int:request_id>', methods=['POST'])
@token_required  # You can add admin role check inside the decorator or here
def admin_process_withdrawal(current_user_email, request_id):
    data = request.get_json()
    action = data.get('action')  # "approve" or "reject"

    if action not in ['approve', 'reject']:
        return jsonify({"message": "Invalid action"}), 400

    try:
        cursor = db.cursor(dictionary=True)

        # Get withdrawal request details
        cursor.execute("SELECT * FROM withdrawal_requests WHERE id = %s AND status = 'pending'", (request_id,))
        request_info = cursor.fetchone()
        if not request_info:
            return jsonify({"message": "Withdrawal request not found or already processed"}), 404

        user_id = request_info['user_id']
        amount = request_info['amount']

        if action == 'approve':
            # Check wallet balance
            cursor.execute("SELECT balance FROM wallets WHERE user_id = %s", (user_id,))
            wallet = cursor.fetchone()
            if not wallet or wallet['balance'] < amount:
                return jsonify({"message": "Insufficient wallet balance"}), 400
            
            # Deduct amount
            new_balance = wallet['balance'] - amount
            cursor.execute("UPDATE wallets SET balance = %s WHERE user_id = %s", (new_balance, user_id))
            
            # Update withdrawal request status
            cursor.execute("UPDATE withdrawal_requests SET status = 'approved' WHERE id = %s", (request_id,))
            
            # Add transaction history
            cursor.execute("""
                INSERT INTO transaction_history (user_id, amount, transaction_type, description)
                VALUES (%s, %s, %s, %s)
            """, (user_id, amount, 'debit', 'Withdrawal approved by admin'))

        else:  # reject
            cursor.execute("UPDATE withdrawal_requests SET status = 'rejected' WHERE id = %s", (request_id,))

        db.commit()
        return jsonify({"message": f"Withdrawal request {action}d successfully"})
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500










@app.route('/request_withdrawal', methods=['POST'])
@token_required
def request_withdrawal(current_user_email):
    data = request.get_json()
    amount = data.get('amount')

    if not amount:
        return jsonify({"message": "Amount is required"}), 400

    try:
        cursor = db.cursor()

        # Get user ID from email
        cursor.execute("SELECT id FROM users WHERE email = %s", (current_user_email,))
        user = cursor.fetchone()
        if not user:
            return jsonify({"message": "User not found"}), 404
        user_id = user[0]

        # Insert withdrawal request
        cursor.execute("""
            INSERT INTO withdrawal_requests (user_id, amount)
            VALUES (%s, %s)
        """, (user_id, amount))

        db.commit()
        return jsonify({"message": "Withdrawal request successfully registered!"})
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500




# CREATE CONTEST
@app.route('/admin/create_contest', methods=['POST'])
@token_required
def admin_create_contest(current_user_email):
    if not is_admin_user(current_user_email):
        return jsonify({"message": "Unauthorized"}), 403

    data = request.get_json()
    contest_name = data.get('contest_name')
    match_id = data.get('match_id')
    entry_fee = data.get('entry_fee')
    max_users = data.get('max_users')
    commission_percentage = data.get('commission_percentage', 15)
    max_teams_per_user = data.get('max_teams_per_user', 1)

    if not all([contest_name, match_id, entry_fee, max_users]):
        return jsonify({"message": "Missing required fields"}), 400

    try:
        entry_fee = float(entry_fee)
        max_users = int(max_users)
        commission_percentage = float(commission_percentage)

        total_collection = entry_fee * max_users
        commission = total_collection * (commission_percentage / 100)
        prize_pool = total_collection - commission

        cursor = db.cursor()
        cursor.execute("""
            INSERT INTO contests (
                contest_name, match_id, entry_fee, prize_pool,
                start_time, end_time, status, max_teams_per_user,
                commission_percentage, max_users
            )
            VALUES (%s, %s, %s, %s, NOW(), NOW(), 'active', %s, %s, %s)
        """, (contest_name, match_id, entry_fee, prize_pool,
              max_teams_per_user, commission_percentage, max_users))

        db.commit()
        return jsonify({"message": "Contest created successfully!"})
    except Exception as err:
        print("❌ Create contest error:", err)
        return jsonify({"error": str(err)}), 500

@app.route('/my_teams', methods=['GET'])
@token_required
def get_my_teams(current_user_email):
    try:
        cursor = db.cursor(dictionary=True)

        # Get user id from email
        cursor.execute("SELECT id FROM users WHERE email = %s", (current_user_email,))
        user = cursor.fetchone()
        if not user:
            return jsonify({"message": "User not found"}), 404
        
        user_id = user['id']

        # Get all teams for this user with contest info
        cursor.execute("""
            SELECT t.id as team_id, t.team_name, t.players, t.total_points, c.id as contest_id, c.contest_name, c.status
            FROM teams t
            LEFT JOIN contests c ON t.contest_id = c.id
            WHERE t.user_id = %s
        """, (user_id,))

        teams = cursor.fetchall()

        # Format players JSON string back to list for better API response
        for team in teams:
            team['players'] = json.loads(team['players'])

        return jsonify({"teams": teams})
    
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500



@app.route('/my_contests', methods=['GET'])
@token_required
def get_my_contests(current_user_email):
    try:
        cursor = db.cursor(dictionary=True)

        # Get user id
        cursor.execute("SELECT id FROM users WHERE email = %s", (current_user_email,))
        user = cursor.fetchone()
        if not user:
            return jsonify({"message": "User not found"}), 404
        
        user_id = user['id']

        # Get contest ids where user has teams
        cursor.execute("""
            SELECT DISTINCT c.id, c.contest_name, c.entry_fee, c.prize_pool, c.status, c.start_time, c.end_time
            FROM contests c
            JOIN teams t ON c.id = t.contest_id
            WHERE t.user_id = %s
        """, (user_id,))

        contests = cursor.fetchall()

        return jsonify({"contests": contests})

    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500


# ----------  MATCH → CONTEST LIST  ----------
@app.route('/contests/<int:match_id>', methods=['GET'])
def get_contests(match_id):
    """
    Return ALL contests that belong to the given match_id
    Ordered by prize_pool DESC so biggest prizes first.
    """
    try:
        cursor = db.cursor(dictionary=True)
        cursor.execute("""
            SELECT id,
                   name,
                   entry_fee,
                   prize_pool,
                   max_users,
                   joined_users,
                   start_time,
                   end_time
            FROM contests
            WHERE match_id = %s
            ORDER BY prize_pool DESC
        """, (match_id,))
        return jsonify(cursor.fetchall())
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500
    


# 3️⃣  Contest details / leaderboard -------
@app.route('/contests/<int:contest_id>/details', methods=['GET'])
@token_required
def contest_details(current_user_email, contest_id):
    """
    Returns:  { contest: {...}, teams: [ {...rank…} ] }
    """
    try:
        cursor = db.cursor(dictionary=True)

        # contest info
        cursor.execute("""
            SELECT id, name, entry_fee, prize_pool, status,
                   start_time, end_time
            FROM contests
            WHERE id = %s
        """, (contest_id,))
        contest = cursor.fetchone()
        if not contest:
            return jsonify({"message": "Contest not found"}), 404

        # leaderboard
        cursor.execute("""
            SELECT t.id   AS team_id,
                   t.team_name,
                   t.total_points,
                   u.username
            FROM teams t
                 JOIN users u ON t.user_id = u.id
            WHERE t.contest_id = %s
            ORDER BY t.total_points DESC
        """, (contest_id,))
        teams = cursor.fetchall()

        # add rank field
        for idx, team in enumerate(teams, start=1):
            team['rank'] = idx

        return jsonify({"contest": contest, "teams": teams})

    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500




@app.route('/edit_team', methods=['POST'])
@token_required
def edit_team(current_user_email):
    data = request.get_json()
    team_id = data.get('team_id')
    new_team_name = data.get('team_name')
    new_players = data.get('players')

    if not team_id or not new_team_name or not new_players:
        return jsonify({"message": "Missing team_id, team_name, or players"}), 400

    try:
        cursor = db.cursor(dictionary=True)

        # Get user_id of current user
        cursor.execute("SELECT id FROM users WHERE email = %s", (current_user_email,))
        user = cursor.fetchone()
        if not user:
            return jsonify({"message": "User not found"}), 404
        user_id = user['id']

        # Check if team belongs to current user
        cursor.execute("SELECT contest_id FROM teams WHERE id = %s AND user_id = %s", (team_id, user_id))
        team = cursor.fetchone()
        if not team:
            return jsonify({"message": "Team not found or does not belong to user"}), 404

        contest_id = team['contest_id']

        # Check if contest has not started yet
        cursor.execute("SELECT start_time FROM contests WHERE id = %s", (contest_id,))
        contest = cursor.fetchone()
        if not contest:
            return jsonify({"message": "Contest not found"}), 404

        from datetime import datetime
        now = datetime.utcnow()
        contest_start = contest['start_time']

        if contest_start <= now:
            return jsonify({"message": "Cannot edit team after contest has started"}), 400

        # Update team details
        players_json = json.dumps(new_players)
        cursor.execute("""
            UPDATE teams 
            SET team_name = %s, players = %s 
            WHERE id = %s
        """, (new_team_name, players_json, team_id))

        db.commit()
        return jsonify({"message": "Team updated successfully"})

    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500








# Match status updater function (outside the route)
def update_match_statuses():
    now = datetime.utcnow()  # ✅ Fix: no need for datetime.datetime
    cursor = db.cursor()
    cursor.execute("UPDATE matches SET status = 'live' WHERE start_time <= %s AND end_time > %s", (now, now))
    cursor.execute("UPDATE matches SET status = 'completed' WHERE end_time <= %s", (now,))
    cursor.execute("UPDATE matches SET status = 'upcoming' WHERE start_time > %s", (now,))
    db.commit()





# Flask route to trigger match status update
@app.route('/admin/update_match_statuses', methods=['GET'])
@token_required
def call_update_status(current_user_email):
    if not is_admin_user(current_user_email):
        return jsonify({"message": "Unauthorized"}), 403

    update_match_statuses()
    return jsonify({"message": "Match statuses updated!"})


@app.route('/matches', methods=['GET'])
def get_matches():
    """Return all matches with status normalised to UPPER-CASE."""
    try:
        cursor = db.cursor(dictionary=True)
        cursor.execute("""
            SELECT
                id,
                match_name       AS name,        -- easier for React
                start_time,
                UPPER(status)    AS status       -- always UPCOMING/LIVE/COMPLETED
            FROM matches
            ORDER BY start_time
        """)
        matches = cursor.fetchall()
        return jsonify(matches)
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500



@app.route('/admin/auto_lock_contests', methods=['POST'])
@token_required
def auto_lock_contests(current_user_email):
    # Check if admin
    if not is_admin_user(current_user_email):
        return jsonify({"message": "Unauthorized"}), 403

    try:
        cursor = db.cursor()
        now = datetime.utcnow()

        # Update contests where match has started but contest not locked yet
        cursor.execute("""
            UPDATE contests c
            JOIN matches m ON c.match_id = m.id
            SET c.status = 'locked'
            WHERE m.start_time <= %s AND c.status = 'upcoming'
        """, (now,))

        db.commit()
        return jsonify({"message": "Auto-lock contests updated based on match start time."})

    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500




@app.route('/notifications', methods=['GET'])
@token_required
def get_notifications(current_user_email):
    try:
        cursor = db.cursor(dictionary=True)
        
        # Get user id from email
        cursor.execute("SELECT id FROM users WHERE email = %s", (current_user_email,))
        user = cursor.fetchone()
        if not user:
            return jsonify({"message": "User not found"}), 404

        user_id = user['id']

        # Fetch notifications for user
        cursor.execute(
            "SELECT message, created_at FROM notifications WHERE user_id = %s ORDER BY created_at DESC", 
            (user_id,)
        )
        notifications = cursor.fetchall()

        # Return notifications wrapped in an object, not raw list (better API design)
        return jsonify({"notifications": notifications})

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

    cursor = db.cursor()
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

    db.commit()
    return jsonify({"message": f"Wallet topped up with ₹{amount} successfully."})



@app.route('/admin/statistics', methods=['GET', 'OPTIONS'])
@token_required
def admin_statistics(current_user_email):
    # 1) CORS preflight
    if request.method == 'OPTIONS':
        return make_response('', 204)

    # 2) Only admins
    if not is_admin_user(current_user_email):
        return jsonify({"message": "Unauthorized"}), 403

    try:
        cursor = db.cursor()

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

        # Prize distributed = sum of prize_pool
        cursor.execute("SELECT COALESCE(SUM(prize_pool),0) FROM contests")
        total_prize_distributed = float(cursor.fetchone()[0])

        # Commission earned = SUM(entry_fee * joined_users * commission_percentage/100)
        cursor.execute("""
            SELECT COALESCE(SUM(entry_fee * joined_users * commission_percentage/100),0)
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
        cursor = db.cursor(dictionary=True)
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
        cursor = db.cursor(dictionary=True)

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
        cursor = db.cursor(dictionary=True)

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
        cursor = db.cursor(dictionary=True)

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
        cursor = db.cursor(dictionary=True)

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
        cursor = db.cursor(dictionary=True)
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
    if not all(data.get(k) for k in ['match_name', 'start_time', 'end_time']):
        return jsonify({"message": "Missing required fields"}), 400

    try:
        cursor = db.cursor()
        cursor.execute("""
            INSERT INTO matches (match_name, start_time, end_time, status)
            VALUES (%s, %s, %s, %s)
        """, (
            data['match_name'],
            data['start_time'],
            data['end_time'],
            data.get('status', 'UPCOMING')
        ))
        db.commit()
        return jsonify({"message": "Match created successfully"}), 201
    except Exception as e:
        db.rollback()
        return jsonify({"error": str(e)}), 500


@app.route('/admin/update_match', methods=['POST'])
@token_required
def admin_update_match(current_user_email):
    if not is_admin_user(current_user_email):
        return jsonify({"message": "Unauthorized"}), 403

    data = request.get_json()
    match_id = data.get("id")
    if not match_id:
        return jsonify({"message": "Match ID is required"}), 400

    fields = []
    values = []
    for key in ['match_name', 'start_time', 'end_time', 'status']:
        if key in data:
            fields.append(f"{key} = %s")
            values.append(data[key])

    if not fields:
        return jsonify({"message": "Nothing to update"}), 400

    values.append(match_id)

    try:
        cursor = db.cursor()
        cursor.execute(f"UPDATE matches SET {', '.join(fields)} WHERE id = %s", tuple(values))
        db.commit()
        return jsonify({"message": "Match updated successfully"}), 200
    except Exception as e:
        db.rollback()
        return jsonify({"error": str(e)}), 500


@app.route('/admin/delete_match', methods=['POST'])
@token_required
def admin_delete_match(current_user_email):
    if not is_admin_user(current_user_email):
        return jsonify({"message": "Unauthorized"}), 403

    data = request.get_json()
    match_id = data.get("id")
    if not match_id:
        return jsonify({"message": "Match ID is required"}), 400

    try:
        cursor = db.cursor()
        cursor.execute("DELETE FROM matches WHERE id = %s", (match_id,))
        db.commit()
        return jsonify({"message": f"Match ID {match_id} deleted"}), 200
    except Exception as e:
        db.rollback()
        return jsonify({"error": str(e)}), 500



@app.route('/admin/get_contests', methods=['GET'])
@token_required
def admin_get_contests(current_user_email):
    if not is_admin_user(current_user_email):
        return jsonify({"message": "Unauthorized"}), 403

    try:
        cursor = db.cursor(dictionary=True)
        cursor.execute("""
            SELECT id, contest_name, match_id, entry_fee, prize_pool,
                   max_users, joined_users,
                   commission_percentage, max_teams_per_user,
                   status, start_time, end_time
            FROM contests
            ORDER BY id DESC
        """)
        return jsonify(cursor.fetchall()), 200
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500


@app.route('/admin/update_contest', methods=['POST'])
@token_required
def admin_update_contest(current_user_email):
    if not is_admin_user(current_user_email):
        return jsonify({"message": "Unauthorized"}), 403

    data = request.get_json()
    contest_id = data.get('id')
    if not contest_id:
        return jsonify({"message": "Missing contest ID"}), 400

    fields = []
    values = []

    for key in ['contest_name', 'entry_fee', 'max_users', 'commission_percentage', 'max_teams_per_user', 'status']:
        if key in data:
            fields.append(f"{key} = %s")
            values.append(data[key])

    values.append(contest_id)

    try:
        cursor = db.cursor()
        cursor.execute(f"UPDATE contests SET {', '.join(fields)} WHERE id = %s", tuple(values))
        db.commit()
        return jsonify({"message": "Contest updated successfully!"})
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500



# DELETE CONTEST
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
        cursor = db.cursor()

        if force:
            print(f"⚠️ Force deleting contest {contest_id} — including entries")
            cursor.execute("DELETE FROM entries WHERE contest_id = %s", (contest_id,))

        cursor.execute("DELETE FROM contests WHERE id = %s", (contest_id,))
        db.commit()
        return jsonify({"message": "Contest deleted successfully!"})

    except Exception as err:
        print("❌ Delete contest error:", err)
        return jsonify({"error": str(err)}), 500



@app.route('/admin/contest/<int:contest_id>/entries', methods=['GET'])
@token_required
def admin_list_entries(current_user_email, contest_id):
    if not is_admin_user(current_user_email):
        return jsonify({"message": "Unauthorized"}), 403

    try:
        cursor = db.cursor(dictionary=True)

        # ✅ This includes joined_at field
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


@app.route('/admin/team/<int:id>', methods=['GET'])
@token_required
def admin_team_details(current_user_email, id):
    if not is_admin_user(current_user_email):
        return jsonify({"message": "Unauthorized"}), 403

    try:
        cursor = db.cursor(dictionary=True)

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

    except mysql.connector.Error as err:
        print(f"🔥 DB error:", err)
        return jsonify({"error": str(err)}), 500


@app.route('/admin/users', methods=['GET'])
@token_required
def get_admin_users(current_user_email):
    if not is_admin_user(current_user_email):
        return jsonify({"message": "Unauthorized"}), 403

    try:
        cursor = db.cursor(dictionary=True)
        
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
    cursor.execute("UPDATE users SET password = %s WHERE id = %s", (hashed, user_id))
    db.commit()

    return jsonify({"message": f"Password for user #{user_id} has been reset ✅"})


@app.route('/admin/user_earnings/<int:user_id>', methods=['GET'])
@token_required
def get_user_earnings(user_id):
    try:
        cursor = db.cursor(dictionary=True)

        # Fetch all transactions
        cursor.execute("""
            SELECT type, amount, message, timestamp
            FROM transactions
            WHERE user_id = %s
            ORDER BY timestamp DESC
        """, (user_id,))
        history = cursor.fetchall()

        # Calculate totals
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
    # 1) CORS preflight
    if request.method == 'OPTIONS':
        return make_response('', 204)

    # 2) Only admins can adjust
    if not is_admin_user(current_user_email):
        return jsonify({"message": "Unauthorized"}), 403

    try:
        # 3) Parse payload
        data    = request.get_json(force=True)
        user_id = data['user_id']
        amount  = float(data['amount'])
        note    = data.get('note', '')

        cursor = db.cursor()

        # 4) Update existing wallet, or insert one if missing
        cursor.execute(
            "UPDATE wallets SET balance = balance + %s WHERE user_id = %s",
            (amount, user_id)
        )
        if cursor.rowcount == 0:
            cursor.execute(
                "INSERT INTO wallets (user_id, balance) VALUES (%s, %s)",
                (user_id, amount)
            )

        # 5) Record the transaction in `transactions.description`
        cursor.execute(
            "INSERT INTO transactions "
            "(user_id, type, amount, description) "
            "VALUES (%s, %s, %s, %s)",
            (
                user_id,
                "credit" if amount > 0 else "debit",
                abs(amount),
                note
            )
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
        cursor = db.cursor()
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
        cursor = db.cursor()
        # Flip is_banned: 1 → 0 or 0 → 1
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
    # 1) Allow preflight through
    if request.method == 'OPTIONS':
        return make_response('', 204)

    # 2) Only admins
    if not is_admin_user(current_user_email):
        return jsonify({"message": "Unauthorized"}), 403

    try:
        cursor = db.cursor(dictionary=True)
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

            # default blanks
            contest_name = ''
            match_title  = ''

            # only for entry-fee debits that say "Joined contest ID X"
            desc = r.get('description') or ''
            if r['type'] == 'debit' and 'Joined contest ID' in desc:
                try:
                    cid = int(desc.split('Joined contest ID')[1].strip())

                    # fetch contest_name & its match_id
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
                            # fetch the real match_name
                            cursor.execute("""
                                SELECT match_name
                                FROM matches
                                WHERE id = %s
                            """, (mid,))
                            mm = cursor.fetchone()
                            if mm:
                                match_title = mm['match_name'] or ''
                except Exception:
                    pass   # on any parse/join error just leave blanks

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
        cur = db.cursor(dictionary=True)
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
        cur = db.cursor(dictionary=True)
        cur.execute("""
            SELECT
              t.id,
              t.user_id,
              u.username,
              t.amount,
              t.description,
              t.created_at       AS date,
              e.contest_id,
              c.contest_name,
              m.match_name
            FROM transactions t
            JOIN users   u ON t.user_id = u.id
            LEFT JOIN entries e ON t.user_id = e.user_id
            LEFT JOIN contests c ON e.contest_id = c.id
            LEFT JOIN matches  m ON c.match_id   = m.id
            WHERE t.type = 'credit'
              AND LOWER(t.description) LIKE '%prize%'
            ORDER BY t.created_at DESC
        """)
        rows = cur.fetchall()

        result = []
        for r in rows:
            result.append({
                'id':            r['id'],
                'user_id':       r['user_id'],
                'username':      r['username'] or '',
                'amount':        float(r['amount'] or 0),
                'description':   r['description'] or '',
                'date':          r['date'].isoformat(),
                'contest_name':  r['contest_name'] or '—',
                'match_name':    r['match_name']   or '—'
            })

        return jsonify(result), 200

    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500




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

