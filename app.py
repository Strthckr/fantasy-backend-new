from datetime import datetime, timedelta
from flask_cors import CORS
import jwt
from functools import wraps
from flask import Flask, request, jsonify
import mysql.connector
import json
from decimal import Decimal
from dotenv import load_dotenv
import os
import bcrypt

# Load environment variables from .env file
load_dotenv()

# ✅ Print to check if variables are loaded
print("✅ DB_HOST:", os.getenv("DB_HOST"))
print("✅ DB_USER:", os.getenv("DB_USER"))
print("✅ DB_PASSWORD:", os.getenv("DB_PASSWORD"))
print("✅ DB_NAME:", os.getenv("DB_NAME"))
print("✅ SECRET_KEY:", os.getenv("SECRET_KEY"))


app = Flask(__name__)
CORS(app, origins=["http://localhost:3000"])
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
        token = None

        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]

        if not token:
            return jsonify({'message': 'Token is missing!'}), 403

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            print("✅ Token expiry time (UTC):", datetime.fromtimestamp(data['exp']))
            print("✅ Current UTC time:", datetime.utcnow())

            current_user_email = data['email']
        except jwt.ExpiredSignatureError:
            print("❌ Token expired error caught!")
            return jsonify({'message': 'Token has expired! Please login again.'}), 401
        except jwt.InvalidTokenError:
            print("❌ Invalid token error caught!")
            return jsonify({'message': 'Invalid token!'}), 401

        return f(current_user_email, *args, **kwargs)
    return decorated

# Function to check if user is admin
def is_admin_user(email):
    cursor = db.cursor()
    cursor.execute("SELECT is_admin FROM users WHERE email = %s", (email,))
    result = cursor.fetchone()
    return result and result[0] == 1


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
    email = data.get('email')
    password = data.get('password')

    cursor = db.cursor()
    cursor.execute("SELECT password FROM users WHERE email = %s", (email,))
    result = cursor.fetchone()

    if result:
        stored_hashed_password = result[0]
        if bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password.encode('utf-8')):
            token = jwt.encode(
                {
                    'email': email,
                    'exp': datetime.utcnow() + timedelta(days=7)
                },
                app.config['SECRET_KEY'],
                algorithm="HS256"
            )

            # 🔑 make sure it's a str, not bytes
            if isinstance(token, bytes):
                token = token.decode('utf-8')

            return jsonify({"token": token})
        else:
            return jsonify({"message": "Invalid credentials"}), 401
    else:
        return jsonify({"message": "User not found"}), 404



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



# Create Team API
@app.route('/create_team', methods=['POST'])
@token_required
def create_team(current_user_email):
    data = request.get_json()
    team_name = data.get('team_name')
    players = data.get('players')
    contest_id = data.get('contest_id')  # Required

    if not team_name or not players or not contest_id:
        return jsonify({"message": "Missing team_name, players, or contest_id"}), 400

    try:
        # Get user ID
        cursor.execute("SELECT id FROM users WHERE email = %s", (current_user_email,))
        user = cursor.fetchone()
        if not user:
            return jsonify({"message": "User not found"}), 404
        user_id = user[0]

        # ✅ Get max teams allowed for this contest
        cursor.execute("SELECT max_teams_per_user FROM contests WHERE id = %s", (contest_id,))
        contest = cursor.fetchone()
        if not contest:
            return jsonify({"message": "Contest not found"}), 404
        max_teams = contest[0]

        # ✅ Count user's teams already created for this contest
        cursor.execute("""
            SELECT COUNT(*) FROM teams 
            WHERE user_id = %s AND contest_id = %s
        """, (user_id, contest_id))
        team_count = cursor.fetchone()[0]

        if max_teams is not None and max_teams > 0 and team_count >= max_teams:
            return jsonify({"message": f"Limit reached: You can create only {max_teams} teams for this contest."}), 403

        # ✅ Prevent duplicate players in the same team
        if len(players) != len(set(players)):
            return jsonify({"message": "Duplicate players found in the team"}), 400

        # ✅ Check if team with same players already exists for the user in this contest
        players_sorted = sorted(players)
        cursor.execute("""
            SELECT players FROM teams 
            WHERE user_id = %s AND contest_id = %s
        """, (user_id, contest_id))
        existing_teams = cursor.fetchall()

        for (existing_players_json,) in existing_teams:
            existing_players = json.loads(existing_players_json)
            if sorted(existing_players) == players_sorted:
                return jsonify({"message": "A team with the same players already exists."}), 400

        # ✅ All good, insert new team
        players_json = json.dumps(players)
        cursor.execute("""
            INSERT INTO teams (team_name, players, user_id, contest_id)
            VALUES (%s, %s, %s, %s)
        """, (team_name, players_json, user_id, contest_id))

        db.commit()
        return jsonify({"message": "Team created successfully!"})

    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500


# Join Contest API
now = datetime.utcnow()


# 4️⃣  Join contest ------------------------
@app.route('/join_contest', methods=['POST'])
@token_required
def join_contest(current_user_email):
    data = request.get_json()
    contest_id = data.get('contest_id')
    team_id    = data.get('team_id')

    if not contest_id or not team_id:
        return jsonify({"message": "contest_id and team_id are required"}), 400

    cursor = db.cursor()

    # -- get user id
    cursor.execute("SELECT id FROM users WHERE email = %s", (current_user_email,))
    row = cursor.fetchone()
    if not row:
        return jsonify({"message": "User not found"}), 404
    user_id = row[0]

    # -- ensure not already joined with same team
    cursor.execute("""
        SELECT id FROM entries
        WHERE user_id = %s AND contest_id = %s AND team_id = %s
    """, (user_id, contest_id, team_id))
    if cursor.fetchone():
        return jsonify({"message": "Already joined with this team"}), 400

    # -- contest info
    cursor.execute("""
        SELECT entry_fee, joined_users, max_users
        FROM contests
        WHERE id = %s
    """, (contest_id,))
    row = cursor.fetchone()
    if not row:
        return jsonify({"message": "Contest not found"}), 404
    entry_fee, joined_users, max_users = row

    if joined_users >= max_users:
        return jsonify({"message": "Contest is full"}), 400

    # -- wallet balance
    cursor.execute("""
        SELECT w.balance
        FROM wallets w
        JOIN users  u ON w.user_id = u.id
        WHERE u.id = %s
    """, (user_id,))
    wallet = cursor.fetchone()
    if not wallet or wallet[0] < entry_fee:
        return jsonify({"message": "Insufficient wallet balance"}), 403

    # ========  transactional actions =========
    cursor.execute("UPDATE wallets SET balance = balance - %s WHERE user_id = %s", (entry_fee, user_id))
    cursor.execute("UPDATE contests SET joined_users = joined_users + 1 WHERE id = %s", (contest_id,))
    cursor.execute("INSERT INTO entries (user_id, contest_id, team_id) VALUES (%s, %s, %s)",
                   (user_id, contest_id, team_id))
    cursor.execute("""
        INSERT INTO transactions (user_id, amount, type, description)
        VALUES (%s, %s, 'debit', 'Joined contest')
    """, (user_id, entry_fee))

    db.commit()
    return jsonify({"message": f"Joined contest! ₹{entry_fee} deducted from wallet."})


# Create Contest API
@app.route('/create_contest', methods=['POST'])
@token_required
def create_contest(current_user_email):
    if not is_admin_user(current_user_email):
        return jsonify({"message": "Unauthorized"}), 403

    data = request.get_json()
    contest_name = data.get('contest_name')
    match_id = data.get('match_id')
    entry_fee = data.get('entry_fee')
    total_spots = data.get('total_spots')
    commission_percentage = data.get('commission_percentage', 15)  # default 15%
    max_teams_per_user = data.get('max_teams_per_user', 1)         # default 1

    if not contest_name or not match_id or not entry_fee or not total_spots:
        return jsonify({"message": "Missing required fields"}), 400

    try:
        cursor = db.cursor()

        # Calculate prize pool after commission
        total_collection = float(entry_fee) * int(total_spots)
        commission_amount = total_collection * (float(commission_percentage) / 100)
        prize_pool = total_collection - commission_amount

        # Insert contest
        cursor.execute("""
            INSERT INTO contests 
            (contest_name, match_id, entry_fee, prize_pool, start_time, end_time, status, max_teams_per_user, commission_percentage)
            VALUES (%s, %s, %s, %s, NOW(), NOW(), 'active', %s, %s)
        """, (contest_name, match_id, entry_fee, prize_pool, max_teams_per_user, commission_percentage))

        db.commit()
        return jsonify({"message": "Contest created successfully!"})

    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500

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
    try:
        cursor = db.cursor(dictionary=True)
        query = """
            SELECT c.id, c.contest_name, c.entry_fee
            FROM contests c
            JOIN entries e ON c.id = e.contest_id
            WHERE e.user_id = %s
        """
        cursor.execute(query, (user_id,))
        contests = cursor.fetchall()
        return jsonify(contests)
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




@app.route('/admin/create_contest', methods=['POST'])
@token_required
def admin_create_contest(current_user_email):
    if not is_admin_user(current_user_email):
        return jsonify({"message": "Unauthorized"}), 403

    data = request.get_json()
    name = data.get('name')
    entry_fee = data.get('entry_fee')
    prize_pool = data.get('prize_pool')
    start_time = data.get('start_time')
    end_time = data.get('end_time')
    match_id = data.get('match_id')
    max_teams_per_user = data.get('max_teams_per_user')
    commission_percentage = data.get('commission_percentage')

    # ✅ Validate all required fields
    if not all([name, entry_fee, prize_pool, start_time, end_time, match_id, max_teams_per_user, commission_percentage]):
        return jsonify({"message": "Missing contest fields"}), 400

    try:
        cursor = db.cursor()
        cursor.execute("""
            INSERT INTO contests (
                name, entry_fee, prize_pool, start_time, end_time, match_id, 
                max_teams_per_user, commission_percentage
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            name, entry_fee, prize_pool, start_time, end_time,
            match_id, max_teams_per_user, commission_percentage
        ))
        db.commit()
        return jsonify({"message": "Contest created successfully!"})

    except mysql.connector.Error as err:
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


# 2️⃣  List contests *for one match* -------
@app.route('/contests/match/<int:match_id>', methods=['GET'])
def list_match_contests(match_id):
    """Contests page in Phase 4 (UI hits this endpoint)."""
    try:
        cursor = db.cursor(dictionary=True)
        cursor.execute("""
            SELECT id,
                   name,
                   entry_fee,
                   prize_pool,
                   max_users,
                   joined_users,
                   status
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


@app.route('/admin/statistics', methods=['GET'])
@token_required
def admin_statistics(current_user_email):
    if not is_admin_user(current_user_email):
        return jsonify({"message": "Unauthorized access"}), 403

    try:
        cursor = db.cursor(dictionary=True)

        # 1. Total users
        cursor.execute("SELECT COUNT(*) as total_users FROM users")
        total_users = cursor.fetchone()['total_users']

        # 2. Total contests
        cursor.execute("SELECT COUNT(*) as total_contests FROM contests")
        total_contests = cursor.fetchone()['total_contests']

        # 3. Total prize distributed (from transaction history as 'credit' + prize)
        cursor.execute("""
            SELECT SUM(amount) as total_prize_distributed 
            FROM transaction_history 
            WHERE transaction_type = 'credit' AND description LIKE 'Prize%'
        """)
        prize_result = cursor.fetchone()
        total_prize_distributed = float(prize_result['total_prize_distributed'] or 0)

        # 4. Total withdrawal requests
        cursor.execute("SELECT COUNT(*) as total_withdraw_requests FROM withdrawal_requests")
        total_withdraw_requests = cursor.fetchone()['total_withdraw_requests']

        # 5. Total commission earned (if you track commissions in transaction_history)
        cursor.execute("""
            SELECT SUM(amount) as total_commission 
            FROM transaction_history 
            WHERE transaction_type = 'commission'
        """)
        commission_result = cursor.fetchone()
        total_commission_earned = float(commission_result['total_commission'] or 0)

        return jsonify({
            "total_users": total_users,
            "total_contests": total_contests,
            "total_prize_distributed": total_prize_distributed,
            "total_withdraw_requests": total_withdraw_requests,
            "total_commission_earned": total_commission_earned
        })

    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500



@app.route('/admin/set_prize_distribution/<int:contest_id>', methods=['POST'])
@token_required
def set_prize_distribution(current_user_email, contest_id):
    # Check if current user is an admin
    if not is_admin_user(current_user_email):
        return jsonify({"message": "Unauthorized"}), 403

    data = request.get_json()
    distributions = data.get("distributions")  # Expected to be a list of dicts

    if not distributions or not isinstance(distributions, list):
        return jsonify({"message": "Invalid input. Provide a list of distributions."}), 400

    try:
        cursor = db.cursor()

        # Optionally delete previous distribution settings for this contest
        cursor.execute("DELETE FROM prize_distributions WHERE contest_id = %s", (contest_id,))

        # Insert new distribution values for the contest
        for item in distributions:
            rank = item.get("rank")
            percentage = item.get("percentage")
            if rank is None or percentage is None:
                return jsonify({"message": "Each distribution item must include 'rank' and 'percentage'."}), 400

            cursor.execute("""
                INSERT INTO prize_distributions (contest_id, rank_position, percentage)
                VALUES (%s, %s, %s)
            """, (contest_id, rank, percentage))

        db.commit()
        return jsonify({"message": f"Prize distribution set for contest {contest_id} successfully."})

    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500


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

