from flask import Blueprint, request, jsonify
import json
from utils import mysql_cursor, token_required, pick_team  # <-- works if utils.py is in same folder

ai_bp = Blueprint("ai_bp", __name__)

@ai_bp.route("/api/ai/generate", methods=["POST"])
@token_required
def generate_ai_team(current_user_email):
    data = request.get_json()
    match_id = data.get("match_id")
    contest_id = data.get("contest_id")
    user_id = data.get("user_id", 1)
    count = data.get("count", 1)

    created = 0
    for i in range(count):
        team = pick_team(match_id)
        if not team or len(team) != 11:
            continue

        captain = next((p['player_name'] for p in team if p.get('is_captain')), None)
        vice_captain = next((p['player_name'] for p in team if p.get('is_vice_captain')), None)

        with mysql_cursor() as cursor:
            cursor.execute("""
                INSERT INTO teams (team_name, players, user_id, contest_id, total_points, captain, vice_captain)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (
                f"AI Team {i+1}",
                json.dumps(team),
                user_id,
                contest_id,
                0,
                captain,
                vice_captain
            ))
        created += 1

    return jsonify({"message": f"{created} teams created successfully"})
