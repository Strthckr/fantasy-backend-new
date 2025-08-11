# ai_team.py
from flask import Blueprint, request, jsonify, current_app as app
from app import mysql_cursor, token_required, pick_team, db
import json
import traceback
import re

ai_bp = Blueprint('ai_bp', __name__)

@ai_bp.route('/api/matches/<int:match_id>/contest/<int:contest_id>/players', methods=['GET'])
@token_required
def get_players_for_ai_page(current_user_email, match_id, contest_id):
    try:
        with mysql_cursor(dictionary=True) as cur:
            # Get match name
            cur.execute("SELECT match_name FROM matches WHERE id = %s", (match_id,))
            match = cur.fetchone()
            if not match:
                return jsonify({'error': 'Match not found'}), 404

            # Parse team names from match_name
            sides = [s.strip() for s in re.split(r'[^A-Za-z ]+', match['match_name']) if s.strip()]

            if len(sides) == 2:
                sql = """
                    SELECT id, player_name, role, team_name, credit_value, is_playing, position
                    FROM players
                    WHERE team_name IN (%s, %s)
                    ORDER BY is_playing DESC, position ASC
                """
                params = (sides[0], sides[1])
            else:
                sql = """
                    SELECT id, player_name, role, team_name, credit_value, is_playing, position
                    FROM players
                    WHERE match_id = %s
                    ORDER BY is_playing DESC, position ASC
                """
                params = (match_id,)

            cur.execute(sql, params)
            players = cur.fetchall()
            return jsonify(players), 200

    except Exception as e:
        traceback.print_exc()
        app.logger.error(f"Error fetching players: {e}")
        return jsonify({"message": "Internal Server Error"}), 500


@ai_bp.route('/match/<int:match_id>/generate-team', methods=['POST'])
@token_required
def generate_ai_teams(current_user_email, match_id):
    try:
        data = request.get_json()
        contest_id = data.get("contest_id")
        num_teams = int(data.get("num_teams", 1))

        created_team_ids = []

        for i in range(num_teams):
            team = pick_team(match_id)
            if not team or len(team) != 11:
                continue

            captain = next((p['player_name'] for p in team if p.get('is_captain')), None)
            vice_captain = next((p['player_name'] for p in team if p.get('is_vice_captain')), None)

            with mysql_cursor() as cur:
                insert_query = """
                    INSERT INTO teams (team_name, players, user_id, contest_id, total_points, captain, vice_captain)
                    VALUES (%s, %s, 
                        (SELECT id FROM users WHERE email = %s LIMIT 1), 
                        %s, %s, %s, %s)
                """
                cur.execute(insert_query, (
                    f"AI Team {i+1}",
                    json.dumps(team),
                    current_user_email,
                    contest_id,
                    0,
                    captain,
                    vice_captain
                ))
                db.commit()
                created_team_ids.append(cur.lastrowid)

        return jsonify({
            "message": f"{len(created_team_ids)} teams created successfully.",
            "team_ids": created_team_ids
        }), 200

    except Exception as e:
        traceback.print_exc()
        return jsonify({"message": "Internal Server Error"}), 500
