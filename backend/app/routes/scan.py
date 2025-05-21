# Scan incoming & past emails
from flask import Blueprint, session, redirect, request, jsonify, current_app
from backend.app.services.email_services.email_login_handler import list_inbox_messages_most_recent
bp = Blueprint('scan', __name__, url_prefix='/scan')

@bp.route('/list', methods=['GET'])
def list():
    try:
        if session.get('authenticated'):
            # Get optional 'max_results' query parameter, default to 5 if not provided
            max_results = request.args.get('max_results', default=5, type=int)
            return jsonify(list_inbox_messages_most_recent(current_app.gmail_service, max_results))
        else:
            return jsonify(error="Unauthorized"), 401
    except Exception as e:
        print(e)
        return jsonify(error=str(e)), 500