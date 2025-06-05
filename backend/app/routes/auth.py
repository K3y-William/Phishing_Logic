from flask import Blueprint, session, jsonify, current_app
#pathing can vary
from app.services.email_services.email_login_handler import authenticate_gmail

TOKEN_PATH = 'token.json'

bp = Blueprint('auth', __name__, url_prefix='/auth')


@bp.route('/login', methods=['GET'])
def login():
    try:
        service = authenticate_gmail()
    except Exception as e:
        return jsonify(error=str(e)), 500

    try:
        session['authenticated'] = True
        current_app.gmail_service = service
        return jsonify({'message': 'Login successful'}), 200
    except Exception as e:
        return jsonify({'error': f'Login failed: {str(e)}'}), 500
