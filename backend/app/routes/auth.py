from backend.app.services.email_services.email_login_handler import authenticate_gmail
from flask import Blueprint, session, redirect, request, jsonify, app

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.route('/login', methods=['GET'])
def login():
    """
    Authenticates the user with Gmail using OAuth.
    Saves a flag to session indicating successful login.
    """
    try:
        service = authenticate_gmail()
        if not service:
            return jsonify({'error': 'Authentication failed'}), 401

        # Save basic session state
        session['authenticated'] = True
        app.gmail_service = service


        return jsonify({'message': 'Login successful'}), 200

    except Exception as e:
        return jsonify({'error': f'Login failed: {str(e)}'}), 500



