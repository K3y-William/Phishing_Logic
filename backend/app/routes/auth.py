from flask import Blueprint, session, redirect, request, jsonify, current_app
from backend.app.services.email_services.email_login_handler import authenticate_gmail

bp = Blueprint('auth', __name__, url_prefix='/auth')


@bp.route('/login', methods=['GET'])
def login():
    try:
        service = authenticate_gmail()
        assert(service is not None)
    except Exception as e:
        return jsonify(error="fail to create gmail service"), 500

    try:
        session['authenticated'] = True
        current_app.gmail_service = service
        return jsonify({'message': 'Login successful'}), 200
    except Exception as e:
        return jsonify({'error': f'Login failed: {str(e)}'}), 500
