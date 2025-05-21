# Scan incoming & past emails
from flask import Blueprint, session, redirect, request, jsonify, current_app
from backend.app.services.email_services.email_login_handler import analyze_email_recent, analyze_specific_email

MAX_RESULTS = 10

bp = Blueprint('scan', __name__, url_prefix='/scan')

@bp.route('/list', methods=['GET'])
def list():
    try:
        print(session)
        if session.get('authenticated') == True and hasattr(current_app, 'gmail_service'):
            messages = analyze_email_recent(current_app.gmail_service)
            return jsonify(messages=messages)
        else:
            return jsonify(error="Not authenticated or gmail_service missing."), 401  
    except Exception as e:
        print("error1", e)
        return jsonify(error=str(e)), 500
    
@bp.route('/search', methods=['GET'])
def search():
    #to be implemeneted
    return jsonify()