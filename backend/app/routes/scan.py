# Scan incoming & past emails
from flask import Blueprint, session, request, jsonify, current_app
#pathing can vary depending on location of app execution
from app.services.email_services.email_login_handler import analyze_email_recent, filter_analyze_email

MAX_RESULTS = 7

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
    
@bp.route('/search', methods=['POST'])
def search():
    if not session.get('authenticated') or not hasattr(current_app, 'gmail_service'):
        return jsonify(error="Not authenticated or gmail_service missing."), 401

    data = request.get_json() or {}

    #receives POST search query data
    sender = data.get('sender')
    subject = data.get('subject')
    start_date = data.get('start_date')
    end_date = data.get('end_date')
    has_attachment = data.get('has_attachment')
    custom_query_part = data.get('custom_query_part')
    
    messages = filter_analyze_email(current_app.gmail_service, sender, subject, start_date, end_date, has_attachment, custom_query_part, MAX_RESULTS)

    return jsonify(messages=messages)