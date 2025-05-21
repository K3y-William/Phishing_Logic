# Scan incoming & past emails
from flask import Blueprint, session, redirect, request, jsonify, current_app
from backend.app.services.email_services.email_login_handler import list_inbox_messages_most_recent
bp = Blueprint('scan', __name__, url_prefix='/scan')

@bp.route('/list', methods=['GET'])
def list():
    try:
        if session['authenticated'] == True:
            # return a list of custom email details in json format
            return list_inbox_messages_most_recent(current_app.gmail_service)
    except Exception as e:
        print("error1")
        return jsonify(error=str(e)), 500

