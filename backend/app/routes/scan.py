# Scan incoming & past emails
from flask import Blueprint, session, redirect, request, jsonify, current_app
from backend.app.services.email_services.email_login_handler import list_inbox_messages_most_recent
from backend.app.services.llm_handler import analyze_content_with_gemini
from backend.app.services.domain_check import extract_links_without_scheme,get_domain_from_email_format, check_link_details

MAX_RESULTS = 10

bp = Blueprint('scan', __name__, url_prefix='/scan')

@bp.route('/list', methods=['GET'])
def list():
    try:
        print(session)
        if session.get('authenticated') == True and hasattr(current_app, 'gmail_service'):
            messages = list_inbox_messages_most_recent(current_app.gmail_service, max_results=MAX_RESULTS)
            # call llm analyze
            for x in range(len(messages)):
                links = extract_links_without_scheme(str(messages[x]))
                links_info = []

                for l in links:
                    links_info.append(check_link_details(l))
                sender_domain = get_domain_from_email_format(messages[x]['from'])
                sender_domain_analysis = check_link_details(sender_domain)
                (messages[x])['scanOutput'] = (analyze_content_with_gemini(messages[x]['subject'],messages[x]['snippet'],sender_domain_analysis, links_info))['analysis'] #converting dict back to value
            return jsonify(messages=messages)
        else:
            return jsonify(error="Not authenticated or gmail_service missing."), 401  
    except Exception as e:
        print("error1", e)
        return jsonify(error=str(e)), 500