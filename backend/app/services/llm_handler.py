import os
import re
import email
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse
import logging
import datetime
import json # Added for printing results nicely in examples

# --- Potentially needed imports (adjust based on YOUR check_link_details) ---
# import whois
# import dns.resolver
# import socket
# --- Keep other necessary imports ---
import time # Example if you need delays
from domain_check import check_link_details
# --- Google Gemini ---
try:
    import google.generativeai as genai
    from google.api_core import exceptions as google_api_exceptions
except ImportError:
    print("Error: The 'google-generativeai' library is not installed.")
    print("Please install it using: pip install google-generativeai")
    genai = None # Set genai to None if import fails

# --- Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
GEMINI_API_KEY_FILE = "gemini_key.txt" # Use a separate file for Gemini key

# --- Gemini API Setup ---
def get_gemini_key(filepath=GEMINI_API_KEY_FILE):
    """Reads the Gemini API key from a file."""
    try:
        with open(filepath, 'r') as f:
            key = f.read().strip()
            if key:
                return key
            else:
                logging.error(f"Gemini API key file '{filepath}' is empty.")
                return None
    except FileNotFoundError:
        logging.error(f"Gemini API key file '{filepath}' not found. Create it and add your key.")
        return None
    except Exception as e:
        logging.error(f"Error reading Gemini API key file '{filepath}': {e}")
        return None

# Configure Gemini client
gemini_api_key = get_gemini_key()
gemini_model = None # Initialize model variable

if genai and gemini_api_key:
    try:
        genai.configure(api_key=gemini_api_key)
        # Use the free 'gemini-pro' model
        gemini_model = genai.GenerativeModel('gemini-pro')
        logging.info("Gemini client configured and model loaded successfully ('gemini-pro').")
    except Exception as e:
        logging.error(f"Failed to configure Gemini client or load model: {e}")
        gemini_model = None # Ensure model is None if setup fails
elif not genai:
     logging.error("Gemini library not found. Gemini features will be disabled.")
else:
    logging.error("Gemini API key not found or empty. Gemini features will be disabled.")


# --- Your check_link_details Function ---
# ============================================================================
# PASTE YOUR FULL check_link_details FUNCTION IMPLEMENTATION HERE
# Ensure it takes one argument (url_string) and returns a dictionary.
# Make sure all necessary libraries for YOUR function are imported above.
# ============================================================================
# ============================================================================
# END OF check_link_details FUNCTION SECTION
# ============================================================================


# --- Email Parsing Logic ---
# (This function remains the same as before)
def parse_email(email_content_bytes):
    """Parses raw email bytes to extract headers and body."""
    try:
        msg = BytesParser(policy=policy.default).parsebytes(email_content_bytes)
        sender = msg.get('From', 'Unknown Sender')
        subject = msg.get('Subject', 'No Subject')
        body_plain, body_html = None, None

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get('Content-Disposition'))
                if 'attachment' in content_disposition: continue
                charset = part.get_content_charset('utf-8') # Default to utf-8
                if content_type == 'text/plain' and body_plain is None:
                    try: body_plain = part.get_payload(decode=True).decode(charset, errors='replace')
                    except Exception as e: logging.warning(f"Decode plain failed: {e}"); body_plain = "[Decode Error]"
                elif content_type == 'text/html' and body_html is None:
                    try: body_html = part.get_payload(decode=True).decode(charset, errors='replace')
                    except Exception as e: logging.warning(f"Decode html failed: {e}"); body_html = "[Decode Error]"
        else:
            content_type = msg.get_content_type()
            charset = msg.get_content_charset('utf-8')
            if content_type == 'text/plain':
                try: body_plain = msg.get_payload(decode=True).decode(charset, errors='replace')
                except Exception as e: logging.warning(f"Decode non-multi plain failed: {e}"); body_plain = "[Decode Error]"
            elif content_type == 'text/html':
                 try: body_html = msg.get_payload(decode=True).decode(charset, errors='replace')
                 except Exception as e: logging.warning(f"Decode non-multi html failed: {e}"); body_html = "[Decode Error]"

        body = body_plain if body_plain else body_html if body_html else "[No readable body found]"
        sender_email = 'Unknown'
        parsed_addr = email.utils.parseaddr(sender)
        if parsed_addr and '@' in parsed_addr[1]: sender_email = parsed_addr[1]
        sender_domain = None
        if sender_email != 'Unknown' and '@' in sender_email:
            try: sender_domain = sender_email.split('@')[1]
            except IndexError: pass

        return {
            'sender_header': sender, 'sender_email': sender_email, 'sender_domain': sender_domain,
            'subject': subject, 'body': body, 'body_plain': body_plain, 'body_html': body_html
        }
    except Exception as e:
        logging.error(f"Failed to parse email content: {e}")
        return { 'error': f"Failed to parse email: {e}", 'sender_header': 'Parse Error', 'sender_email': 'Parse Error',
                 'sender_domain': None, 'subject': 'Parse Error', 'body': 'Parse Error', 'body_plain': None, 'body_html': None }

# --- Link Extraction ---
# (This function remains the same as before)
def extract_links(text):
    """Extracts URLs from a given text string."""
    url_pattern = re.compile(r'(?:(?:https?|ftp)://|www\.)[\w/\-?=%&.:~+#]+[\w/\-?=%&~+#]')
    if text: return url_pattern.findall(text)
    else: return []

# --- Gemini Content Analysis ---
def analyze_content_with_gemini(subject, body):
    """Uses Gemini API to analyze email content for scam characteristics."""
    if not gemini_model: # Check if the model object was successfully created
        return {"error": "Gemini client not initialized or model not loaded. Cannot analyze content."}
    if not body or body.strip() == "[No readable body found]" or body.strip() == "Parse Error":
         return {"warning": "Email body is empty or could not be parsed. Cannot analyze content."}

    # Limit body length to avoid excessive token usage / potential API limits
    max_body_length = 4000 # Adjust as needed, Gemini Pro has context window limits
    truncated_body = body[:max_body_length]
    if len(body) > max_body_length:
        logging.warning(f"Email body truncated to {max_body_length} characters for Gemini analysis.")

    prompt = f"""
    Analyze the following email content (Subject and Body) for potential scam characteristics.
    Focus on:
    - Urgency (e.g., "immediate action required", "account suspension")
    - Suspicious requests (e.g., asking for login credentials, personal info, money transfers)
    - Generic greetings (e.g., "Dear Customer", "Hello user") vs. personalized ones
    - Poor grammar, spelling, or awkward phrasing
    - Mismatched sender information or impersonation attempts
    - Unexpected attachments or links, especially if domains look suspicious
    - Offers that seem too good to be true (e.g., lottery wins, unexpected inheritances)

    Based on these factors, provide:
    1. A brief summary of your findings.
    2. A clear risk assessment level: Low, Medium, or High.
    3. A concise explanation for your assessment.

    Subject: {subject}

    Body:
    {truncated_body}

    Analysis:
    """

    try:
        # Configure safety settings to be less restrictive if needed,
        # otherwise potentially harmful content might get blocked by default.
        # Be cautious when lowering safety settings.
        safety_settings = [
            {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
            {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
            {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
        ]

        response = gemini_model.generate_content(
            prompt,
            # generation_config=genai.types.GenerationConfig( # Optional: control output
            #     # candidate_count=1, # Usually default is 1
            #     # stop_sequences=['...'],
            #     # max_output_tokens=300,
            #     temperature=0.3 # Lower temperature for more factual/consistent analysis
            # ),
            safety_settings=safety_settings # Apply safety settings
            )

        # Handle potential blocks or lack of response text
        if not response.parts:
             if response.prompt_feedback.block_reason:
                 block_reason = response.prompt_feedback.block_reason
                 safety_ratings = response.prompt_feedback.safety_ratings
                 error_msg = f"Gemini analysis blocked. Reason: {block_reason}. Ratings: {safety_ratings}"
                 logging.warning(error_msg)
                 return {"error": error_msg, "details": {"block_reason": str(block_reason), "safety_ratings": str(safety_ratings)}}
             else:
                  error_msg = "Gemini response empty, reason unknown."
                  logging.warning(error_msg)
                  return {"error": error_msg}

        analysis = response.text.strip()
        return {"analysis": analysis}

    # Handle specific Google API errors if needed
    except google_api_exceptions.GoogleAPIError as e:
        logging.error(f"Gemini API error: {e}")
        return {"error": f"Gemini API error: {e}"}
    except ValueError as e:
        # Catch potential errors like blocked prompts due to safety settings if not handled above
         logging.error(f"Gemini value error (potentially blocked content): {e}")
         return {"error": f"Gemini analysis error (potentially blocked content): {e}"}
    except Exception as e:
        # Catch-all for other unexpected errors
        logging.error(f"Error during Gemini analysis: {type(e).__name__} - {e}")
        return {"error": f"An unexpected error occurred during Gemini analysis: {e}"}


# --- Main Orchestration Function ---
# (Largely the same, but calls Gemini and uses different report keys)
def check_email_safety(email_filepath=None, email_content_str=None):
    """Analyzes an email from a file or string for scam indicators using Gemini."""
    if not email_filepath and not email_content_str: return {"error": "No input provided."}
    if email_filepath and email_content_str: return {"error": "Provide file OR string, not both."}

    email_bytes = None
    input_src = "String Input"
    if email_filepath:
        input_src = email_filepath
        try:
            with open(email_filepath, 'rb') as f: email_bytes = f.read()
        except Exception as e: return {"error": f"Error reading {email_filepath}: {e}"}
    elif email_content_str:
         try: email_bytes = email_content_str.encode('utf-8', errors='replace')
         except Exception as e: return {"error": f"Error encoding string: {e}"}

    if not email_bytes: return {"error": "Could not get email bytes."}

    logging.info("Starting email analysis...")
    parsed_email = parse_email(email_bytes)
    if parsed_email.get('error'):
        logging.error(f"Email parsing failed: {parsed_email['error']}")
        return {"error": parsed_email['error'], "parsed_data": parsed_email}

    logging.info(f"Parsed: Sender='{parsed_email['sender_email']}', Subject='{parsed_email['subject']}'")

    # *** Call Gemini for analysis ***
    gemini_result = analyze_content_with_gemini(parsed_email['subject'], parsed_email['body'])
    logging.info(f"Gemini Analysis: {gemini_result}")

    sender_domain_analysis = None
    if parsed_email['sender_domain']:
        logging.info(f"Analyzing sender domain: {parsed_email['sender_domain']}")
        try:
            # *** This calls YOUR check_link_details implementation ***
            sender_domain_analysis = check_link_details(parsed_email['sender_domain'])
        except NotImplementedError as e:
             logging.error(f"Cannot analyze sender domain: {e}")
             sender_domain_analysis = {"error": str(e)}
        except Exception as e:
             logging.error(f"Error analyzing sender domain {parsed_email['sender_domain']}: {e}")
             sender_domain_analysis = {"error": f"Error checking sender domain: {e}"}
    else:
        logging.warning("Sender domain could not be extracted.")
        sender_domain_analysis = {"error": "Sender domain not found in headers"}

    body_for_links = parsed_email['body_html'] if parsed_email['body_html'] else parsed_email['body_plain']
    extracted_links = extract_links(body_for_links)
    logging.info(f"Found {len(extracted_links)} links.")

    link_analysis_results = {}
    unique_links = set(extracted_links)
    for link in unique_links:
        logging.info(f"Analyzing link: {link}")
        try:
            # *** This calls YOUR check_link_details implementation ***
            link_analysis_results[link] = check_link_details(link)
            # time.sleep(0.5) # Optional delay
        except NotImplementedError as e:
             logging.error(f"Cannot analyze link {link}: {e}")
             link_analysis_results[link] = {"error": str(e)}
             break # Stop checking links if function isn't implemented
        except Exception as e:
             logging.error(f"Error analyzing link {link}: {e}")
             link_analysis_results[link] = {"error": f"Error checking link: {e}"}

    final_report = {
        "input_source": input_src,
        "parsing_info": {k: v for k, v in parsed_email.items() if k not in ['body', 'body_plain', 'body_html', 'error']},
        "gemini_content_analysis": gemini_result, # Renamed key
        "sender_domain_analysis": sender_domain_analysis,
        "links_found": len(extracted_links),
        "unique_links_analyzed": len(unique_links),
        "link_analysis": link_analysis_results,
        "overall_assessment": "Review sections" # Placeholder
    }

    # Simple risk assessment logic (adapt based on your check_link_details output)
    risk_factors = []
    # *** Check Gemini result ***
    if isinstance(gemini_result, dict) and gemini_result.get('analysis') and any(w in gemini_result['analysis'].lower() for w in ['medium', 'high', 'suspicious', 'scam', 'phishing', 'risk']):
         risk_factors.append("Gemini flagged content.")
    elif isinstance(gemini_result, dict) and gemini_result.get('error'):
         risk_factors.append(f"Gemini analysis error: {gemini_result['error']}")


    # (Checks for sender domain and links remain the same conceptually,
    # but remember to adapt them based on the keys YOUR check_link_details returns)
    if isinstance(sender_domain_analysis, dict):
        if sender_domain_analysis.get('error'): risk_factors.append(f"Sender domain check error: {sender_domain_analysis['error']}")
        whois_info = sender_domain_analysis.get('whois') # Adapt key if needed
        if isinstance(whois_info, dict) and whois_info.get('warning'): risk_factors.append(f"Sender domain issue: {whois_info['warning']}") # Adapt key if needed
        if 'fail' in str(sender_domain_analysis.get('spf', '')).lower(): risk_factors.append("Sender SPF potentially failing.") # Adapt key if needed

    for link, analysis in link_analysis_results.items():
         if isinstance(analysis, dict):
             domain_key = analysis.get('domain', link)
             if analysis.get('error'): risk_factors.append(f"Link check error ({domain_key}): {analysis['error']}")
             link_whois = analysis.get('whois') # Adapt key if needed
             if isinstance(link_whois, dict) and link_whois.get('warning'): risk_factors.append(f"Link domain issue ({domain_key}): {link_whois['warning']}") # Adapt key if needed

    if risk_factors: final_report["overall_assessment"] = f"Potential Risk Detected. Factors: {'; '.join(risk_factors)}"
    else: final_report["overall_assessment"] = "Initial checks suggest low risk, review details."

    logging.info("Email analysis complete.")
    return final_report


# --- Example Usage ---
if __name__ == "__main__":
    print("\n--- NOTE: Ensure you have pasted your 'check_link_details' function above! ---")
    print("--- NOTE: Ensure 'gemini_key.txt' exists with your API key! ---")

    # --- Option 1: Analyze an email file ---
    dummy_eml_content = """From: Spammer <spammer@suspicious-domain.xyz>
To: You <you@example.com>
Subject: Urgent Action Required! Update Your Account!

Dear Valued Customer, Click https://totally-legit-update-portal.suspicious-domain.xyz/login
Failure to act now results in suspension! Very urgent!
"""
    dummy_eml_path = "test_email_gemini.eml"
    try:
        with open(dummy_eml_path, "w") as f: f.write(dummy_eml_content)
        logging.info(f"Created dummy email file: {dummy_eml_path}")

        print("\n--- Analyzing Email File ---")
        analysis_result_file = check_email_safety(email_filepath=dummy_eml_path)
        print(json.dumps(analysis_result_file, indent=2, default=str))
        # os.remove(dummy_eml_path)

    except Exception as e:
        print(f"\nError during file analysis example: {e}")
        print("Check 'check_link_details' implementation and Gemini setup.")


    # --- Option 2: Analyze an email string ---
    print("\n--- Analyzing Email String (Known Bad Example) ---")
    email_string_content = """From: PayPal <service@paypal-security-update-center.com>
Subject: Issue with billing - Action Required

Hello valued member, Login here urgently <a href="http://paypal-security-update-center.com/verify">Update Now</a> to avoid fees.
"""
    try:
        analysis_result_string = check_email_safety(email_content_str=email_string_content)
        print(json.dumps(analysis_result_string, indent=2, default=str))
    except Exception as e:
        print(f"\nError during string analysis example: {e}")
        print("Check 'check_link_details' implementation and Gemini setup.")

    # --- Option 3: Analyze a legit example ---
    print("\n--- Analyzing Email String (Legit Example) ---")
    email_string_legit = """From: Google <no-reply@google.com>
Subject: Security alert for Your Google Account

Hi User,
We detected a new sign-in to your Google Account on a new device. If this was you, you can ignore this email.
If you don't recognize this activity, please check your recently used devices now: https://myaccount.google.com/notifications

Thank you,
The Google Accounts team
"""
    try:
        analysis_result_legit = check_email_safety(email_content_str=email_string_legit)
        print(json.dumps(analysis_result_legit, indent=2, default=str))
    except Exception as e:
        print(f"\nError during legit analysis example: {e}")
        print("Check 'check_link_details' implementation and Gemini setup.")