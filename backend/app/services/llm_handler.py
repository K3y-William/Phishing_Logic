import os
import re
import email
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse
import logging
import datetime


# --- Potentially needed imports for YOUR check_link_details implementation ---
# Make sure all libraries used within your check_link_details are imported here
# Examples (adjust based on your actual code):
import whois
import dns.resolver
import socket
# Add any others your function uses...

# --- OpenAI ---
from openai import OpenAI, APIError

from domain_check import check_link_details

# --- Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
API_KEY_FILE = "key.txt"

# --- OpenAI API Setup ---
def get_openai_key(filepath=API_KEY_FILE):
    """Reads the OpenAI API key from a file."""
    try:
        with open(filepath, 'r') as f:
            key = f.read().strip()
            if key:
                return key
            else:
                logging.error(f"API key file '{filepath}' is empty.")
                return None
    except FileNotFoundError:
        logging.error(f"API key file '{filepath}' not found.")
        return None
    except Exception as e:
        logging.error(f"Error reading API key file '{filepath}': {e}")
        return None

# Initialize OpenAI client
api_key = get_openai_key()
if api_key:
    try:
        client = OpenAI(api_key=api_key)
        logging.info("OpenAI client initialized successfully.")
    except Exception as e:
        logging.error(f"Failed to initialize OpenAI client: {e}")
        client = None
else:
    logging.error("OpenAI API key not found or empty. OpenAI features will be disabled.")
    client = None

# --- Email Parsing Logic ---
def parse_email(email_content_bytes):
    """Parses raw email bytes to extract headers and body."""
    # This function remains the same as before.
    # It does NOT currently extract DKIM-Signature headers.
    # If your check_link_details needs DKIM selectors, this parsing
    # function would need to be enhanced.
    try:
        msg = BytesParser(policy=policy.default).parsebytes(email_content_bytes)

        sender = msg.get('From', 'Unknown Sender')
        subject = msg.get('Subject', 'No Subject')
        # Extract other headers if needed (e.g., DKIM-Signature)
        # dkim_header = msg.get('DKIM-Signature')

        body_plain = None
        body_html = None

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get('Content-Disposition'))
                if 'attachment' in content_disposition:
                    continue
                if content_type == 'text/plain' and body_plain is None:
                    try:
                        body_plain = part.get_payload(decode=True).decode(part.get_content_charset('utf-8'), errors='replace')
                    except Exception as e:
                        logging.warning(f"Could not decode plain text part: {e}")
                        body_plain = f"[Decoding Error: {e}]"
                elif content_type == 'text/html' and body_html is None:
                     try:
                         body_html = part.get_payload(decode=True).decode(part.get_content_charset('utf-8'), errors='replace')
                     except Exception as e:
                        logging.warning(f"Could not decode HTML part: {e}")
                        body_html = f"[Decoding Error: {e}]"
        else:
            content_type = msg.get_content_type()
            if content_type == 'text/plain':
                 try:
                    body_plain = msg.get_payload(decode=True).decode(msg.get_content_charset('utf-8'), errors='replace')
                 except Exception as e:
                    logging.warning(f"Could not decode non-multipart plain text body: {e}")
                    body_plain = f"[Decoding Error: {e}]"
            elif content_type == 'text/html':
                 try:
                    body_html = msg.get_payload(decode=True).decode(msg.get_content_charset('utf-8'), errors='replace')
                 except Exception as e:
                    logging.warning(f"Could not decode non-multipart HTML body: {e}")
                    body_html = f"[Decoding Error: {e}]"

        body = body_plain if body_plain else body_html if body_html else "[No readable body found]"
        sender_email = 'Unknown'
        parsed_addr = email.utils.parseaddr(sender)
        if parsed_addr and '@' in parsed_addr[1]:
            sender_email = parsed_addr[1]

        sender_domain = None
        if sender_email != 'Unknown' and '@' in sender_email:
            try:
                sender_domain = sender_email.split('@')[1]
            except IndexError:
                pass

        return {
            'sender_header': sender,
            'sender_email': sender_email,
            'sender_domain': sender_domain,
            'subject': subject,
            'body': body,
            'body_plain': body_plain,
            'body_html': body_html
            # If you enhance parsing, you could return extracted DKIM selectors here
            # 'dkim_selectors': extracted_dkim_selectors
        }

    except Exception as e:
        logging.error(f"Failed to parse email content: {e}")
        return {
            'error': f"Failed to parse email: {e}",
            'sender_header': 'Parse Error',
            'sender_email': 'Parse Error',
            'sender_domain': None,
            'subject': 'Parse Error',
            'body': 'Parse Error',
            'body_plain': None,
            'body_html': None,
        }


# --- Link Extraction ---
def extract_links(text):
    """Extracts URLs from a given text string."""
    # This function remains the same
    url_pattern = re.compile(r'(?:(?:https?|ftp)://|www\.)[\w/\-?=%&.:~+#]+[\w/\-?=%&~+#]')
    if text:
        # Added basic filtering for common non-actionable links
        links = url_pattern.findall(text)
        filtered_links = [link for link in links if not link.startswith('mailto:')]
        # You might want to add more filtering here (e.g., image source domains if desired)
        return filtered_links
    else:
        return []


# --- OpenAI Content Analysis ---
def analyze_content_with_openai(subject, body):
    """Uses OpenAI API to analyze email content for scam characteristics."""
    # This function remains the same
    if not client:
        return {"error": "OpenAI client not initialized. Cannot analyze content."}
    if not body or body.strip() == "[No readable body found]" or body.strip() == "Parse Error":
         return {"warning": "Email body is empty or could not be parsed. Cannot analyze content."}

    prompt = f"""
    Analyze the following email content (Subject and Body) for potential scam characteristics.
    Consider urgency, suspicious requests (login, personal info, money), generic greetings,
    poor grammar/spelling, unexpected attachments/links, impersonation, and too-good-to-be-true offers.

    Provide a brief summary of your findings and a risk assessment level (Low, Medium, High).
    Explain your reasoning clearly.

    Subject: {subject}

    Body:
    {body[:3500]}  # Limit body length

    Analysis:
    """

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini", # Or "gpt-3.5-turbo" etc.
            messages=[
                {"role": "system", "content": "You are a helpful assistant specialized in detecting email scams."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2,
            max_tokens=300
        )
        analysis = response.choices[0].message.content.strip()
        return {"analysis": analysis}
    except APIError as e:
        logging.error(f"OpenAI API error: {e}")
        return {"error": f"OpenAI API error: {e}"}
    except Exception as e:
        logging.error(f"Error during OpenAI analysis: {e}")
        return {"error": f"An unexpected error occurred during OpenAI analysis: {e}"}


# --- Main Orchestration Function ---
def check_email_safety(email_filepath=None, email_content_str=None):
    """
    Analyzes an email from a file or string for scam indicators.
    """
    # This function is updated to call your check_link_details signature
    if not email_filepath and not email_content_str:
        return {"error": "No email file path or content string provided."}
    if email_filepath and email_content_str:
         return {"error": "Provide either email_filepath OR email_content_str, not both."}

    email_bytes = None
    if email_filepath:
        try:
            with open(email_filepath, 'rb') as f:
                email_bytes = f.read()
        except FileNotFoundError:
            return {"error": f"Email file not found: {email_filepath}"}
        except Exception as e:
            return {"error": f"Error reading email file {email_filepath}: {e}"}
    elif email_content_str:
         try:
              email_bytes = email_content_str.encode('utf-8', errors='replace')
         except Exception as e:
              return {"error": f"Error encoding email string to bytes: {e}"}

    if not email_bytes:
         return {"error": "Could not obtain email content bytes."}

    logging.info("Starting email analysis...")

    # 1. Parse Email
    parsed_email = parse_email(email_bytes)
    if parsed_email.get('error'):
        logging.error(f"Email parsing failed: {parsed_email['error']}")
        return {"error": parsed_email['error'], "parsed_data": parsed_email}

    logging.info(f"Parsed email: Sender='{parsed_email['sender_email']}', Subject='{parsed_email['subject']}'")
    # Note: DKIM selectors are not currently extracted by parse_email.
    # If you need them, enhance parse_email and retrieve them here.
    # extracted_dkim_selectors = parsed_email.get('dkim_selectors')


    # 2. Analyze Content with OpenAI
    openai_result = analyze_content_with_openai(parsed_email['subject'], parsed_email['body'])
    logging.info(f"OpenAI Analysis Result: {openai_result}")


    # 3. Analyze Sender Domain
    sender_domain_analysis = None
    if parsed_email['sender_domain']:
        logging.info(f"Analyzing sender domain: {parsed_email['sender_domain']}")
        # Call check_link_details for the domain.
        # DKIM selectors are not passed here as they usually relate to the specific email,
        # not just the domain, and aren't extracted currently.
        sender_domain_analysis = check_link_details(
            url_string="https://"+parsed_email['sender_domain'],
            dkim_selectors=None # Pass None explicitly or rely on default
        )
    else:
        logging.warning("Sender domain could not be extracted.")
        sender_domain_analysis = {"error": "Sender domain not found in headers"}


    # 4. Extract and Analyze Links in Body
    body_for_links = parsed_email['body_html'] if parsed_email['body_html'] else parsed_email['body_plain']
    extracted_links = extract_links(body_for_links)
    logging.info(f"Found {len(extracted_links)} links in the email body.")

    link_analysis_results = {}
    unique_links = set(extracted_links)
    for link in unique_links:
        logging.info(f"Analyzing link: {link}")
        # Call check_link_details for each link. DKIM check is not relevant for
        # arbitrary links found in the body, so dkim_selectors=None is appropriate.
        link_analysis_results[link] = check_link_details(
            url_string=link,
            dkim_selectors=None # Pass None explicitly or rely on default
        )
        # Optional delay if needed
        # import time
        # time.sleep(0.5)


    # 5. Consolidate Results
    final_report = {
        "input_source": email_filepath if email_filepath else "String Input",
        "parsing_info": {
            "sender_header": parsed_email['sender_header'],
            "sender_email": parsed_email['sender_email'],
            "sender_domain": parsed_email['sender_domain'],
            "subject": parsed_email['subject'],
        },
        "openai_content_analysis": openai_result,
        "sender_domain_analysis": sender_domain_analysis,
        "links_found": len(extracted_links),
        "unique_links_analyzed": len(unique_links),
        "link_analysis": link_analysis_results,
        "overall_assessment": "Review individual sections for details."
    }

    # Add simple overall risk assessment logic (remains the same, but uses results
    # from your potentially different check_link_details structure)
    risk_factors = []
    if openai_result.get('analysis') and any(word in openai_result['analysis'].lower() for word in ['medium', 'high', 'suspicious', 'scam', 'phishing']):
         risk_factors.append("OpenAI flagged content.")

    # Check sender domain results (adapt keys if your function returns different ones)
    if sender_domain_analysis:
        if sender_domain_analysis.get('error'):
            risk_factors.append(f"Sender domain check error: {sender_domain_analysis['error']}")
        # Example: Check if WHOIS data suggests a new domain (assuming 'whois' contains structured data like before)
        whois_data = sender_domain_analysis.get('whois')
        if isinstance(whois_data, dict) and whois_data.get('warning'): # Check your actual whois result structure
             risk_factors.append(f"Sender domain issue: {whois_data['warning']}")
        # Example: Check SPF/DMARC results (check your actual result format)
        if 'fail' in str(sender_domain_analysis.get('spf', '')).lower():
             risk_factors.append("Sender domain SPF potentially failing.")
        # Add DMARC policy check based on your function's output format
        # if sender_domain_analysis.get('dmarc_policy') != 'Strict...':
        #      risk_factors.append("Sender DMARC policy not strict.")

    # Check link results
    for link, analysis in link_analysis_results.items():
         if analysis:
            domain_checked = analysis.get('domain', link) # Use domain from results if available
            if analysis.get('error'):
                risk_factors.append(f"Link check error for {domain_checked}: {analysis['error']}")
            link_whois = analysis.get('whois')
            if isinstance(link_whois, dict) and link_whois.get('warning'): # Check your actual whois result structure
                risk_factors.append(f"Link domain issue ({domain_checked}): {link_whois['warning']}")
            # Add more checks based on link analysis results (SPF, DMARC of link domains?)

    if risk_factors:
        final_report["overall_assessment"] = f"Potential Risk Detected. Factors: {'; '.join(risk_factors)}"
    else:
        final_report["overall_assessment"] = "Initial checks suggest low risk, but requires functional 'check_link_details' and careful review."

    logging.info("Email analysis complete.")
    return final_report


# --- Example Usage ---
if __name__ == "__main__":
    print("Starting email checker examples...")
    print("NOTE: The 'check_link_details' function needs your actual implementation.")

    # --- Option 1: Analyze an email file ---
    dummy_eml_content = """From: Spammer <spammer@3mku6ze.com>
To: You <you@example.com>
Subject: Urgent Action Required! Update Your Account!

Dear Valued Customer,

We detected unusual activity on your account. Please click the link below immediately to verify your identity and prevent account suspension.

Click here: https://totally-legit-update-portal.suspicious-domain.xyz/login?session=bad123

Failure to do so within 24 hours will result in permanent closure. Also check www.google.com for comparison.

Sincerely,
Your Bank Security Team (Maybe)
"""
    dummy_eml_path = "test_email.eml"
    try:
        with open(dummy_eml_path, "w") as f:
            f.write(dummy_eml_content)
        logging.info(f"Created dummy email file: {dummy_eml_path}")

        print(f"\n--- Analyzing Email File ({dummy_eml_path}) ---")
        analysis_result_file = check_email_safety(email_filepath=dummy_eml_path)

        import json
        print(json.dumps(analysis_result_file, indent=2, default=str))

        # os.remove(dummy_eml_path) # Keep file for inspection if needed

    except Exception as e:
        print(f"\nError during file analysis example: {e}")
        logging.exception("Error in file analysis example block")


    # --- Option 2: Analyze an email string ---
    print("\n--- Analyzing Email String (Phishing Example) ---")
    email_string_content = """Return-Path: <bounce@notification.paypal.com>
From: PayPal <service@paypal.com>
Subject: Your account needs immediate attention

Hello Customer,

There seems to be an issue with your PayPal account billing information.
Please log in securely using the button below to update your details:

<a href="http://paypal-security-update-center.com/verify">Update Now</a>

Thanks,
PayPal Support Team
(This is a known phishing example domain)
"""
    try:
        analysis_result_string = check_email_safety(email_content_str=email_string_content)
        import json
        print(json.dumps(analysis_result_string, indent=2, default=str))
    except Exception as e:
        print(f"\nError during string analysis example: {e}")
        logging.exception("Error in string analysis example block")


    # --- Option 3: Test with a known good sender ---
    print("\n--- Analyzing Email String (Legit Example) ---")
    email_string_legit = """From: Google <no-reply@google.com>
Subject: Security alert

We detected a new sign-in to your Google Account.

Check activity: https://myaccount.google.com/notifications

Thank you,
The Google Accounts team
"""
    try:
        analysis_result_legit = check_email_safety(email_content_str=email_string_legit)
        import json
        print(json.dumps(analysis_result_legit, indent=2, default=str))
    except Exception as e:
        print(f"\nError during legit string analysis example: {e}")
        logging.exception("Error in legit string analysis example block")