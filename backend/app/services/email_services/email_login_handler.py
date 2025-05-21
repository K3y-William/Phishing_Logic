# Email reading/parsing
# Login, logout
import os.path
import base64
import textwrap
from datetime import datetime, timedelta

from backend.app.services.llm_handler import analyze_content_with_gemini
from backend.app.services.domain_check import extract_links_without_scheme,get_domain_from_email_format, check_link_details

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# --- Configuration ---
# If modifying these scopes, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly'] # Read-only access
TOKEN_PATH = '../token.json'
CREDENTIALS_PATH = 'client_secret.json'
MAX_RESULTS = 5 # How many emails to fetch

# --- Functions ---

def authenticate_gmail():
    """Shows basic usage of the Gmail API.
    Handles user authentication and returns the API service object.
    """
    creds = None
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first time.
    if os.path.exists(TOKEN_PATH):
        try:
            creds = Credentials.from_authorized_user_file(TOKEN_PATH, SCOPES)
        except ValueError as e:
             print(f"Error loading token file: {e}. It might be corrupted.")
             creds = None # Force re-authentication

    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                print("Credentials expired, refreshing...")
                creds.refresh(Request())
            except Exception as e:
                print(f"Error refreshing token: {e}")
                print("Could not refresh token. Please re-authenticate.")
                if os.path.exists(TOKEN_PATH):
                    os.remove(TOKEN_PATH) # Remove invalid token
                creds = None # Force re-authentication
        else:
             # Only try to load credentials if token refresh failed or no token exists
             if not os.path.exists(CREDENTIALS_PATH):
                 print(f"ERROR: Credentials file not found at '{CREDENTIALS_PATH}'")
                 print("Please download it from Google Cloud Console and save it.")
                 return None

             try:
                 flow = InstalledAppFlow.from_client_secrets_file(
                     CREDENTIALS_PATH, SCOPES)
                 # Run local server flow automatically handles browser opening & code exchange
                 creds = flow.run_local_server(port=8080)
             except Exception as e:
                 print(f"Error during authentication flow: {e}")
                 return None

        # Save the credentials for the next run only if successfully obtained/refreshed
        if creds:
            try:
                with open(TOKEN_PATH, 'w') as token:
                    token.write(creds.to_json())
                print(f"Credentials saved to {TOKEN_PATH}")
            except Exception as e:
                print(f"Error saving token: {e}")

    if not creds:
        print("Failed to obtain credentials.")
        return None

    # Build the Gmail API service
    try:
        service = build('gmail', 'v1', credentials=creds)
        return service
    except HttpError as error:
        print(f'An error occurred building the service: {error}')
        return None
    except Exception as e:
        print(f'An unexpected error occurred building the service: {e}')
        return None


def get_message_details(service, msg_id):
    """Gets detailed information for a specific message."""
    try:
        # Get the full message details
        message = service.users().messages().get(userId='me', id=msg_id, format='full').execute()

        payload = message.get('payload', {})
        headers = payload.get('headers', [])
        parts = payload.get('parts', [])

        # Extract common headers
        subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), 'No Subject')
        sender = next((h['value'] for h in headers if h['name'].lower() == 'from'), 'Unknown Sender')
        date = next((h['value'] for h in headers if h['name'].lower() == 'date'), 'Unknown Date')

        # Extract body (handle different structures)
        body_text = ""
        if 'data' in payload.get('body', {}): # Simple case, body directly in payload
            encoded_data = payload['body']['data']
            decoded_bytes = base64.urlsafe_b64decode(encoded_data + '===') # Add padding if needed
            body_text = decoded_bytes.decode('utf-8', errors='replace')
        elif parts: # Multipart message
            # Look for text/plain part first
            plain_part = next((p for p in parts if p.get('mimeType') == 'text/plain'), None)
            if plain_part and 'data' in plain_part.get('body', {}):
                encoded_data = plain_part['body']['data']
                decoded_bytes = base64.urlsafe_b64decode(encoded_data + '===')
                body_text = decoded_bytes.decode('utf-8', errors='replace')
            else:
                # Fallback: Try to find *any* part with data or recursively check nested parts
                # (This is a simplified example, real-world parsing can be more complex)
                def find_body_in_parts(part_list):
                    for part in part_list:
                        if 'data' in part.get('body', {}):
                            encoded_data = part['body']['data']
                            decoded_bytes = base64.urlsafe_b64decode(encoded_data + '===')
                            # Decode carefully, might not be utf-8
                            try:
                                return decoded_bytes.decode('utf-8', errors='replace')
                            except UnicodeDecodeError:
                                try:
                                    # Try latin-1 as a common fallback
                                    return decoded_bytes.decode('latin-1', errors='replace')
                                except Exception:
                                    return "[Could not decode body part]"
                        # Recurse if there are nested parts
                        if 'parts' in part:
                            found_body = find_body_in_parts(part.get('parts', []))
                            if found_body:
                                return found_body
                    return "" # No suitable body found in these parts

                body_text = find_body_in_parts(parts)

        return {
            'id': msg_id,
            'subject': subject,
            'from': sender,
            'date': date,
            'snippet': message.get('snippet', 'No Snippet'),
            'body': body_text[:3000] + ('...' if len(body_text) > 3000 else '') # Truncate long bodies
        }

    except HttpError as error:
        print(f'An error occurred getting message {msg_id}: {error}')
        return None
    except Exception as e:
        print(f'An unexpected error occurred getting message {msg_id}: {e}')
        return None


def list_inbox_messages_most_recent(service, max_results=5):
    """Lists most recent messages in the user's inbox."""
    try:
        # Call the Gmail API to fetch INBOX messages
        results = service.users().messages().list(
            userId='me',
            labelIds=['INBOX'],
            maxResults=max_results
        ).execute()

        messages = results.get('messages', [])

        if not messages:
            print("No messages found in INBOX.")
            return []
        else:
            print(f"Found {len(messages)} messages (showing up to {max_results}):\n")
            message_details_list = []
            # x = {}
            # x["id'] = {"te"}
            for message_stub in messages:
                msg_id = message_stub['id']
                print(f"Fetching details for message ID: {msg_id}...")
                details = get_message_details(service, msg_id)
                if details:
                    message_details_list.append(details)
                    # print("-" * 30)
                    # print(f"  ID: {details['id']}")
                    # print(f"  From: {details['from']}")
                    # print(f"  Subject: {details['subject']}")
                    # print(f"  Date: {details['date']}")
                    # print(f"  Snippet: {details['snippet']}")
                    # Uncomment to print the first 500 chars of the body
                    # print(f"  Body (Preview):\n{details['body']}")
                    # print("-" * 30 + "\n")
            return message_details_list

    except HttpError as error:
        # TODO(developer) - Handle errors from gmail API.
        print(f'An API error occurred: {error}')
        return []
    except Exception as e:
        print(f'An unexpected error occurred listing messages: {e}')
        return []


# --- New Search Functions ---

def _fetch_and_process_messages(service, query_string, max_results=10, label_ids=None):
    """
    Internal helper function to fetch messages based on a query and process them.
    """
    if label_ids is None:
        label_ids = ['INBOX'] # Default to INBOX if not specified

    try:
        results = service.users().messages().list(
            userId='me',
            q=query_string,
            labelIds=label_ids,
            maxResults=max_results
        ).execute()

        messages_stubs = results.get('messages', [])

        if not messages_stubs:
            print(f"No messages found matching query: '{query_string}' in labels: {label_ids}")
            return []
        else:
            print(f"Found {len(messages_stubs)} message stubs (up to {max_results}) matching query.")
            print("Fetching details...")
            message_details_list = []
            for i, message_stub in enumerate(messages_stubs):
                msg_id = message_stub['id']
                print(f"  ({i+1}/{len(messages_stubs)}) Fetching message ID: {msg_id}")
                # Using your get_message_details function
                details = get_message_details(service, msg_id)
                if details:
                    message_details_list.append(details)
            return message_details_list

    except HttpError as error:
        print(f'An API error occurred during list/fetch: {error}')
        return []
    except Exception as e:
        print(f'An unexpected error occurred during list/fetch: {e}')
        return []

def search_messages_by_sender(service, sender_email_or_name, max_results=5, label_ids=None):
    """
    Lists messages from a specific sender.
    """
    print(f"\nSearching for messages from: '{sender_email_or_name}'...")
    # If sender_email_or_name contains spaces and is not an email, it should ideally be quoted for Gmail search.
    # Example: "John Doe" or john.doe@example.com
    query = f"from:({sender_email_or_name})" # Using parentheses for broader match, or quote if exact.
    return _fetch_and_process_messages(service, query, max_results, label_ids)

def search_messages_by_subject(service, subject_keywords, max_results=5, label_ids=None):
    """
    Lists messages with specific keywords in the subject.
    """
    print(f"\nSearching for messages with subject containing: '{subject_keywords}'...")
    query = f"subject:({subject_keywords})" # Using parentheses for broader match, or quote if exact phrase.
    return _fetch_and_process_messages(service, query, max_results, label_ids)

def search_messages_by_date_range(service, start_date_str=None, end_date_str=None, max_results=5, label_ids=None):
    """
    Lists messages within a specific date range. Dates in 'YYYY/MM/DD' format.
    If only start_date_str is provided, searches for messages after that date.
    If only end_date_str is provided, searches for messages before that date (exclusive of the day).
    """
    query_parts = []
    date_info = []
    if start_date_str:
        query_parts.append(f"after:{start_date_str}")
        date_info.append(f"after {start_date_str}")
    if end_date_str:
        try:
            # To make end_date_str inclusive for user expectation,
            # use 'before:' the day *after* end_date_str.
            end_dt_obj = datetime.strptime(end_date_str, "%Y/%m/%d")
            next_day_dt_obj = end_dt_obj + timedelta(days=1)
            next_day_str = next_day_dt_obj.strftime("%Y/%m/%d")
            query_parts.append(f"before:{next_day_str}")
            date_info.append(f"on or before {end_date_str}")
        except ValueError:
            print(f"Warning: Invalid end_date_str format: {end_date_str}. Should be YYYY/MM/DD. Ignoring end date.")

    if not query_parts:
        print("Error: No valid date criteria provided for date search.")
        return []

    query = " ".join(query_parts)
    print(f"\nSearching for messages {' and '.join(date_info)}...")
    return _fetch_and_process_messages(service, query, max_results, label_ids)

def search_messages_combined(service, sender=None, subject=None, start_date=None, end_date=None,
                             has_attachment=None, custom_query_part=None,
                             max_results=5, label_ids=None):
    """
    Searches messages based on a combination of criteria.
    """
    query_parts = []
    description_parts = []

    if sender:
        query_parts.append(f"from:({sender})")
        description_parts.append(f"from '{sender}'")
    if subject:
        query_parts.append(f"subject:({subject})")
        description_parts.append(f"subject '{subject}'")
    if start_date:
        query_parts.append(f"after:{start_date}")
        description_parts.append(f"after {start_date}")
    if end_date:
        try:
            end_dt_obj = datetime.strptime(end_date, "%Y/%m/%d")
            next_day_dt_obj = end_dt_obj + timedelta(days=1)
            next_day_str = next_day_dt_obj.strftime("%Y/%m/%d")
            query_parts.append(f"before:{next_day_str}")
            description_parts.append(f"on or before {end_date}")
        except (ValueError, TypeError):
            if end_date is not None:
                print(f"Warning: Invalid end_date format: {end_date}. Ignoring.")
    if has_attachment is True:
        query_parts.append("has:attachment")
        description_parts.append("with attachments")
    elif has_attachment is False:
        query_parts.append("-has:attachment")
        description_parts.append("without attachments")
    if custom_query_part:
        query_parts.append(custom_query_part)
        description_parts.append(f"custom query '{custom_query_part}'")


    if not query_parts:
        print("\nNo search criteria provided. Listing most recent messages from specified labels.")
        return _fetch_and_process_messages(service, "", max_results, label_ids) # Empty query for most recent

    query = " ".join(query_parts)
    search_description = ", ".join(description_parts)
    print(f"\nCombined search for messages {search_description} with query: '{query}'...")
    return _fetch_and_process_messages(service, query, max_results, label_ids)


# --- Helper to print message summaries ---
def print_message_summary_list(messages_list):
    if not messages_list:
        print("No messages to display for this search.")
        return
    print(f"\n--- Displaying {len(messages_list)} messages ---")
    for i, msg in enumerate(messages_list):
        print(f"\nMessage {i+1}:")
        print(f"  ID: {msg['id']}")
        print(f"  From: {msg['from']}")
        print(f"  Subject: {msg['subject']}")
        print(f"  Date: {msg['date']}")
        print(f"  Snippet: {msg['snippet'][:100]}...") # Show more of the snippet
        # print(f"  Body Preview: {msg['body'][:200]}...") # Uncomment to see body preview
    print("-" * 30 + "\n")


def format_analysis_output_with_wrapping(data_dict, max_line_width=75):
    """
    Formats the analysis text from the input dictionary for better readability,
    wrapping long lines in the body content.

    Args:
        data_dict (dict): A dictionary expected to have an 'analysis' key
                          with a string value containing the analysis text.
        max_line_width (int): The maximum width for lines in the body.
    """
    if 'analysis' not in data_dict:
        print("Error: 'analysis' key not found in the input dictionary.")
        return

    analysis_text = data_dict['analysis']
    lines = analysis_text.split('\n')

    print("=" * 80)
    print("Phishing Email Analysis Report".center(80))
    print("=" * 80)

    in_bullet_section = False  # To handle multi-line bullet content indentation

    for line in lines:
        stripped_line = line.strip()

        if not stripped_line:  # Handles blank lines (originally \n\n)
            print()
            in_bullet_section = False
            continue

        # Main Headers (like "Risk Assessment:", "Summary of Findings:")
        if stripped_line.startswith('**') and stripped_line.endswith('**:'):
            header_text = stripped_line.replace('**', '').strip().upper()
            print(f"\n{header_text}")
            print("-" * len(header_text))
            in_bullet_section = False
        elif stripped_line.startswith('**') and ':' in stripped_line:  # For "Risk Assessment:** High"
            parts = stripped_line.split(':', 1)
            header_part = parts[0].replace('**', '').strip().upper()
            value_part = parts[1].strip()
            print(f"\n{header_part}: {value_part}")
            print("-" * (len(header_part) + len(value_part) + 2))
            in_bullet_section = False
        # Bullet Points
        elif stripped_line.startswith('* '):
            bullet_content = stripped_line[2:]
            # Wrap the content of the bullet point.
            # The first line of the wrapped content gets the "  - " prefix.
            # Subsequent wrapped lines get "    " prefix for alignment.
            print(textwrap.fill(bullet_content,
                                width=max_line_width,
                                initial_indent="  - ",
                                subsequent_indent="    "))
            in_bullet_section = True
        # Regular paragraph lines OR continuation of bullet points (that were on a new line in original input)
        else:
            text_to_wrap = stripped_line # Already stripped
            if in_bullet_section:
                # This is a continuation of the previous bullet point.
                # Indent consistently with wrapped bullet content.
                print(textwrap.fill(text_to_wrap,
                                    width=max_line_width,
                                    initial_indent="    ",  # Subsequent lines of a bullet item
                                    subsequent_indent="    "))
            else:
                # This is a general paragraph line, not part of a bullet list.
                print(textwrap.fill(text_to_wrap, width=max_line_width))

    print("=" * 80)


def analyze_email_recent(gmail_service):
    """Analyze most recent emails"""
    messages = list_inbox_messages_most_recent(gmail_service, max_results=MAX_RESULTS)
    # call llm analyze
    for x in range(len(messages)):
        links = extract_links_without_scheme(str(messages[x]))
        links_info = []
        print(links)

        for l in links:
            links_info.append(check_link_details(l))
        sender_domain = get_domain_from_email_format(messages[x]['from'])
        sender_domain_analysis = check_link_details(sender_domain)
        format_analysis_output_with_wrapping(analyze_content_with_gemini(messages[x]['subject'], messages[x]['body'], sender_domain_analysis,
                                          links_info))

def analyze_email_specific(gmail_service,sender=None, subject=None, start_date=None, end_date=None,
                             has_attachment=None, custom_query_part=None,
                             max_results=5, label_ids=None):
    """Analyze emails filtered by a set of params"""
    messages = search_messages_combined(gmail_service,sender,subject,start_date,end_date,has_attachment,custom_query_part,max_results,label_ids)
    for x in range(len(messages)):
        links = extract_links_without_scheme(str(messages[x]))
        links_info = []

        for l in links:
            links_info.append(check_link_details(l))
        sender_domain = get_domain_from_email_format(messages[x]['from'])
        sender_domain_analysis = check_link_details(sender_domain)
        format_analysis_output_with_wrapping(analyze_content_with_gemini(messages[x]['subject'], messages[x]['body'], sender_domain_analysis,
                                          links_info))
def email_login():
    """Login gmail service"""
    print("Attempting to authenticate and connect to Gmail...")
    gmail_service = authenticate_gmail()

    if gmail_service:
        print("\nAuthentication successful. Fetching inbox messages...")
        return gmail_service
    else:
        print("\nCould not connect to Gmail API. Exiting.")

# --- Main Execution ---
if __name__ == '__main__':
    gmail_service = email_login()
    # analyze_email_recent(gmail_service)
    analyze_email_specific(gmail_service = gmail_service, subject = "Boss\'s Message")