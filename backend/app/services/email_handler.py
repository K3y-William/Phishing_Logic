# Email reading/parsing
# Login, logout
import os.path
import base64
from email import message_from_bytes # For parsing email content

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# --- Configuration ---
# If modifying these scopes, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly'] # Read-only access
TOKEN_PATH = 'token.json'
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
                 creds = flow.run_local_server(port=0)
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
            'body': body_text[:500] + ('...' if len(body_text) > 500 else '') # Truncate long bodies
        }

    except HttpError as error:
        print(f'An error occurred getting message {msg_id}: {error}')
        return None
    except Exception as e:
        print(f'An unexpected error occurred getting message {msg_id}: {e}')
        return None


def list_inbox_messages(service, max_results=5):
    """Lists messages in the user's inbox."""
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
            for message_stub in messages:
                msg_id = message_stub['id']
                print(f"Fetching details for message ID: {msg_id}...")
                details = get_message_details(service, msg_id)
                if details:
                    message_details_list.append(details)
                    print("-" * 30)
                    print(f"  ID: {details['id']}")
                    print(f"  From: {details['from']}")
                    print(f"  Subject: {details['subject']}")
                    print(f"  Date: {details['date']}")
                    print(f"  Snippet: {details['snippet']}")
                    # Uncomment to print the first 500 chars of the body
                    # print(f"  Body (Preview):\n{details['body']}")
                    print("-" * 30 + "\n")
            return message_details_list

    except HttpError as error:
        # TODO(developer) - Handle errors from gmail API.
        print(f'An API error occurred: {error}')
        return []
    except Exception as e:
        print(f'An unexpected error occurred listing messages: {e}')
        return []

# --- Main Execution ---
if __name__ == '__main__':
    print("Attempting to authenticate and connect to Gmail...")
    gmail_service = authenticate_gmail()

    if gmail_service:
        print("\nAuthentication successful. Fetching inbox messages...")
        list_inbox_messages(gmail_service, max_results=MAX_RESULTS)
    else:
        print("\nCould not connect to Gmail API. Exiting.")