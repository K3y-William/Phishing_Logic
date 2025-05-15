from flask import app
import base64
from googleapiclient.errors import HttpError

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

#TODO write auto scan demon
# def auto_scan_loop():
#     while True:
#         emails = email_handler.list_inbox_messages(app.gmail_service, max_results=10)
#         for email in emails:
#             if email['id'] not in scanned_ids:
#                 scanned_ids.add(email['id'])
#                 # run scam filter
#         time.sleep(300)
