import requests
import time
import sys
import json
from urllib.parse import quote # For URL encoding the email

# --- Configuration ---
# HIBP API v3 endpoint for checking a single account
HIBP_API_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{account}"

# REQUIRED: Set a descriptive User-Agent. Replace 'YourAppNameOrScript'
# HIBP requires this for API v3.
HEADERS = {
    'User-Agent': 'Python-PwnedCheckScript-v1.0',
    'hibp-api-key': None # Set your API key here if you have one (optional for basic use)
}

# Delay between requests to respect HIBP rate limiting (in seconds)
# Anonymous access is typically rate-limited to ~1 request per 1.5-2 seconds.
REQUEST_DELAY = 2.0

# --- Functions ---

def check_email_breach(email_address):
    """
    Checks a single email address against the HIBP API.

    Args:
        email_address (str): The email address to check.

    Returns:
        None: Prints the results directly.
    """
    if not email_address or '@' not in email_address:
        print("Error: Invalid email address format provided.")
        return

    # URL-encode the email address to handle special characters safely
    encoded_email = quote(email_address)
    url = HIBP_API_URL.format(account=encoded_email)

    print(f"[*] Checking email: {email_address}")
    # Add a delay before making the request to comply with rate limits
    print(f"[*] Waiting {REQUEST_DELAY} seconds before API call...")
    time.sleep(REQUEST_DELAY)

    try:
        response = requests.get(url, headers=HEADERS, timeout=15) # 15-second timeout

        # --- Handle Response ---

        # 200 OK: Email found in breaches
        if response.status_code == 200:
            print("\n[!] Oh no — PWNED!")
            try:
                breaches = response.json()
                print(f"[*] Found in the following breaches ({len(breaches)}):")
                for breach in breaches:
                    print(f"  - {breach.get('Name', 'Unknown Breach')} ({breach.get('BreachDate', 'N/A')})")
                    # You can print more details if needed:
                    # print(f"    Domain: {breach.get('Domain', 'N/A')}")
                    # print(f"    Data Classes: {', '.join(breach.get('DataClasses', []))}")
                    # print(f"    Description: {breach.get('Description', '')[:100]}...") # Show preview
            except json.JSONDecodeError:
                print("[!] Found in breaches, but couldn't parse the details from the API response.")
                print(f"Raw response: {response.text}")
            except Exception as e:
                print(f"[!] Found in breaches, but an error occurred processing details: {e}")

        # 404 Not Found: Email not found in any breaches (Good!)
        elif response.status_code == 404:
            print("\n[+] Good news — NOT PWNED!")
            print("[*] This email address was not found in any known breaches checked by HIBP.")

        # 400 Bad Request: Often means malformed email, but could be API changes
        elif response.status_code == 400:
            print(f"\n[-] Error: Bad Request (400). Is the email format correct? Response: {response.text}")

        # 401 Unauthorized: Missing or invalid API key (if you added one)
        elif response.status_code == 401:
             print(f"\n[-] Error: Unauthorized (401). Check your HIBP API Key in the script. Response: {response.text}")

        # 403 Forbidden: Often means User-Agent header is missing or blocked
        elif response.status_code == 403:
            print(f"\n[-] Error: Forbidden (403). Is the User-Agent header set correctly? Response: {response.text}")

        # 429 Too Many Requests: Rate limit exceeded
        elif response.status_code == 429:
            print("\n[-] Error: Too Many Requests (429). Please wait longer between checks.")
            print(f"[*] HIBP Rate Limit likely exceeded. Try increasing REQUEST_DELAY.")
            retry_after = response.headers.get('Retry-After')
            if retry_after:
                print(f"[*] Suggested wait time: {retry_after} seconds.")

        # 5xx Server Error
        elif response.status_code >= 500:
            print(f"\n[-] Error: HIBP Server Error ({response.status_code}). Please try again later.")
            print(f"Response: {response.text}")

        # Other unexpected status codes
        else:
            print(f"\n[-] Error: Unexpected response code: {response.status_code}")
            print(f"Response: {response.text}")

    except requests.exceptions.Timeout:
        print("\n[-] Error: The request timed out. The HIBP server might be slow or unreachable.")
    except requests.exceptions.ConnectionError:
        print("\n[-] Error: Could not connect to the HIBP server. Check your internet connection.")
    except requests.exceptions.RequestException as e:
        print(f"\n[-] Error: An error occurred during the request: {e}")
    except Exception as e:
        print(f"\n[-] An unexpected error occurred: {e}")

# --- Main Execution ---

if __name__ == "__main__":
    print("--- Have I Been Pwned? Email Checker ---")
    print("This script checks if your email address appears in known data breaches.")
    print("It uses the public Have I Been Pwned API (v3).")
    print("Privacy Note: Your email address will be sent to the HIBP service.")
    print("-" * 40)

    email_to_check = input("Enter the email address to check: ").strip()

    if email_to_check:
        check_email_breach(email_to_check)
    else:
        print("No email address entered. Exiting.")

    print("\n--- Check complete ---")