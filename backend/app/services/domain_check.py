import whois
import dns.resolver
import dns.exception
from urllib.parse import urlparse
import logging

# Configure basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def check_link_details(url_string, dkim_selectors=None):
    """
    Checks WHOIS, SPF, DMARC, and optionally DKIM records for the domain of a URL.

    Args:
        url_string (str): The URL to check (e.g., "https://www.google.com").
        dkim_selectors (list, optional): A list of DKIM selectors to check.
                                         Defaults to None. DKIM requires selectors
                                         found in email headers for a proper check.

    Returns:
        dict: A dictionary containing the results for 'domain', 'whois',
              'spf', 'dmarc', and 'dkim'. Values might be data, None,
              or error messages.
    """
    results = {
        'url_provided': url_string,
        'domain': None,
        'whois': None,
        'spf': {'status': 'Not Checked', 'records': []},
        'dmarc': {'status': 'Not Checked', 'record': None},
        'dkim': {'status': 'Not Checked', 'selectors_checked': {}, 'info': None}
    }

    if dkim_selectors is None:
        dkim_selectors = [] # Ensure it's iterable

    # --- 1. Extract Domain from URL ---
    try:
        parsed_url = urlparse(url_string)
        domain = parsed_url.netloc
        # Remove port if present (e.g., example.com:8080)
        if ':' in domain:
            domain = domain.split(':')[0]
        # Basic validation - rudimentary, improve if needed
        if '.' not in domain or domain.startswith('.'):
             raise ValueError("Invalid domain extracted")
        results['domain'] = domain
        logging.info(f"Extracted domain: {domain}")
    except Exception as e:
        logging.error(f"Error parsing URL '{url_string}': {e}")
        results['domain'] = f"Error parsing URL: {e}"
        # Cannot proceed without a valid domain
        return results

    # --- 2. WHOIS Check ---
    try:
        logging.info(f"Performing WHOIS lookup for: {domain}")
        w = whois.whois(domain)
        # python-whois returns different structures. Try to get text or dict.
        if w.text:
             # Sometimes expiration_date is a list, handle it
            if isinstance(w.get('expiration_date'), list):
                w['expiration_date'] = w['expiration_date'][0]
             # Convert datetime objects to strings for easier serialization if needed
            whois_data = {k: str(v) if v is not None else None for k, v in w.items()}
            results['whois'] = whois_data
            logging.info(f"WHOIS lookup successful for {domain}.")
        else:
             results['whois'] = "WHOIS data not found or empty."
             logging.warning(f"WHOIS data not found or empty for {domain}.")

    except whois.parser.PywhoisError as e:
         # Specific error from python-whois for domain not found etc.
         results['whois'] = f"WHOIS lookup error: No match for '{domain}' or query failed."
         logging.warning(f"WHOIS lookup failed for {domain}: {e}")
    except Exception as e:
        results['whois'] = f"WHOIS lookup error: {e}"
        logging.error(f"Unexpected error during WHOIS lookup for {domain}: {e}")

    # --- 3. DNS Resolver Setup ---
    resolver = dns.resolver.Resolver()
    # Optionally configure nameservers, timeouts etc.
    # resolver.nameservers = ['8.8.8.8', '1.1.1.1']
    # resolver.timeout = 5
    # resolver.lifetime = 10

    # --- 4. SPF Check (TXT Record) ---
    try:
        logging.info(f"Querying SPF (TXT record) for: {domain}")
        spf_records = []
        answers = resolver.resolve(domain, 'TXT')
        found_spf = False
        for rdata in answers:
            for txt_string in rdata.strings:
                decoded_string = txt_string.decode('utf-8')
                if decoded_string.lower().startswith('v=spf1'):
                    spf_records.append(decoded_string)
                    found_spf = True
        if found_spf:
             results['spf']['status'] = "Record(s) Found"
             results['spf']['records'] = spf_records
             logging.info(f"Found SPF records for {domain}: {spf_records}")
        else:
             results['spf']['status'] = "No SPF record found"
             logging.warning(f"No SPF TXT record found for {domain}")

    except dns.resolver.NoAnswer:
        results['spf']['status'] = "No TXT records found at all for domain"
        logging.warning(f"No TXT records found for {domain}")
    except dns.resolver.NXDOMAIN:
        results['spf']['status'] = f"Domain '{domain}' does not exist (NXDOMAIN)"
        logging.warning(f"Domain {domain} does not exist (NXDOMAIN)")
    except dns.exception.Timeout:
         results['spf']['status'] = "DNS query timed out"
         logging.error(f"DNS query for SPF on {domain} timed out.")
    except Exception as e:
        results['spf']['status'] = f"SPF check error: {e}"
        logging.error(f"Error checking SPF for {domain}: {e}")

    # --- 5. DMARC Check (TXT Record at _dmarc subdomain) ---
    dmarc_query = f"_dmarc.{domain}"
    try:
        logging.info(f"Querying DMARC (TXT record) for: {dmarc_query}")
        answers = resolver.resolve(dmarc_query, 'TXT')
        found_dmarc = False
        for rdata in answers:
             for txt_string in rdata.strings:
                decoded_string = txt_string.decode('utf-8')
                if decoded_string.lower().startswith('v=dmarc1'):
                    results['dmarc']['record'] = decoded_string
                    results['dmarc']['status'] = "Record Found"
                    found_dmarc = True
                    logging.info(f"Found DMARC record for {domain}: {decoded_string}")
                    break # Typically only one DMARC record
             if found_dmarc:
                 break
        if not found_dmarc:
             results['dmarc']['status'] = "No DMARC record found"
             logging.warning(f"No DMARC record found at {dmarc_query}")

    except dns.resolver.NoAnswer:
        results['dmarc']['status'] = f"No TXT record found for {dmarc_query}"
        logging.warning(f"No DMARC TXT record found for {dmarc_query}")
    except dns.resolver.NXDOMAIN:
        results['dmarc']['status'] = f"DMARC domain '{dmarc_query}' does not exist (NXDOMAIN)"
        logging.warning(f"DMARC domain {dmarc_query} does not exist (NXDOMAIN)")
    except dns.exception.Timeout:
         results['dmarc']['status'] = "DNS query timed out"
         logging.error(f"DNS query for DMARC on {domain} timed out.")
    except Exception as e:
        results['dmarc']['status'] = f"DMARC check error: {e}"
        logging.error(f"Error checking DMARC for {domain}: {e}")


    # --- 6. DKIM Check (TXT Record at selector._domainkey subdomain) ---
    if not dkim_selectors:
        results['dkim']['status'] = "Not Checked"
        results['dkim']['info'] = "No DKIM selectors provided. DKIM checks require specific selectors (e.g., 'google', 's1')."
        logging.info(f"Skipping DKIM check for {domain} as no selectors were provided.")
    else:
        results['dkim']['status'] = "Checked"
        logging.info(f"Checking DKIM for selectors: {dkim_selectors}")
        all_selectors_failed = True # Assume failure until one succeeds
        for selector in dkim_selectors:
            dkim_query = f"{selector}._domainkey.{domain}"
            try:
                logging.info(f"Querying DKIM (TXT record) for: {dkim_query}")
                answers = resolver.resolve(dkim_query, 'TXT')
                selector_records = []
                for rdata in answers:
                    # DKIM records can be split across multiple strings
                    full_record = "".join([s.decode('utf-8') for s in rdata.strings])
                    selector_records.append(full_record)

                if selector_records:
                    results['dkim']['selectors_checked'][selector] = {
                        'status': 'Record(s) Found',
                        'records': selector_records
                    }
                    logging.info(f"Found DKIM record(s) for selector '{selector}' at {dkim_query}")
                    all_selectors_failed = False # At least one lookup worked
                else:
                     results['dkim']['selectors_checked'][selector] = {
                        'status': 'No DKIM record found',
                        'records': []
                     }
                     logging.warning(f"No DKIM record found for selector '{selector}' at {dkim_query}")


            except dns.resolver.NoAnswer:
                 results['dkim']['selectors_checked'][selector] = {
                     'status': f"No TXT record found for {dkim_query}",
                     'records': []
                 }
                 logging.warning(f"No DKIM TXT record found for {dkim_query}")
            except dns.resolver.NXDOMAIN:
                 results['dkim']['selectors_checked'][selector] = {
                     'status': f"DKIM domain '{dkim_query}' does not exist (NXDOMAIN)",
                     'records': []
                 }
                 logging.warning(f"DKIM domain {dkim_query} does not exist (NXDOMAIN)")
            except dns.exception.Timeout:
                results['dkim']['selectors_checked'][selector] = {
                    'status': "DNS query timed out",
                    'records': []
                }
                logging.error(f"DNS query for DKIM selector '{selector}' on {domain} timed out.")
            except Exception as e:
                results['dkim']['selectors_checked'][selector] = {
                    'status': f"DKIM check error: {e}",
                    'records': []
                }
                logging.error(f"Error checking DKIM selector '{selector}' for {domain}: {e}")

        if all_selectors_failed and dkim_selectors:
             results['dkim']['info'] = "Checked provided selectors, but errors or no records found for all."
        elif not all_selectors_failed :
             results['dkim']['info'] = "Checked provided selectors. See 'selectors_checked' for details."


    return results

# --- Example Usage ---
if __name__ == "__main__":
    # Example 1: Google (usually has SPF, DMARC, DKIM needs selectors)
    url1 = "https://www.google.com"
    # You might know common selectors like 'google' or find them in email headers
    google_selectors = ['20230601'] # Google uses date-based selectors, this one is current as of mid-2024
    print(f"--- Checking: {url1} ---")
    details1 = check_link_details(url1, dkim_selectors=google_selectors)
    import json # Use json for pretty printing the dictionary
    print(json.dumps(details1, indent=2))
    print("-" * 30)

    # Example 2: A domain that might lack some records
    url2 = "https://3mku6ze.com" # Often has basic WHOIS but maybe not SPF/DMARC
    print(f"--- Checking: {url2} ---")
    details2 = check_link_details(url2)
    print(json.dumps(details2, indent=2))
    print("-" * 30)

    # Example 3: Invalid URL
    url3 = "not_a_valid_url"
    print(f"--- Checking: {url3} ---")
    details3 = check_link_details(url3)
    print(json.dumps(details3, indent=2))
    print("-" * 30)

    # Example 4: Domain likely not existing
    url4 = "https://thisshouldreallynotexist12345abc.org"
    print(f"--- Checking: {url4} ---")
    details4 = check_link_details(url4)
    print(json.dumps(details4, indent=2))
    print("-" * 30)

    # Example 5: URL with port
    url5 = "https://localhost:8080" # Domain is 'localhost'
    print(f"--- Checking: {url5} ---")
    details5 = check_link_details(url5) # Expect failures for public lookups on localhost
    print(json.dumps(details5, indent=2))
    print("-" * 30)