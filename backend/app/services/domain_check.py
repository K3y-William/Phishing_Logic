import whois
import dns.resolver
import dns.exception
from urllib.parse import urlparse
import logging
import re

# Configure basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def get_domain_from_email_format(email_string):
    """
    Extracts the domain name from an email address string
    in the format: "Name <local_part@domain.com>".

    Args:
        email_string (str): The string containing the email address.
                            Expected format: "Optional Name <email@domain.com>"
                            or just "<email@domain.com>".

    Returns:
        str: The extracted domain name (e.g., "gmail.com").
        None: If the email address or domain cannot be found in the expected format.
    """
    # Regex to find the content within angle brackets, then capture the domain part.
    # Breakdown:
    # <         : Matches the literal '<'
    # [^@<>]+   : Matches one or more characters that are NOT '@', '<', or '>' (the local part)
    # @         : Matches the literal '@'
    # ([^<>@]+) : Capturing group 1. Matches one or more characters that are NOT '<', '>', or '@'
    #             This is the domain part we want.
    # >         : Matches the literal '>'
    match = re.search(r"<[^@<>]+@([^<>@]+)>", email_string)

    if match:
        # group(0) is the whole match, e.g., "<jerrywilliams1041@gmail.com>"
        # group(1) is the first captured group, e.g., "gmail.com"
        return match.group(1)
    else:
        # Fallback: if the string is just an email like "test@example.com" (no name, no brackets)
        # This part is an extension in case the input format is simpler.
        # The problem specifically asked for "Name <email>", so the above regex is primary.
        # If you only want to support the "Name <...>" format strictly, you can remove this else block.
        parts = email_string.split('@')
        if len(parts) == 2 and '.' in parts[1] and not ('<' in email_string or '>' in email_string):
            # Basic validation for a domain (contains a dot, not part of the bracketed format)
            # This check for '<' or '>' ensures we don't misinterpret a malformed bracketed string
            return parts[1]
        return None


def remove_duplicates_ordered_set_trick(link_list):
    """
    Removes duplicate links from a list while preserving the order
    of the first appearance of each link.
    This method uses dict.fromkeys(), which in Python 3.7+ preserves
    insertion order. For Python 3.6 and earlier, dicts were unordered,
    so for those versions, use the 'manual_iteration' method for order.

    Args:
        link_list (List[str]): A list of link strings, possibly with duplicates.

    Returns:
        List[str]: A new list with duplicate links removed, order preserved.
    """
    if not link_list:
        return []
    # dict.fromkeys creates a dictionary with unique keys from the iterable.
    # Since Python 3.7, dictionary keys maintain insertion order.
    # Converting it back to a list gives unique items in order.
    return list(dict.fromkeys(link_list))

def extract_links_without_scheme(text):
    """
    Extracts URLs from a given string and returns them without the
    leading "http://" or "https://://" scheme.

    Args:
        text (str): The string to search for links.

    Returns:
        list: A list of found URLs (strings) without the scheme.
              Returns an empty list if no links are found.
    """
    # Regex explanation:
    # r"https?://" : Matches "http://" or "https://" (but we won't include this in the final result directly from findall)
    # r"("         : Start of a capturing group. re.findall will return the content of this group.
    #   (?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|  # domain...
    #   localhost|  # localhost...
    #   \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})  # ...or ip
    #   (?::\d+)?  # optional port
    #   (?:/?|[/?]\S+)  # optional path, query, fragment
    # r")"         : End of the capturing group.
    url_pattern = re.compile(
        r"https?://"  # Match http or https (this part is NOT in the capturing group)
        r"("          # Start of the capturing group (this is what findall will return)
        r"(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|"
        r"localhost|"
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
        r"(?::\d+)?"
        r"(?:/?|[/?]\S+)"
        r")",         # End of the capturing group
        re.IGNORECASE
    )

    # re.findall() with a pattern containing one capturing group will return
    # a list of strings, where each string is the content of that group.
    links_without_scheme = re.findall(url_pattern, text)
    return remove_duplicates_ordered_set_trick(links_without_scheme)


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
        # parsed_url = urlparse(url_string)

        domain = url_string
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

