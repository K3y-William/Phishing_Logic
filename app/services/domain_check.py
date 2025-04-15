# DNS check api
import dns.resolver
import dns.exception
from urllib.parse import urlparse
import logging

# Configure basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def check_domain_email_security(url: str) -> dict:
    """
    Checks the domain extracted from a URL for DNS resolution, SPF, and DMARC records.

    Args:
        url: The URL string (e.g., "https://www.example.com/path").

    Returns:
        A dictionary containing the check results:
        {
            'url': The original URL provided.
            'domain': The extracted domain name.
            'dns_a': List of A record IP addresses or error message.
            'dns_aaaa': List of AAAA record IP addresses or error message.
            'spf': The SPF record string, None if not found, or error message.
            'dmarc': The DMARC record string, None if not found, or error message.
            'dkim_notes': Information about DKIM checking limitations.
            'errors': A list of errors encountered during the process.
        }
    """
    results = {
        'url': url,
        'domain': None,
        'dns_a': None,
        'dns_aaaa': None,
        'spf': None,
        'dmarc': None,
        'dkim_notes': "DKIM requires a 'selector' found in email headers for a full check. "
                      "Only DMARC presence (which often relies on DKIM) is checked here.",
        'errors': []
    }

    # 1. Extract Domain from URL
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        if not domain:
            # Handle cases like relative paths or invalid URLs
            if parsed_url.path and '.' in parsed_url.path.split('/')[0]:
                 # Maybe it's just a domain name without scheme?
                 domain = parsed_url.path.split('/')[0]
                 logging.info(f"Assuming '{domain}' is the domain from path '{parsed_url.path}'")
            else:
                 raise ValueError("Could not extract domain/hostname from URL")

        # Remove port if present (e.g., example.com:8080)
        if ':' in domain:
            domain = domain.split(':')[0]

        results['domain'] = domain
        logging.info(f"Extracted domain: {domain}")

    except ValueError as e:
        error_msg = f"Invalid URL format: {e}"
        logging.error(error_msg)
        results['errors'].append(error_msg)
        # Cannot proceed without a domain
        results['dns_a'] = "Error: Domain extraction failed."
        results['dns_aaaa'] = "Error: Domain extraction failed."
        results['spf'] = "Error: Domain extraction failed."
        results['dmarc'] = "Error: Domain extraction failed."
        return results

    # Initialize DNS Resolver
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    # --- DNS Checks (A and AAAA records) ---
    logging.info(f"Checking A records for {domain}...")
    try:
        a_records = resolver.resolve(domain, 'A')
        results['dns_a'] = [record.to_text() for record in a_records]
        logging.info(f"Found A records: {results['dns_a']}")
    except dns.resolver.NoAnswer:
        results['dns_a'] = "No A records found."
        logging.warning(f"No A records found for {domain}")
    except dns.resolver.NXDOMAIN:
        results['dns_a'] = f"Domain does not exist (NXDOMAIN)."
        logging.error(f"Domain {domain} does not exist (NXDOMAIN).")
        results['errors'].append(f"Domain {domain} does not exist (NXDOMAIN). Cannot perform further checks.")
        # Stop further checks if domain doesn't exist
        results['dns_aaaa'] = "Error: NXDOMAIN"
        results['spf'] = "Error: NXDOMAIN"
        results['dmarc'] = "Error: NXDOMAIN"
        return results
    except dns.exception.Timeout:
        results['dns_a'] = "DNS query timed out."
        logging.error(f"DNS query for A records timed out for {domain}")
        results['errors'].append(f"DNS query for A records timed out for {domain}")
    except Exception as e:
        error_msg = f"Error resolving A records: {e}"
        logging.error(error_msg)
        results['dns_a'] = f"Error: {e}"
        results['errors'].append(error_msg)


    logging.info(f"Checking AAAA records for {domain}...")
    try:
        aaaa_records = resolver.resolve(domain, 'AAAA')
        results['dns_aaaa'] = [record.to_text() for record in aaaa_records]
        logging.info(f"Found AAAA records: {results['dns_aaaa']}")
    except dns.resolver.NoAnswer:
        results['dns_aaaa'] = "No AAAA records found."
        logging.warning(f"No AAAA records found for {domain}")
    except dns.resolver.NXDOMAIN:
        # Should have been caught by A record check, but handle defensively
        results['dns_aaaa'] = f"Domain does not exist (NXDOMAIN)."
        logging.error(f"Domain {domain} does not exist (NXDOMAIN).")
        results['errors'].append(f"Domain {domain} does not exist (NXDOMAIN).")
    except dns.exception.Timeout:
        results['dns_aaaa'] = "DNS query timed out."
        logging.error(f"DNS query for AAAA records timed out for {domain}")
        results['errors'].append(f"DNS query for AAAA records timed out for {domain}")
    except Exception as e:
        error_msg = f"Error resolving AAAA records: {e}"
        logging.error(error_msg)
        results['dns_aaaa'] = f"Error: {e}"
        results['errors'].append(error_msg)

    # --- SPF Check ---
    logging.info(f"Checking SPF record for {domain}...")
    try:
        txt_records = resolver.resolve(domain, 'TXT')
        spf_record = None
        for record in txt_records:
            record_text = record.to_text().strip('"') # Remove surrounding quotes
            if record_text.lower().startswith("v=spf1"):
                spf_record = record_text
                break # Found the SPF record
        results['spf'] = spf_record if spf_record else "No SPF record found."
        if spf_record:
            logging.info(f"Found SPF record: {spf_record}")
        else:
             logging.warning(f"No SPF record found for {domain}")

    except dns.resolver.NoAnswer:
        results['spf'] = "No TXT records found (implies no SPF)."
        logging.warning(f"No TXT records found for {domain}")
    except dns.resolver.NXDOMAIN:
         # Should have been caught earlier
        results['spf'] = f"Domain does not exist (NXDOMAIN)."
        logging.error(f"Domain {domain} does not exist (NXDOMAIN).")
    except dns.exception.Timeout:
        results['spf'] = "DNS query for TXT/SPF timed out."
        logging.error(f"DNS query for TXT/SPF timed out for {domain}")
        results['errors'].append(f"DNS query for TXT/SPF timed out for {domain}")
    except Exception as e:
        error_msg = f"Error resolving TXT/SPF records: {e}"
        logging.error(error_msg)
        results['spf'] = f"Error: {e}"
        results['errors'].append(error_msg)


    # --- DMARC Check ---
    dmarc_domain = f"_dmarc.{domain}"
    logging.info(f"Checking DMARC record at {dmarc_domain}...")
    try:
        txt_records = resolver.resolve(dmarc_domain, 'TXT')
        dmarc_record = None
        for record in txt_records:
            record_text = record.to_text().strip('"') # Remove surrounding quotes
            if record_text.lower().startswith("v=dmarc1"):
                dmarc_record = record_text
                break # Found the DMARC record
        results['dmarc'] = dmarc_record if dmarc_record else "No DMARC record found."
        if dmarc_record:
            logging.info(f"Found DMARC record: {dmarc_record}")
        else:
             logging.warning(f"No DMARC record found at {dmarc_domain}")

    except dns.resolver.NoAnswer:
        results['dmarc'] = "No TXT records found at _dmarc subdomain (implies no DMARC)."
        logging.warning(f"No TXT records found at {dmarc_domain}")
    except dns.resolver.NXDOMAIN:
        results['dmarc'] = "No DMARC record found (NXDOMAIN for _dmarc subdomain)."
        logging.warning(f"No DMARC record published for {domain} (_dmarc subdomain does not exist).")
    except dns.exception.Timeout:
        results['dmarc'] = "DNS query for TXT/DMARC timed out."
        logging.error(f"DNS query for TXT/DMARC timed out for {dmarc_domain}")
        results['errors'].append(f"DNS query for TXT/DMARC timed out for {dmarc_domain}")
    except Exception as e:
        error_msg = f"Error resolving TXT/DMARC records: {e}"
        logging.error(error_msg)
        results['dmarc'] = f"Error: {e}"
        results['errors'].append(error_msg)

    # --- DKIM Notes ---
    # Already added in the initial dictionary setup.

    logging.info(f"Finished checks for {url}")
    return results

# --- Example Usage ---
if __name__ == "__main__":
    # Example URLs to test
    urls_to_check = [
        "https://www.google.com",
        "https://github.com/features",
        "https://domain-without-dmarc.com", # Replace with a real domain if needed
        "http://nonexistent-domain-sdfgsdfg.org",
        "invalid-url-format",
        "mailto:test@example.com", # Will likely fail domain extraction
        "example.com" # Test without scheme
    ]

    for link in urls_to_check:
        print("-" * 40)
        print(f"Checking link: {link}")
        check_results = check_domain_email_security(link)

        print(f"  Domain: {check_results['domain']}")
        print(f"  A Records: {check_results['dns_a']}")
        print(f"  AAAA Records: {check_results['dns_aaaa']}")
        print(f"  SPF Record: {check_results['spf']}")
        print(f"  DMARC Record: {check_results['dmarc']}")
        print(f"  DKIM Notes: {check_results['dkim_notes']}")
        if check_results['errors']:
            print(f"  Errors Encountered:")
            for error in check_results['errors']:
                print(f"    - {error}")
        print("-" * 40)
        print() # Add a newline for readability