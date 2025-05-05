import logging

import pytest
import dns.resolver
import dns.exception
import whois
import datetime
from unittest.mock import patch, MagicMock, PropertyMock

# Import the function to test
from domain_check import check_link_details # <-- *** RENAME 'your_module' to the actual filename ***

# --- Mock Data and Objects ---

# Mock DNS answers (need to simulate the structure dnspython returns)
class MockRdata:
    def __init__(self, strings):
        # Store strings as bytes, like dnspython does
        self.strings = [s.encode('utf-8') for s in strings]

# Mock WHOIS data structure
class MockWhoisResult:
    def __init__(self, text=None, data=None, error=None):
        self._text = text
        self._data = data or {}
        self._error = error
        if error:
            raise error

    @property
    def text(self):
        return self._text

    def get(self, key, default=None):
        return self._data.get(key, default)

    def items(self):
        return self._data.items()

    # Add other attributes if your code uses them directly (like expiration_date)
    @property
    def expiration_date(self):
        return self._data.get('expiration_date')

# --- Test Cases ---

@pytest.fixture
def mock_resolver(mocker):
    """Fixture to mock dns.resolver.Resolver"""
    mock_instance = MagicMock(spec=dns.resolver.Resolver)
    # Default behavior: raise NoAnswer if not configured otherwise
    mock_instance.resolve.side_effect = dns.resolver.NoAnswer("Default mock: No answer")
    mocker.patch('dns.resolver.Resolver', return_value=mock_instance)
    return mock_instance

@pytest.fixture
def mock_whois(mocker):
    """Fixture to mock whois.whois"""
    mock_func = mocker.patch('whois.whois', autospec=True)
    # Default behavior: return basic whois info
    mock_func.return_value = MockWhoisResult(
        text="Domain Name: EXAMPLE.COM...",
        data={'domain_name': 'EXAMPLE.COM', 'registrar': 'Example Registrar', 'expiration_date': datetime.datetime(2025, 1, 1)}
    )
    return mock_func

# --- URL Parsing Tests ---

def test_valid_url_extraction():
    url = "https://www.example.com/path?query=1"
    result = check_link_details(url) # Don't need mocks just for parsing
    assert result['url_provided'] == url
    assert result['domain'] == "www.example.com"

def test_valid_url_with_port():
    url = "http://test.domain:8080"
    result = check_link_details(url)
    assert result['domain'] == "test.domain"

def test_invalid_url_handling():
    url = "invalid-url-string"
    result = check_link_details(url)
    assert result['domain'].startswith("Error parsing URL:")
    assert result['whois'] is None # Should stop after parsing error
    assert result['spf']['status'] == 'Not Checked'
    assert result['dmarc']['status'] == 'Not Checked'
    assert result['dkim']['status'] == 'Not Checked'

def test_url_leading_to_invalid_domain():
    # urlparse might succeed but domain is bad
    url = "https://.nodomain"
    result = check_link_details(url)
    assert result['domain'].startswith("Error parsing URL:") # Our custom validation catches this
    assert result['whois'] is None
    assert result['spf']['status'] == 'Not Checked'

# --- WHOIS Tests ---

def test_whois_success(mock_whois, mock_resolver): # Need mock_resolver even if not used directly by WHOIS part
    url = "https://example.com"
    mock_whois.return_value = MockWhoisResult(
        text="Domain: EXAMPLE.COM...",
        data={'domain_name': 'EXAMPLE.COM', 'expiration_date': datetime.datetime(2025, 1, 1)}
    )
    result = check_link_details(url)
    assert result['domain'] == "example.com"
    assert result['whois'] is not None
    assert result['whois']['domain_name'] == 'EXAMPLE.COM'
    # Check if datetime was converted to string
    assert isinstance(result['whois']['expiration_date'], str)
    mock_whois.assert_called_once_with("example.com")

def test_whois_success_with_list_expiry(mock_whois, mock_resolver):
    url = "https://example.com"
    # Simulate python-whois sometimes returning a list for expiry
    mock_whois.return_value = MockWhoisResult(
        text="Domain: EXAMPLE.COM...",
        data={'domain_name': 'EXAMPLE.COM', 'expiration_date': [datetime.datetime(2025, 1, 1), datetime.datetime(2026, 1, 1)]}
    )
    result = check_link_details(url)
    assert result['whois'] is not None
    assert isinstance(result['whois']['expiration_date'], str)
    assert result['whois']['expiration_date'].startswith('2025') # Should take the first one

def test_whois_not_found(mock_whois, mock_resolver):
    url = "https://nonexistentdomain12345.org"
    # Simulate the specific error for not found
    mock_whois.side_effect = whois.parser.PywhoisError("No match for nonexistentdomain12345.org.")
    result = check_link_details(url)
    assert result['domain'] == "nonexistentdomain12345.org"
    assert "WHOIS lookup error: No match for" in result['whois']
    mock_whois.assert_called_once_with("nonexistentdomain12345.org")

def test_whois_empty_result(mock_whois, mock_resolver):
    url = "https://example.com"
    # Simulate case where whois runs but finds no parseable text/data
    mock_whois.return_value = MockWhoisResult(text=None, data={}) # text is None or empty string
    result = check_link_details(url)
    assert result['domain'] == "example.com"
    assert result['whois'] == "WHOIS data not found or empty."

def test_whois_generic_exception(mock_whois, mock_resolver):
    url = "https://example.com"
    mock_whois.side_effect = Exception("Unexpected WHOIS library error")
    result = check_link_details(url)
    assert result['domain'] == "example.com"
    assert "WHOIS lookup error: Unexpected WHOIS library error" in result['whois']

# --- DNS Record Tests (SPF, DMARC, DKIM) ---

def setup_resolver_responses(resolver_mock, responses):
    """Helper to configure mock_resolver side_effect based on query."""
    def resolve_side_effect(query, rdtype):
        print(f"Mock resolving: {query} {rdtype}") # Debug print
        key = (query, rdtype)
        if key in responses:
            response_data = responses[key]
            if isinstance(response_data, Exception):
                raise response_data
            # Simulate dnspython answer structure
            if response_data is None: # Simulate NoAnswer specifically if needed
                 raise dns.resolver.NoAnswer(f"Mock NoAnswer for {query} {rdtype}")
            if isinstance(response_data, list) and all(isinstance(item, MockRdata) for item in response_data):
                 return response_data # Already in correct mock format
            # Assume it's a list of strings for TXT records
            elif rdtype == 'TXT':
                 return [MockRdata(response_data)]
            else:
                 # Add handling for other record types if needed
                 raise NotImplementedError(f"Mocking for {rdtype} not fully implemented")
        # Default if not specified in responses dict
        raise dns.resolver.NoAnswer(f"Mock not configured for {query} {rdtype}")

    resolver_mock.resolve.side_effect = resolve_side_effect

# SPF Tests
def test_spf_found(mock_whois, mock_resolver):
    url = "https://example.com"
    domain = "example.com"
    setup_resolver_responses(mock_resolver, {
        (domain, 'TXT'): ["v=spf1 include:_spf.google.com ~all", "other txt record"]
    })
    result = check_link_details(url)
    assert result['spf']['status'] == "Record(s) Found"
    assert result['spf']['records'] == ["v=spf1 include:_spf.google.com ~all"]
    mock_resolver.resolve.assert_any_call(domain, 'TXT')

def test_spf_not_found_but_other_txt_exist(mock_whois, mock_resolver):
    url = "https://example.com"
    domain = "example.com"
    setup_resolver_responses(mock_resolver, {
        (domain, 'TXT'): ["google-site-verification=abc", "another unrelated record"]
    })
    result = check_link_details(url)
    assert result['spf']['status'] == "No SPF record found"
    assert result['spf']['records'] == []

def test_spf_no_txt_records(mock_whois, mock_resolver):
    url = "https://example.com"
    domain = "example.com"
    setup_resolver_responses(mock_resolver, {
        (domain, 'TXT'): dns.resolver.NoAnswer("No TXT") # Explicit NoAnswer for TXT
        # Or just let the default side_effect handle it if setup_resolver_responses isn't used
    })
    result = check_link_details(url)
    assert result['spf']['status'] == "No TXT records found at all for domain"

def test_spf_domain_nxdomain(mock_whois, mock_resolver):
    url = "https://nxdomain-test.com"
    domain = "nxdomain-test.com"
    # Simulate NXDOMAIN for *any* query to this domain
    mock_resolver.resolve.side_effect = dns.resolver.NXDOMAIN(f"Mock NXDOMAIN for {domain}")
    result = check_link_details(url)
    # WHOIS might run first or fail, test the DNS part
    assert result['spf']['status'] == f"Domain '{domain}' does not exist (NXDOMAIN)"
    # Also check DMARC (it should also fail with NXDOMAIN)
    assert result['dmarc']['status'] == f"DMARC domain '_dmarc.{domain}' does not exist (NXDOMAIN)"

def test_spf_timeout(mock_whois, mock_resolver):
    url = "https://example.com"
    domain = "example.com"
    setup_resolver_responses(mock_resolver, {
        (domain, 'TXT'): dns.exception.Timeout("Mock Timeout")
    })
    result = check_link_details(url)
    assert result['spf']['status'] == "DNS query timed out"

# DMARC Tests
def test_dmarc_found(mock_whois, mock_resolver):
    url = "https://example.com"
    domain = "example.com"
    dmarc_domain = f"_dmarc.{domain}"
    setup_resolver_responses(mock_resolver, {
        (domain, 'TXT'): [], # Assume SPF/other TXT might exist or not
        (dmarc_domain, 'TXT'): ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"]
    })
    result = check_link_details(url)
    assert result['dmarc']['status'] == "Record Found"
    assert result['dmarc']['record'] == "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
    mock_resolver.resolve.assert_any_call(dmarc_domain, 'TXT')

def test_dmarc_not_found(mock_whois, mock_resolver):
    url = "https://example.com"
    domain = "example.com"
    dmarc_domain = f"_dmarc.{domain}"
    setup_resolver_responses(mock_resolver, {
        (domain, 'TXT'): [], # Assume SPF/other TXT might exist or not
        (dmarc_domain, 'TXT'): dns.resolver.NoAnswer("No TXT for _dmarc") # Explicit NoAnswer
    })
    result = check_link_details(url)
    assert result['dmarc']['status'] == f"No TXT record found for {dmarc_domain}"
    assert result['dmarc']['record'] is None

def test_dmarc_subdomain_nxdomain(mock_whois, mock_resolver):
    url = "https://example.com" # Domain itself exists
    domain = "example.com"
    dmarc_domain = f"_dmarc.{domain}"
    setup_resolver_responses(mock_resolver, {
        (domain, 'TXT'): ["v=spf1 ok"], # SPF exists
        (dmarc_domain, 'TXT'): dns.resolver.NXDOMAIN(f"Mock NXDOMAIN for {dmarc_domain}")
    })
    result = check_link_details(url)
    assert result['spf']['status'] == "Record(s) Found" # Verify SPF check still worked
    assert result['dmarc']['status'] == f"DMARC domain '{dmarc_domain}' does not exist (NXDOMAIN)"

def test_dmarc_timeout(mock_whois, mock_resolver):
    url = "https://example.com"
    domain = "example.com"
    dmarc_domain = f"_dmarc.{domain}"
    setup_resolver_responses(mock_resolver, {
         (domain, 'TXT'): [], # Assume SPF/other TXT might exist or not
         (dmarc_domain, 'TXT'): dns.exception.Timeout("Mock Timeout")
    })
    result = check_link_details(url)
    assert result['dmarc']['status'] == "DNS query timed out"


# DKIM Tests
def test_dkim_no_selectors_provided(mock_whois, mock_resolver):
    url = "https://example.com"
    result = check_link_details(url, dkim_selectors=None) # Explicitly None
    assert result['dkim']['status'] == "Not Checked"
    assert "No DKIM selectors provided" in result['dkim']['info']
    assert result['dkim']['selectors_checked'] == {}

    result_empty = check_link_details(url, dkim_selectors=[]) # Explicitly empty list
    assert result_empty['dkim']['status'] == "Not Checked"
    assert "No DKIM selectors provided" in result_empty['dkim']['info']
    assert result_empty['dkim']['selectors_checked'] == {}
    # Ensure resolver was NOT called for DKIM
    for call_args in mock_resolver.resolve.call_args_list:
        assert '_domainkey' not in call_args[0][0] # Check query string

def test_dkim_one_selector_found(mock_whois, mock_resolver):
    url = "https://example.com"
    domain = "example.com"
    selector = "s1"
    dkim_domain = f"{selector}._domainkey.{domain}"
    dkim_record_str = "v=DKIM1; k=rsa; p=ABC..."
    setup_resolver_responses(mock_resolver, {
        (dkim_domain, 'TXT'): [dkim_record_str]
    })
    result = check_link_details(url, dkim_selectors=[selector])
    assert result['dkim']['status'] == "Checked"
    assert result['dkim']['info'] == "Checked provided selectors. See 'selectors_checked' for details."
    assert selector in result['dkim']['selectors_checked']
    assert result['dkim']['selectors_checked'][selector]['status'] == "Record(s) Found"
    assert result['dkim']['selectors_checked'][selector]['records'] == [dkim_record_str]
    mock_resolver.resolve.assert_any_call(dkim_domain, 'TXT')

def test_dkim_one_selector_not_found_noanswer(mock_whois, mock_resolver):
    url = "https://example.com"
    domain = "example.com"
    selector = "s1"
    dkim_domain = f"{selector}._domainkey.{domain}"
    setup_resolver_responses(mock_resolver, {
        (dkim_domain, 'TXT'): dns.resolver.NoAnswer("No TXT for DKIM")
    })
    result = check_link_details(url, dkim_selectors=[selector])
    assert result['dkim']['status'] == "Checked"
    assert result['dkim']['info'] == "Checked provided selectors, but errors or no records found for all."
    assert selector in result['dkim']['selectors_checked']
    assert result['dkim']['selectors_checked'][selector]['status'] == f"No TXT record found for {dkim_domain}"
    assert result['dkim']['selectors_checked'][selector]['records'] == []

def test_dkim_one_selector_nxdomain(mock_whois, mock_resolver):
    url = "https://example.com"
    domain = "example.com"
    selector = "s1"
    dkim_domain = f"{selector}._domainkey.{domain}"
    setup_resolver_responses(mock_resolver, {
        (dkim_domain, 'TXT'): dns.resolver.NXDOMAIN(f"NXDOMAIN for {dkim_domain}")
    })
    result = check_link_details(url, dkim_selectors=[selector])
    assert result['dkim']['status'] == "Checked"
    assert result['dkim']['info'] == "Checked provided selectors, but errors or no records found for all."
    assert selector in result['dkim']['selectors_checked']
    assert result['dkim']['selectors_checked'][selector]['status'] == f"DKIM domain '{dkim_domain}' does not exist (NXDOMAIN)"

def test_dkim_multiple_selectors_mixed_results(mock_whois, mock_resolver):
    url = "https://example.com"
    domain = "example.com"
    selector1 = "s1"
    selector2 = "s2"
    selector3 = "s3"
    dkim1_domain = f"{selector1}._domainkey.{domain}"
    dkim2_domain = f"{selector2}._domainkey.{domain}"
    dkim3_domain = f"{selector3}._domainkey.{domain}"
    dkim1_record = "v=DKIM1; p=S1KEY..."
    # Simulate s2 doesn't exist, s3 times out
    setup_resolver_responses(mock_resolver, {
        (dkim1_domain, 'TXT'): [dkim1_record],
        (dkim2_domain, 'TXT'): dns.resolver.NXDOMAIN(f"NXDOMAIN for {dkim2_domain}"),
        (dkim3_domain, 'TXT'): dns.exception.Timeout("Timeout for s3")
    })
    result = check_link_details(url, dkim_selectors=[selector1, selector2, selector3])

    assert result['dkim']['status'] == "Checked"
    # Since s1 succeeded, the overall info should reflect that
    assert result['dkim']['info'] == "Checked provided selectors. See 'selectors_checked' for details."
    assert selector1 in result['dkim']['selectors_checked']
    assert selector2 in result['dkim']['selectors_checked']
    assert selector3 in result['dkim']['selectors_checked']

    # Check s1 (found)
    assert result['dkim']['selectors_checked'][selector1]['status'] == "Record(s) Found"
    assert result['dkim']['selectors_checked'][selector1]['records'] == [dkim1_record]
    # Check s2 (nxdomain)
    assert result['dkim']['selectors_checked'][selector2]['status'] == f"DKIM domain '{dkim2_domain}' does not exist (NXDOMAIN)"
    # Check s3 (timeout)
    assert result['dkim']['selectors_checked'][selector3]['status'] == "DNS query timed out"

def test_dkim_record_split_strings(mock_whois, mock_resolver):
    url = "https://example.com"
    domain = "example.com"
    selector = "split"
    dkim_domain = f"{selector}._domainkey.{domain}"
    # Simulate a record split into two TXT strings within the same answer
    mock_answer = [MockRdata(["v=DKIM1; k=rsa; p=PART1", "PART2END"])]
    setup_resolver_responses(mock_resolver, {
        (dkim_domain, 'TXT'): mock_answer
    })
    result = check_link_details(url, dkim_selectors=[selector])
    assert result['dkim']['status'] == "Checked"
    assert selector in result['dkim']['selectors_checked']
    assert result['dkim']['selectors_checked'][selector]['status'] == "Record(s) Found"
    # Ensure the strings were concatenated
    assert result['dkim']['selectors_checked'][selector]['records'] == ["v=DKIM1; k=rsa; p=PART1PART2END"]


# --- Full Integration Style Test (Happy Path) ---

def test_full_check_happy_path(mock_whois, mock_resolver):
    url = "https://good-domain.com"
    domain = "good-domain.com"
    dmarc_domain = f"_dmarc.{domain}"
    selector = "dkim1"
    dkim_domain = f"{selector}._domainkey.{domain}"

    # Mock WHOIS success
    mock_whois.return_value = MockWhoisResult(
        text="Domain: GOOD-DOMAIN.COM...",
        data={'domain_name': 'GOOD-DOMAIN.COM', 'registrar': 'GoodReg', 'expiration_date': datetime.datetime(2026, 1, 1)}
    )

    # Mock DNS Success
    spf_record = "v=spf1 mx ~all"
    dmarc_record = "v=DMARC1; p=quarantine"
    dkim_record = "v=DKIM1; k=rsa; p=GOODKEY"
    setup_resolver_responses(mock_resolver, {
        (domain, 'TXT'): [spf_record],
        (dmarc_domain, 'TXT'): [dmarc_record],
        (dkim_domain, 'TXT'): [dkim_record]
    })

    result = check_link_details(url, dkim_selectors=[selector])

    # Assertions
    assert result['domain'] == domain
    assert result['whois']['domain_name'] == 'GOOD-DOMAIN.COM'
    assert result['spf']['status'] == "Record(s) Found"
    assert result['spf']['records'] == [spf_record]
    assert result['dmarc']['status'] == "Record Found"
    assert result['dmarc']['record'] == dmarc_record
    assert result['dkim']['status'] == "Checked"
    assert result['dkim']['info'] == "Checked provided selectors. See 'selectors_checked' for details."
    assert result['dkim']['selectors_checked'][selector]['status'] == "Record(s) Found"
    assert result['dkim']['selectors_checked'][selector]['records'] == [dkim_record]

# --- Logging Test Example ---

def test_logging_on_error(mock_whois, mock_resolver, caplog):
    url = "https://timeout-domain.com"
    domain = "timeout-domain.com"

    # Mock WHOIS success
    mock_whois.return_value = MockWhoisResult(
        text="Domain: TIMEOUT-DOMAIN.COM...",
        data={'domain_name': 'TIMEOUT-DOMAIN.COM'}
    )
    # Mock DNS Timeout for SPF
    setup_resolver_responses(mock_resolver, {
        (domain, 'TXT'): dns.exception.Timeout("SPF Mock Timeout"),
        # Let DMARC/DKIM default to NoAnswer or fail similarly
    })

    with caplog.at_level(logging.ERROR): # Capture ERROR level logs
         result = check_link_details(url)

    assert result['spf']['status'] == "DNS query timed out"
    # Check if the error was logged
    assert f"DNS query for SPF on {domain} timed out." in caplog.text
    # Check that other non-error logs are not present if level is ERROR
    assert f"Performing WHOIS lookup for: {domain}" not in caplog.text # This is INFO level

    # Example checking warning log
    mock_resolver.resolve.side_effect = dns.resolver.NoAnswer("No TXT") # Reset side effect
    with caplog.at_level(logging.WARNING):
         result = check_link_details(url) # Run again with NoAnswer

    assert result['spf']['status'] == "No TXT records found at all for domain"
    assert f"No TXT records found for {domain}" in caplog.text