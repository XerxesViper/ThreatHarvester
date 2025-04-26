import json
import base64
import requests
import urllib.parse

# try:
#     from pymisp import PyMISP, MISPServerError  # Import PyMISP and common errors
#
#     PYMISP_AVAILABLE = True
# except ImportError:
#     print("[Warning] pymisp library not installed. MISP feed processing will be skipped.")
#     PYMISP_AVAILABLE = False

try:
    import shodan
    from shodan.exception import APIError as ShodanAPIError

    SHODAN_AVAILABLE = True
except ImportError:
    print("[Warning] shodan library not installed. Shodan enrichment will be skipped.")
    SHODAN_AVAILABLE = False

from . import config
from .feed_handler import OTX_SDK_AVAILABLE

VT_BASE_URL = "https://www.virustotal.com/api/v3"
ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2/check"
OTX_API_BASE_URL = "https://otx.alienvault.com"
URLSCAN_API_BASE = "https://urlscan.io/api/v1"
GREYNOISE_COMMUNITY_API = "https://api.greynoise.io/v3/community"  # V3 is the free one. #V2 is paid
IPINFO_API_BASE = "https://ipinfo.io"
MALSHARE_API_BASE = "https://malshare.com/api.php"

# --- Type Mapping for OTX API Calls ---
OTX_API_PATH_TYPE_MAP = {
    "ipv4": "ip",
    # "ipv6": "ip", # Assuming IPv6 might also use 'ip', needs testing if IPv6 is added
    "domain": "domain",
    "hostname": "hostname",  # Keep as hostname (OTX differentiates)
    "url": "url",
    "md5": "file",
    "sha1": "file",
    "sha256": "file",
}
INTERNAL_TYPE_TO_OTX_MAP = {
    "ipv4": "IPv4",
    "ipv6": "IPv6",
    "domain": "domain",
    # "hostname": "hostname", # SDK might just use 'domain' or handle internally
    "url": "URL",
    "md5": "FileHash-MD5",
    "sha1": "FileHash-SHA1",
    "sha256": "FileHash-SHA256",
}

# --- Type Mapping for MISP calls (on my server) ---
INTERNAL_TYPE_TO_MISP_TYPE_MAP = {
    "ipv4": ["ip-src", "ip-dst"],  # Search for either source or destination IP
    "domain": ["domain", "hostname"],  # Search for domain or hostname
    "url": ["url"],
    "md5": ["md5"],
    "sha1": ["sha1"],
    "sha256": ["sha256"],
    "filename": ["filename"],
    "regkey": ["regkey"],
    "user-agent": ["user-agent"],
}


def enrich_virustotal(ioc_value, ioc_type, api_key):
    """
        Enriches an IOC using the VirusTotal API v3.

        Args:
            ioc_value (str): The indicator value.
            ioc_type (str): The type of indicator ('ipv4', 'domain', 'url', 'md5', 'sha1', 'sha256').
            api_key (str): The VirusTotal API key.

        Returns:
            dict: A dictionary containing extracted enrichment data
            None: if an error occurs or not found.
    """

    if not api_key:
        print("VirusTotal enrichment skipped: API key missing.")
        return None

    endpoint = ""
    if ioc_type == "ipv4":
        endpoint = f"/ip_addresses/{ioc_value}"
    elif ioc_type == "domain":
        endpoint = f"/domains/{ioc_value}"
    elif ioc_type in ['md5', 'sha1', 'sha256']:
        endpoint = f"/files/{ioc_value}"
    elif ioc_type == "url":
        # For URLs, VT uses an ID which is base64 of the URL
        # See: https://developers.virustotal.com/reference/url-info
        try:
            # Need URL safe base64 without padding '='
            url_id = base64.urlsafe_b64encode(ioc_value.encode()).decode().strip("=")
            endpoint = f"/urls/{url_id}"
        except Exception as e:
            print(f"Failed to encode URL for VirusTotal ID: {e}")
            return None
    else:
        print(f"VirusTotal enrichment skipped: Unsupported IOC type '{ioc_type}'")
        return None

    url = f"{VT_BASE_URL}{endpoint}"
    headers = {
        "x-apikey": api_key,
        "User-Agent": config.USER_AGENT,
        "Accept": "application/json"
    }

    try:
        # time.sleep(16)  # VT free tier allows 4/min

        print(f"Querying VirusTotal for {url}")
        response = requests.get(url, headers=headers, timeout=20)

        if response.status_code == 200:
            print(f"VirusTotal: Success (200 OK) for {ioc_value}")
            data = response.json()
            # print(json.dumps(response.json(), sort_keys=True, indent=4, separators=(',', ': ')))
            attributes = data.get("data", {}).get("attributes", {})

            # Extract common useful fields
            extracted_data = {
                'vt_last_analysis_stats': attributes.get('last_analysis_stats'),
                'vt_reputation': attributes.get('reputation'),
                'vt_last_modification_date': attributes.get('last_modification_date'),
                # Add more fields as needed based on type
            }
            if ioc_type == 'ipv4':
                extracted_data['vt_owner'] = attributes.get('as_owner')
                extracted_data['vt_country'] = attributes.get('country')
            elif ioc_type == 'domain':
                extracted_data['vt_whois'] = attributes.get('whois')  # Can be large
                extracted_data['vt_categories'] = attributes.get('categories')
            elif ioc_type in ['md5', 'sha1', 'sha256']:
                extracted_data['vt_names'] = attributes.get('names')
                extracted_data['vt_type_tags'] = attributes.get('type_tags')
                extracted_data['vt_size'] = attributes.get('size')

            yara_results_list = attributes.get('crowdsourced_yara_results', [])
            # Store details (name, description) for each hit
            yara_hits_details = []
            if isinstance(yara_results_list, list):
                for yara_hit in yara_results_list:
                    # Ensure hit is a dict and has a rule_name
                    if isinstance(yara_hit, dict) and yara_hit.get('rule_name'):
                        hit_detail = {
                            'rule_name': yara_hit['rule_name'],
                            # Use .get() for description as it might be optional
                            'description': yara_hit.get('description', 'N/A')
                        }
                        yara_hits_details.append(hit_detail)

            # Add the list of details to extracted_data if any rules were found
            if yara_hits_details:
                # Use a different key name to reflect the change
                extracted_data['vt_yara_hits_details'] = yara_hits_details

            return extracted_data

        elif response.status_code == 404:
            print(f"VirusTotal: IOC not found (404) for {ioc_value}")
            return None  # Indicate not found

        elif response.status_code == 401:
            print(f"VirusTotal: Authentication failed (401). Check API key.")
            return None  # Indicate error

        elif response.status_code == 429:
            print(f"VirusTotal: Rate limit exceeded (429). Try again later.")
            # Consider adding a retry mechanism or longer sleep here if needed
            return None  # Indicate error/rate limit

        else:
            print(f"VirusTotal: Received unexpected status code {response.status_code} for {ioc_value}. Response: {response.text[:200]}")
            return None  # Indicate error

    except requests.exceptions.Timeout:
        print(f"VirusTotal: Request timed out for {ioc_value}")
        return None

    except requests.exceptions.RequestException as e:
        print(f"VirusTotal: Request failed for {ioc_value}: {e}")
        return None

    except Exception as e:  # Catch potential JSON parsing errors etc.
        print(f"VirusTotal: Error processing response for {ioc_value}: {e}")
        return None


def enrich_abuseipdb(ip_address, api_key, max_age_days=90):
    """
    Enriches an IP address using the AbuseIPDB API v2.

    Args:
        ip_address (str): The IPv4 address to check.
        api_key (str): The AbuseIPDB API key.
        max_age_days (int): How far back to look for reports.

    Returns:
        dict: A dictionary containing extracted enrichment data, or None if an error occurs or not found.
    """

    if not api_key:
        print("AbuseIPDB enrichment skipped: API key missing.")
        return None

    headers = {
        'Key': api_key,
        'Accept': 'application/json',
        'User-Agent': config.USER_AGENT
    }
    params = {
        'ipAddress': ip_address,
        'maxAgeInDays': str(max_age_days),
        # 'verbose': ''  # Add if you want verbose output (more details)
    }

    try:
        print(f"Querying AbuseIPDB for: {ip_address}")
        response = requests.get(ABUSEIPDB_BASE_URL, headers=headers, params=params, timeout=15)

        # AbuseIPDB uses different status codes sometimes
        # See: https://docs.abuseipdb.com/#check-endpoint
        if response.status_code == 200:
            print(f"AbuseIPDB: Success (200 OK) for {ip_address}")
            data = response.json().get('data', {})  # Safely get the 'data' object

            # Extract useful fields
            extracted_data = {
                'abuseipdb_score': data.get('abuseConfidenceScore'),
                'abuseipdb_country': data.get('countryCode'),
                'abuseipdb_isp': data.get('isp'),
                'abuseipdb_domain': data.get('domain'),
                'abuseipdb_is_whitelisted': data.get('isWhitelisted'),
                'abuseipdb_reports': data.get('totalReports'),
                'abuseipdb_last_reported': data.get('lastReportedAt'),
            }
            return extracted_data

        # Handle specific AbuseIPDB errors if needed based on response body
        # For now, treat non-200 as generic errors or not found implicitly
        elif response.status_code == 404:  # Unlikely for /check, but possible
            print(f"AbuseIPDB: Endpoint not found? (404) for {ip_address}")
            return None
        elif response.status_code == 401:
            print(f"AbuseIPDB: Authentication failed (401). Check API key.")
            return None
        elif response.status_code == 429:
            print(f"AbuseIPDB: Rate limit exceeded (429). Try again later.")
            return None
        elif response.status_code == 402:  # Payment Required (if exceeding free limits)
            print(f"AbuseIPDB: Payment Required (402). Check API plan limits.")
            return None
        else:
            print(f"AbuseIPDB: Received unexpected status code {response.status_code} for {ip_address}. Response: {response.text[:200]}")
            return None

    except requests.exceptions.Timeout:
        print(f"AbuseIPDB: Request timed out for {ip_address}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"AbuseIPDB: Request failed for {ip_address}: {e}")
        return None
    except Exception as e:  # Catch potential JSON parsing errors etc.
        print(f"AbuseIPDB: Error processing response for {ip_address}: {e}")
        return None


def enrich_otx(ioc_value, ioc_type, api_key):
    """
        Enriches an IOC using the AlienVault OTX API v2.

        Args:
            ioc_value (str): The indicator value.
            ioc_type (str): Our internal indicator type.
            api_key (str): The OTX API key.

        Returns:
            dict: A dictionary containing extracted OTX data (e.g., pulse info),
                  or None if an error occurs, not found, or type unsupported.

    """

    if not OTX_SDK_AVAILABLE:
        print("OTX enrichment skipped: OTX SDK not installed.")
        return None
    if not api_key:
        print("OTX enrichment skipped: API key missing.")
        return None

    otx_indicator_type = INTERNAL_TYPE_TO_OTX_MAP.get(ioc_type, None)
    print(otx_indicator_type)
    if not otx_indicator_type:
        print(f"OTX enrichment skipped: Unsupported IOC type '{ioc_type}'")
        return None

    otx_api_path_type = OTX_API_PATH_TYPE_MAP.get(ioc_type)
    if not otx_api_path_type:  # Check if type is supported for enrichment path
        print(f"OTX enrichment skipped: Unsupported IOC type for OTX enrichment path '{ioc_type}'")
        return None

    # --- Direct API Call using requests ---
    section = 'pulse_info'  # Section we want
    url = f"{OTX_API_BASE_URL}/api/v1/indicators/{otx_api_path_type}/{ioc_value}/"
    print(f"OTX API URL: {url}")

    headers = {
        'X-OTX-API-KEY': api_key,
        'User-Agent': getattr(config, 'USER_AGENT', 'ThreatIntelTool/0.2'),
        'Accept': 'application/json'
    }

    try:
        print(f"Querying OTX API directly for '{section}' on {otx_indicator_type}: {ioc_value}")
        response = requests.get(url, headers=headers, timeout=20)

        # --- Process Response ---
        if response.status_code == 200:
            print(f"OTX API: Succes`s (200 OK) for {ioc_value}")
            data = response.json()

            # Extract 'pulse_info' section
            pulse_info_data = data.get('pulse_info', {})
            pulses = pulse_info_data.get('pulses', [])
            pulse_count = pulse_info_data.get('count', 0)

            # --- Extract additional fields ---
            otx_type_title = data.get('type_title')
            base_indicator_info = data.get('base_indicator')
            related_base_indicator = None
            related_base_type = None
            if base_indicator_info and isinstance(base_indicator_info, dict):
                related_base_indicator = base_indicator_info.get('indicator')
                related_base_type = base_indicator_info.get('type')

            # Extract details from first few pulses (e.g., first 3)
            related_pulse_details = []
            for p in pulses[:3]:  # Limit to first 3 pulses
                pulse_detail = {
                    "id": p.get('id'),
                    "name": p.get('name'),
                    "malware_families": [mf.get('display_name') for mf in p.get('malware_families', []) if mf.get('display_name')],
                    "adversary": p.get('adversary')
                }
                related_pulse_details.append(pulse_detail)
            # --- End additional field extraction ---

            extracted_data = {
                'otx_pulse_count': pulse_count,
                # Keep IDs for potential linking later
                'otx_related_pulse_ids': [p.get('id') for p in pulses[:5] if p.get('id')],
                # Add new fields
                'otx_type_title': otx_type_title,
                'otx_base_indicator': related_base_indicator,
                'otx_base_indicator_type': related_base_type,
                'otx_related_pulse_details': related_pulse_details  # List of dicts
            }
            return extracted_data

        elif response.status_code == 404:
            print(f"OTX API: Indicator not found (404) for {ioc_value}")
            return None  # Indicate not found
        elif response.status_code == 403:  # Often used for bad API key
            print(f"OTX API: Forbidden (403). Check API key permissions.")
            return None
        elif response.status_code == 401:  # Sometimes used for bad API key
            print(f"OTX API: Unauthorized (401). Check API key.")
            return None
        elif response.status_code == 429:
            print(f"OTX API: Rate limit exceeded (429). Try again later.")
            return None
        else:
            print(f"OTX API: Received unexpected status code {response.status_code} for {ioc_value}. Response: {response.text[:200]}")
            return None

    except requests.exceptions.Timeout:
        print(f"OTX API: Request timed out for {ioc_value}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"OTX API: Request failed for {ioc_value}: {e}")
        return None
    except Exception as e:  # Catch potential JSON parsing errors etc.
        print(f"OTX API: Error processing response for {ioc_value}: {e}")
        return None


def enrich_urlscan(ioc_value, ioc_type, api_key):
    """
    Enriches an IOC by searching for existing scans on URLScan.io.
    Supports 'url', 'domain', 'ipv4', 'md5', 'sha1', 'sha256'.
    """
    if not api_key:
        print("[!] URLScan.io enrichment skipped: API key missing.")
        return None

    # --- Build Search Query ---
    query = ""
    if ioc_type == 'url':
        query = f'page.url:"{ioc_value}"'
    elif ioc_type == 'domain':
        query = f'page.domain:"{ioc_value}"'
    elif ioc_type == 'ipv4':
        query = f'page.ip:"{ioc_value}"'
    # --- Add Hash Types ---
    elif ioc_type in ['md5', 'sha1', 'sha256']:
        # URLScan search uses 'hash:' for any supported hash type
        query = f'hash:{ioc_value}'
    else:
        # Skip unsupported types for URLScan enrichment
        print(f"[*] URLScan.io enrichment skipped: Type '{ioc_type}' not supported for search.")
        return None  # Return None, not an error, just not supported

    # URL encode the query part
    encoded_query = urllib.parse.quote(query)
    search_url = f"{URLSCAN_API_BASE}/search/?q={encoded_query}"

    headers = {
        'API-Key': api_key,
        'Accept': 'application/json',
        'User-Agent': getattr(config, 'USER_AGENT', 'ThreatIntelTool/0.1')
    }

    try:
        print(f"[*] Querying URLScan.io Search API for: {query}")
        response = requests.get(search_url, headers=headers, timeout=20)

        # --- Process Response ---
        if response.status_code == 200:
            results_data = response.json()
            results = results_data.get('results', [])
            total_hits = results_data.get('total', 0)

            if total_hits == 0 or not results:
                print(f"[*] IOC not found in URLScan.io scans: {ioc_value} (Query: {query})")
                return None

            print(f"[*] URLScan.io: Found {total_hits} scan(s). Processing most recent.")

            latest_scan = results[0]
            task_info = latest_scan.get('task', {})
            page_info = latest_scan.get('page', {})
            stats_info = latest_scan.get('stats', {})

            extracted_data = {
                'urlscan_total_hits': total_hits,
                'urlscan_latest_scan_id': task_info.get('uuid'),
                'urlscan_latest_scan_url': task_info.get('url'),
                'urlscan_latest_scan_date': task_info.get('time'),
                'urlscan_latest_page_url': page_info.get('url'),
                'urlscan_latest_page_domain': page_info.get('domain'),
                'urlscan_latest_page_ip': page_info.get('ip'),
                'urlscan_verdict_malicious': stats_info.get('malicious'),
                'urlscan_verdict_score': stats_info.get('malscore'),
                'urlscan_report_url': latest_scan.get('result'),
                'urlscan_screenshot_url': task_info.get('screenshotURL'),
            }
            return extracted_data

        # --- Handle API Errors ---
        # ... (Error handling for 404, 401, 429, etc. remains the same) ...
        elif response.status_code == 401:
            print(f"[!] URLScan.io API Error (401): Authentication failed. Check API key.")
            return None
        elif response.status_code == 429:
            print(f"[!] URLScan.io API Error (429): Rate limit exceeded.")
            return None
        else:
            print(f"[!] URLScan.io API Error ({response.status_code}): {response.text[:200]}")
            return None

    except requests.exceptions.Timeout:
        print(f"[!] URLScan.io API: Request timed out for {query}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"[!] URLScan.io API: Request failed for {query}: {e}")
        return None
    except Exception as e:
        print(f"[!] Error processing URLScan.io response for {query}: {e}")
        return None


def enrich_shodan(ip_address, api_key):
    """
    Enriches an IP address using the Shodan API.
    """
    if not SHODAN_AVAILABLE:
        print("[!] Shodan enrichment skipped: shodan library not installed.")
        return None
    if not api_key:
        print("[!] Shodan enrichment skipped: API key missing.")
        return None

    print(f"[*] Querying Shodan for IP: {ip_address}")
    try:
        api = shodan.Shodan(api_key)
        # Lookup the host
        host_info = api.host(ip_address)

        # --- Parse the results ---
        # Extract key information
        open_ports = host_info.get('ports', [])
        hostnames = host_info.get('hostnames', [])
        domains = host_info.get('domains', [])
        asn = host_info.get('asn', 'N/A')
        isp = host_info.get('isp', 'N/A')
        org = host_info.get('org', 'N/A')
        country = host_info.get('country_name', 'N/A')
        city = host_info.get('city', 'N/A')
        os_version = host_info.get('os', None)  # OS fingerprinting

        # Extract service details from the 'data' list
        services = []
        for item in host_info.get('data', []):
            service_info = {
                'port': item.get('port'),
                'transport': item.get('transport', 'tcp'),  # Default to tcp
                'product': item.get('product'),
                'version': item.get('version'),
                'cpes': item.get('cpe'),  # Common Platform Enumeration
                # Add 'banner': item.get('banner') if needed, can be large
            }
            services.append(service_info)

        extracted_data = {
            'shodan_asn': asn,
            'shodan_isp': isp,
            'shodan_org': org,
            'shodan_os': os_version,
            'shodan_country': country,
            'shodan_city': city,
            'shodan_hostnames': hostnames,
            'shodan_domains': domains,
            'shodan_open_ports': open_ports,
            'shodan_services': services  # List of service dictionaries
            # Add 'shodan_vulns': host_info.get('vulns') if needed (often requires paid key)
        }
        print(f"[*] Shodan: Success for {ip_address}")
        return extracted_data

    except ShodanAPIError as e:
        # Handle Shodan specific errors (e.g., "No information available for that IP.")
        print(f"[!] Shodan API Error for {ip_address}: {e}")
        return None  # Indicate not found or error
    except Exception as e:
        # Handle other potential errors (network, etc.)
        print(f"[!] Error during Shodan lookup for {ip_address}: {e}")
        return None


def enrich_greynoise(ip_address, api_key):
    """
    Enriches an IP address using the GreyNoise Community API.
    """
    if not api_key:
        print("[!] GreyNoise enrichment skipped: API key missing.")
        return None

    url = f"{GREYNOISE_COMMUNITY_API}/{ip_address}"
    headers = {
        # GreyNoise uses 'key' header according to docs
        'key': api_key,
        'Accept': 'application/json',
        'User-Agent': getattr(config, 'USER_AGENT', 'ThreatIntelTool/0.1')
    }

    try:
        print(f"[*] Querying GreyNoise Community API for IP: {ip_address}")
        response = requests.get(url, headers=headers, timeout=15)

        # --- Process Response ---
        if response.status_code == 200:
            print(f"[*] GreyNoise: Success (200 OK) for {ip_address}")
            data = response.json()

            # Check if GreyNoise has classified it (might return 200 but 'noise': false)
            if not data.get('noise') and not data.get('riot'):
                print(f"[*] GreyNoise: IP not classified as noise or RIOT: {ip_address}")
                # Return minimal info indicating it was checked but not noise/riot
                return {
                    'greynoise_seen': False,
                    'greynoise_noise': False,
                    'greynoise_riot': False,
                    'greynoise_classification': data.get('classification', 'unknown'),  # Might still have classification
                    'greynoise_message': data.get('message')  # e.g. "IP not seen scanning the internet"
                }

            extracted_data = {
                'greynoise_seen': True,  # Indicate it was found in GreyNoise dataset
                'greynoise_noise': data.get('noise'),  # True/False
                'greynoise_riot': data.get('riot'),  # True/False
                'greynoise_classification': data.get('classification'),  # malicious, benign, unknown
                'greynoise_name': data.get('name'),  # Actor name
                'greynoise_last_seen': data.get('last_seen'),
                'greynoise_link': data.get('link'),  # Link to visualizer
                # Add 'greynoise_message': data.get('message') if needed
            }
            return extracted_data

        # --- Handle API Errors ---
        elif response.status_code == 404:
            # 404 likely means IP not in GreyNoise Community dataset (or endpoint wrong)
            print(f"[*] GreyNoise: IP not found in Community dataset (404): {ip_address}")
            return None  # Indicate not found
        elif response.status_code == 400:
            # 400 often means invalid IP format
            print(f"[!] GreyNoise API Error (400): Bad Request (Invalid IP?): {ip_address}. Response: {response.text[:200]}")
            return None
        elif response.status_code == 401:
            print(f"[!] GreyNoise API Error (401): Authentication failed. Check API key.")
            return None
        elif response.status_code == 429:
            print(f"[!] GreyNoise API Error (429): Rate limit exceeded.")
            return None
        else:
            print(f"[!] GreyNoise API Error ({response.status_code}): {response.text[:200]}")
            return None

    except requests.exceptions.Timeout:
        print(f"[!] GreyNoise API: Request timed out for {ip_address}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"[!] GreyNoise API: Request failed for {ip_address}: {e}")
        return None
    except Exception as e:
        print(f"[!] Error processing GreyNoise response for {ip_address}: {e}")
        return None


def enrich_ipinfo(ip_address, api_token):
    """
    Enriches an IP address using the IPinfo.io API.
    """
    if not api_token:
        print("[!] IPinfo.io enrichment skipped: API token missing.")
        return None

    # Append token as query parameter
    url = f"{IPINFO_API_BASE}/{ip_address}?token={api_token}"
    headers = {
        'Accept': 'application/json',
        'User-Agent': getattr(config, 'USER_AGENT', 'ThreatIntelTool/0.1')
    }

    try:
        print(f"[*] Querying IPinfo.io API for IP: {ip_address}")
        # No specific payload needed, just GET request
        response = requests.get(url, headers=headers, timeout=15)

        # --- Process Response ---
        if response.status_code == 200:
            print(f"[*] IPinfo.io: Success (200 OK) for {ip_address}")
            data = response.json()

            # Extract relevant fields (check IPinfo docs for exact field names)
            extracted_data = {
                'ipinfo_hostname': data.get('hostname'),
                'ipinfo_city': data.get('city'),
                'ipinfo_region': data.get('region'),
                'ipinfo_country': data.get('country'),  # 2-letter code
                'ipinfo_location': data.get('loc'),  # Lat/Lon string
                'ipinfo_org': data.get('org'),  # ASN + Org Name string
                'ipinfo_postal': data.get('postal'),
                'ipinfo_timezone': data.get('timezone'),
                # Add 'ipinfo_abuse_email': data.get('abuse', {}).get('email') if needed
            }
            return extracted_data

        # --- Handle API Errors ---
        elif response.status_code == 404:
            # 404 can mean private IP, bogon, or invalid IP format
            print(f"[*] IPinfo.io: IP not found or invalid (404): {ip_address}")
            return None  # Indicate not found/invalid
        elif response.status_code == 401 or response.status_code == 403:
            print(f"[!] IPinfo.io API Error ({response.status_code}): Authentication failed. Check API token.")
            return None
        elif response.status_code == 429:
            # Should not happen with free tier if unlimited, but good practice
            print(f"[!] IPinfo.io API Error (429): Rate limit exceeded?")
            return None
        else:
            print(f"[!] IPinfo.io API Error ({response.status_code}): {response.text[:200]}")
            return None

    except requests.exceptions.Timeout:
        print(f"[!] IPinfo.io API: Request timed out for {ip_address}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"[!] IPinfo.io API: Request failed for {ip_address}: {e}")
        return None
    except Exception as e:
        print(f"[!] Error processing IPinfo.io response for {ip_address}: {e}")
        return None


def enrich_malshare(hash_value, ioc_type, api_key):
    """
    Enriches a file hash using the MalShare API, extracting details like
    other hashes, filenames, and YARA hits if available.
    Supports 'md5', 'sha1', 'sha256'.
    """
    if ioc_type not in ['md5', 'sha1', 'sha256']:
        return None
    if not api_key:
        print("[!] MalShare enrichment skipped: API key missing.")
        return None

    params = {'api_key': api_key, 'action': 'details', 'hash': hash_value}
    headers = {'User-Agent': getattr(config, 'USER_AGENT', 'ThreatIntelTool/0.1')}

    try:
        print(f"[*] Querying MalShare API for hash: {hash_value}")
        response = requests.get(MALSHARE_API_BASE, params=params, headers=headers, timeout=20)

        if response.status_code == 200:
            # Assume JSON response is most likely for structured data
            try:
                data = response.json()
                # Check for explicit error messages within the JSON
                if isinstance(data, dict) and ("Error" in data or "ERROR" in data):
                    print(f"[*] MalShare API returned an error message: {data}")
                    return None  # Treat API-level error as not found/error

                # If we get here and data is not empty, assume hash found
                print(f"[*] MalShare: Success - Hash found: {hash_value}")

                # --- Extract Specific Fields ---
                # Use .get() to safely access potential keys
                md5 = data.get('MD5') if isinstance(data, dict) else None
                sha1 = data.get('SHA1') if isinstance(data, dict) else None
                sha256 = data.get('SHA256') if isinstance(data, dict) else None
                ssdeep = data.get('SSDEEP') if isinstance(data, dict) else None
                # File names might be in a list under a key like 'observed_file_names' or 'filenames'
                file_names = data.get('FILENAMES', data.get('observed_file_names', [])) if isinstance(data, dict) else []
                # YARA hits likely in a list under 'yara_hits' or 'yara'
                yara_hits = data.get('yarahits', data.get('yarahits', [])) if isinstance(data, dict) else []
                # --- End Extraction ---

                extracted_data = {
                    'malshare_found': True,
                    'malshare_md5': md5,
                    'malshare_sha1': sha1,
                    'malshare_sha256': sha256,
                    'malshare_ssdeep': ssdeep,
                    'malshare_file_names': file_names if isinstance(file_names, list) else [],  # Ensure it's a list
                    'malshare_yara_hits': yara_hits if isinstance(yara_hits, list) else []  # Ensure it's a list
                }
                return extracted_data

            except json.JSONDecodeError:
                # Handle cases where response is 200 OK but not valid JSON
                response_text = response.text.strip()
                if not response_text or "Not Found" in response_text or "Error" in response_text:
                    print(f"[*] Hash not found in MalShare or API error message: {response_text}")
                    return None
                else:
                    # Found, but couldn't parse details - maybe plain text confirmation?
                    print(f"[*] MalShare: Hash found, but response was not JSON. Response: {response_text[:100]}")
                    return {'malshare_found': True, 'malshare_raw_response': response_text[:100]}

        # --- Handle API Errors ---
        elif response.status_code == 401 or response.status_code == 403:
            print(f"[!] MalShare API Error ({response.status_code}): Authentication failed. Check API key.")
            return None
        else:
            print(f"[!] MalShare API Error ({response.status_code}): {response.text[:200]}")
            return None

    # ... (Timeout, RequestException, other Exception handling remains the same) ...
    except requests.exceptions.Timeout:
        print(f"[!] MalShare API: Request timed out for {hash_value}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"[!] MalShare API: Request failed for {hash_value}: {e}")
        return None
    except Exception as e:
        print(f"[!] Error processing MalShare response for {hash_value}: {e}")
        return None
# def enrich_misp(
#         ioc_value,
#         ioc_type,  # Keep ioc_type for logging/context
#         misp_url=config.MISP_URL,
#         misp_key=config.MISP_API_KEY,
#         verify_cert=config.MISP_VERIFYCERT
# ):
#     """
#     Enriches an IOC by searching for EVENTS containing the IOC value using misp.search_index().
#     Uses print() for output.
#     """
#     if not PYMISP_AVAILABLE:
#         print("[!] MISP enrichment skipped: pymisp library not installed.")
#         return None
#     if not misp_url or not misp_key:
#         print("[!] MISP enrichment skipped: MISP_URL or MISP_API_KEY not configured.")
#         return None
#
#     # Type mapping not needed for search_index(attribute=...) filter
#     print(f"[*] Attempting MISP enrichment for IOC value: {ioc_value} at {misp_url} using search_index")
#
#     misp = None
#     try:
#         misp = PyMISP(misp_url, misp_key, verify_cert, 'json')
#         print(f"[*] Successfully initialized PyMISP for enrichment.")
#     except Exception as e:
#         print(f"[!] Failed to initialize PyMISP client for enrichment: {e}")
#         return None
#
#     # --- Search for EVENTS containing the attribute value using search_index ---
#     found_events = []  # Will store MISPEvent objects
#     try:
#         print(f"[*] Searching MISP index for events containing attribute value '{ioc_value}'...")
#
#         # Use search_index filtering by attribute value
#         found_events = misp.search_index(
#             attribute=ioc_value,
#             pythonify=True  # Get MISPEvent objects
#         )
#
#         print(found_events[:5])
#
#     except MISPServerError as e:
#         print(f"[!] MISP Server Error during search_index: {e}")
#         return None
#
#     except Exception as e:
#         print(f"[!] Error during MISP search_index: {e}")
#         return None
#
#     # --- Process results (list of MISPEvent objects) ---
#     if not found_events:
#         # Note: This might include events where the value matched an attribute of the WRONG type
#         print(f"[*] IOC value not found in any MISP events using search_index: {ioc_value}")
#         return None  # Indicate not found
#     else:
#         # Note: This count includes events where the value might match attributes of the WRONG type
#         print(f"[*] Found {len(found_events)} MISP event(s) containing value '{ioc_value}' (may include type mismatches).")
#
#         event_ids = set()
#         event_infos = {}
#         for event in found_events[:5]:  # Limit processing
#             # Access attributes using getattr for PyMISP objects
#             event_id = getattr(event, 'id', None)
#             if event_id:
#                 event_ids.add(event_id)
#                 if hasattr(event, 'info') and getattr(event, 'info', None):
#                     event_info = getattr(event, 'info')
#                     event_infos[event_id] = event_info.split('\n')[0][:70]
#                 else:
#                     event_infos[event_id] = f"Event {event_id}"  # Fallback
#
#         extracted_data = {
#             'misp_event_hit_count': len(found_events),
#             'misp_event_ids': list(event_ids),
#             'misp_event_infos': event_infos
#         }
#         # Add a note about potential type mismatches?
#         extracted_data['misp_search_method'] = 'search_index (value only)'
#         return extracted_data
