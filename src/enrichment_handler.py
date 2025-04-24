import time
import base64
import requests
from OTXv2 import OTXv2

try:
    from pymisp import PyMISP, MISPServerError  # Import PyMISP and common errors

    PYMISP_AVAILABLE = True
except ImportError:
    print("[Warning] pymisp library not installed. MISP feed processing will be skipped.")
    PYMISP_AVAILABLE = False

from . import config
from .feed_handler import OTX_SDK_AVAILABLE

VT_BASE_URL = "https://www.virustotal.com/api/v3"
ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2/check"
OTX_API_BASE_URL = "https://otx.alienvault.com"

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
