import time
import base64
import requests

from . import config

VT_BASE_URL = "https://www.virustotal.com/api/v3"
ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2/check"


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
            # Add URL specific extraction if needed

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
