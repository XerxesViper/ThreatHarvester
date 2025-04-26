import argparse
import pprint
from src.db_manager import query_ioc
from src.utils import detect_ioc_type

from src import config
from src.enrichment_handler import enrich_virustotal, enrich_abuseipdb, enrich_otx, enrich_urlscan, enrich_shodan


def display_results(
        ioc_value,
        ioc_type,
        local_results,

        arg_VT_disabled,
        arg_AIPDB_disabled,
        arg_OTX_disabled,
        arg_MISP_disabled,
        arg_URLSCAN_disabled,
        arg_SHODAN_disabled,

        vt_results=None,
        abuseipdb_results=None,
        otx_results=None,
        misp_results=None,
        urlscan_results=None,
        shodan_results=None,
):
    """Formats and prints the collected results."""

    print("\n" + "=" * 40)
    print(f"Results for IOC: {ioc_value} (Type: {ioc_type})")
    print("=" * 40)

    # --- Local Database Findings ---
    print("\n--- Local Database Findings ---")
    if local_results:
        print(f"[+] Found {len(local_results)} record(s) locally:")
        for record in local_results:
            # Access tuple elements by index
            ioc_type = record[1] if len(record) > 1 else 'N/A'
            first_seen = record[2] if len(record) > 2 else 'N/A'
            last_seen = record[3] if len(record) > 3 else 'N/A'
            sources = record[4] if len(record) > 4 else 'N/A'
            tags = record[5] if len(record) > 5 else 'None'  # Handle None specifically for tags
            feed_url = record[6] if len(record) > 6 else 'N/A'

            print(f"  - Type: {ioc_type}")
            print(f"    Sources: {sources}")
            print(f"    Tags: {tags if tags is not None else 'None'}")  # Nicer printing for None tags
            print(f"    Feed URL: {feed_url}")
            print(f"    First Seen (Feed): {first_seen if first_seen is not None else 'N/A'}")
            print(f"    Last Seen (Local): {last_seen}")
            print("-" * 20)  # Separator between records if multiple

    else:
        print("[-] No records found locally for this IOC.")

    # --- VirusTotal Enrichment ---
    print("\n--- VirusTotal Enrichment ---")
    if vt_results:
        stats = vt_results.get('vt_last_analysis_stats', {})
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        harmless = stats.get('harmless', 0)
        undetected = stats.get('undetected', 0)
        total = malicious + suspicious + harmless + undetected

        print(f"[+] Analysis Stats: Malicious={malicious}, Suspicious={suspicious}, Harmless={harmless}, Undetected={undetected} (Total={total})")
        print(f"[+] Reputation Score: {vt_results.get('vt_reputation', 'N/A')}")
        if 'vt_owner' in vt_results: print(f"[+] AS Owner: {vt_results['vt_owner']}")
        if 'vt_country' in vt_results: print(f"[+] Country: {vt_results['vt_country']}")
        if 'vt_names' in vt_results: print(f"[+] Known Names: {vt_results['vt_names']}")

    # *** Use the passed flag to explain missing data ***
    elif arg_VT_disabled:
        print("[!] VirusTotal lookup skipped (disabled by user flag --no_VT).")
    elif vt_results is None and config.VT_API_KEY:  # Check API key exists
        print("[-] IOC not found in VirusTotal or an error occurred during lookup.")
    elif not config.VT_API_KEY:
        print("[!] VirusTotal lookup skipped (API key not configured).")
    else:
        print("[-] No VirusTotal data available.")  # Fallback

    # --- AbuseIPDB Enrichment (Only for IPv4) ---
    if ioc_type == 'ipv4':
        print("\n--- AbuseIPDB Enrichment ---")
        if abuseipdb_results:
            # ... (print abuseipdb_results details as before) ...
            print(f"[+] Abuse Confidence Score: {abuseipdb_results.get('abuseipdb_score', 'N/A')}")
            print(f"[+] Country: {abuseipdb_results.get('abuseipdb_country', 'N/A')}")
            print(f"[+] ISP: {abuseipdb_results.get('abuseipdb_isp', 'N/A')}")
            print(f"[+] Domain: {abuseipdb_results.get('abuseipdb_domain', 'N/A')}")
            print(f"[+] Total Reports: {abuseipdb_results.get('abuseipdb_reports', 'N/A')}")
            print(f"[+] Last Reported: {abuseipdb_results.get('abuseipdb_last_reported', 'N/A')}")

        # *** Use the passed flag to explain missing data ***``
        elif arg_AIPDB_disabled:
            print("[!] AbuseIPDB lookup skipped (disabled by user flag --no_AIPDB).")
        elif abuseipdb_results is None and config.ABUSEIPDB_API_KEY:  # Check API key exists
            print("[-] IP not found in AbuseIPDB or an error occurred during lookup.")
        elif not config.ABUSEIPDB_API_KEY:
            print("[!] AbuseIPDB lookup skipped (API key not configured).")
        else:
            print("[-] No AbuseIPDB data available.")  # Fallback

    else:
        print("\n")
        print("[-] AbuseIPDB lookup ignored because input is not IPv4")
    print("\n" + "=" * 40)

    # --- AlienVault OTX Enrichment ---
    print("\n--- AlienVault OTX Enrichment ---")

    if otx_results:
        pulse_count = otx_results.get('otx_pulse_count', 0)
        related_ids = otx_results.get('otx_related_pulse_ids', [])
        print(f"[+] OTX Type Title: {otx_results.get('otx_type_title', 'N/A')}")

        # Print base indicator info if available
        base_ind = otx_results.get('otx_base_indicator')
        base_type = otx_results.get('otx_base_indicator_type')
        if base_ind and base_type:
            print(f"[+] Base Indicator: {base_ind} ({base_type})")

        print(f"[+] Related Pulse Count: {pulse_count}")

        # Print details of related pulses
        pulse_details = otx_results.get('otx_related_pulse_details', [])
        if pulse_details:
            print("[+] Related Pulse Details (Sample):")
            for detail in pulse_details:
                print(f"  - Pulse ID: {detail.get('id', 'N/A')}")
                print(f"    Name: {detail.get('name', 'N/A')}")
                adversary = detail.get('adversary')
                print(f"    Adversary: {adversary}") if adversary else None
                malware = detail.get('malware_families', [])
                print(f"    Malware Families: {', '.join(malware)}") if malware else None
                print("    ---")  # Separator for pulse details
        elif pulse_count > 0:  # If count > 0 but no details extracted
            print(f"[+] Related Pulse IDs (Sample): {', '.join(related_ids)}")

    elif arg_OTX_disabled:
        print("[!] AlienVault OTX lookup skipped (disabled by user flag --no_OTX).")
    elif otx_results is None and config.OTX_API_KEY:
        print("[-] IOC not found in OTX or an error occurred during lookup.")
    elif not config.OTX_API_KEY:
        print("[!] OTX lookup skipped (API key not configured).")
    else:
        print("[-] No OTX data available.")

    # --- MISP Enrichment ---
    print("\n--- MISP Enrichment ---")
    if misp_results:
        hit_count = misp_results.get('misp_hit_count', 0)
        event_ids = misp_results.get('misp_event_ids', [])
        event_infos = misp_results.get('misp_event_infos', {})

        print(f"[+] Found {hit_count} matching attribute(s) in MISP.")
        if event_ids:
            print(f"[+] Associated Event IDs: {', '.join(map(str, event_ids))}")
            if event_infos:
                print("[+] Associated Event Info (Sample):")
                for eid, info in event_infos.items():
                    print(f"  - {eid}: {info}")

    elif arg_MISP_disabled:
        print("[!] MISP lookup skipped (disabled by user flag --no_MISP).")
    elif misp_results is None and config.MISP_URL and config.MISP_API_KEY:
        print("[-] IOC not found in MISP or an error occurred during lookup.")
    elif not config.MISP_URL or not config.MISP_API_KEY:
        print("[!] MISP lookup skipped (URL or API key not configured).")
    else:
        print("[-] No MISP data available.")

    # --- URLScan.io Enrichment ---
    # Only show if relevant type was queried
    if ioc_type in ['url', 'domain', 'ipv4', 'md5', 'sha1', 'sha256']:
        print("\n--- URLScan.io Enrichment ---")
        if urlscan_results:
            total_hits = urlscan_results.get('urlscan_total_hits', 0)
            print(f"[+] Found {total_hits} existing scan(s).")
            if total_hits > 0:
                print(f"[+] Latest Scan Info:")
                print(f"  - Scan ID: {urlscan_results.get('urlscan_latest_scan_id', 'N/A')}")
                print(f"  - Scan Date: {urlscan_results.get('urlscan_latest_scan_date', 'N/A')}")
                print(f"  - Submitted URL: {urlscan_results.get('urlscan_latest_scan_url', 'N/A')}")
                print(f"  - Final URL: {urlscan_results.get('urlscan_latest_page_url', 'N/A')}")
                print(f"  - Final Domain: {urlscan_results.get('urlscan_latest_page_domain', 'N/A')}")
                print(f"  - Final IP: {urlscan_results.get('urlscan_latest_page_ip', 'N/A')}")
                print(f"  - Malicious Verdict: {urlscan_results.get('urlscan_verdict_malicious', 'N/A')}")
                print(f"  - Malicious Score (0-100): {urlscan_results.get('urlscan_verdict_score', 'N/A')}")
                print(f"  - Report Link: {urlscan_results.get('urlscan_report_url', 'N/A')}")
                print(f"  - Screenshot: {urlscan_results.get('urlscan_screenshot_url', 'N/A')}")

        elif arg_URLSCAN_disabled:
            print("[!] URLScan.io lookup skipped (disabled by user flag --no_URLSCAN).")
        elif urlscan_results is None and config.URLSCAN_API_KEY:
            print("[-] IOC not found in URLScan.io or an error occurred during lookup.")
        elif not config.URLSCAN_API_KEY:
            print("[!] URLScan.io lookup skipped (API key not configured).")
        else:
            print("[-] No URLScan.io data available.")

    # --- Shodan Enrichment (Only show if IP was queried) ---
    if ioc_type == 'ipv4':
        print("\n--- Shodan Enrichment ---")
        if shodan_results:
            print(f"[+] ASN: {shodan_results.get('shodan_asn', 'N/A')}")
            print(f"[+] ISP: {shodan_results.get('shodan_isp', 'N/A')}")
            print(f"[+] Organization: {shodan_results.get('shodan_org', 'N/A')}")
            print(f"[+] Location: {shodan_results.get('shodan_city', 'N/A')}, {shodan_results.get('shodan_country', 'N/A')}")
            print(f"[+] OS: {shodan_results.get('shodan_os', 'N/A')}")
            print(f"[+] Hostnames: {', '.join(shodan_results.get('shodan_hostnames', [])) if shodan_results.get('shodan_hostnames') else 'None'}")
            print(f"[+] Domains: {', '.join(shodan_results.get('shodan_domains', [])) if shodan_results.get('shodan_domains') else 'None'}")
            print(f"[+] Open Ports: {', '.join(map(str, shodan_results.get('shodan_open_ports', []))) if shodan_results.get('shodan_open_ports') else 'None'}")

            services = shodan_results.get('shodan_services', [])
            if services:
                print("[+] Services:")
                for svc in services[:10]:  # Limit output
                    print(f"  - Port {svc.get('port')}/{svc.get('transport', 'tcp')}: Product={svc.get('product', 'N/A')}, Version={svc.get('version', 'N/A')}")
            # Add Vulns if needed: print(f"[+] Vulns: {shodan_results.get('shodan_vulns')}")

        elif arg_SHODAN_disabled:
            print("[!] Shodan lookup skipped (disabled by user flag --no_SHODAN).")
        elif shodan_results is None and config.SHODAN_API_KEY:
            print("[-] IP not found in Shodan or an error occurred during lookup.")
        elif not config.SHODAN_API_KEY:
            print("[!] Shodan lookup skipped (API key not configured).")
        else:
            print("[-] No Shodan data available.")

    print("\n" + "=" * 40)


def main():
    parser = argparse.ArgumentParser(
        description="Threat Intel Feed Correlator & Enrichment Tool"
    )

    parser.add_argument(
        '-i', "--ioc",
        type=str,
        required=True,
        help="Indicator of Compromise to query (IP, domain, hash, URL)"
    )
    parser.add_argument(
        '-nvt', '--no_VT',
        action='store_true',
        help="Disable VirusTotal enrichment"
    )
    parser.add_argument(
        '-naipdb', '-nipdb', '--no_AIPDB',
        action='store_true',
        help="Disable AbuseIPDB enrichment"
    )
    parser.add_argument(
        '-notx', '--no_OTX',
        action='store_true',
        help="Disable AlienVault OTX enrichment"
    )
    parser.add_argument(
        '-nmisp', '--no_MISP',
        action='store_true',
        help="Disable MISP enrichment lookup"
    )
    parser.add_argument(
        '-nurl', '--no_URLSCAN',
        action='store_true',
        help="Disable URLScan.io enrichment lookup"
    )
    parser.add_argument(
        '--no_SHODAN',
        action='store_true',
        help="Disable Shodan enrichment lookup"
    )
    parser.add_argument(
        '-local', '--local_only',
        action='store_true',
        help="Only query local database for IOC - Disables all external enrichment calls"
    )
    args = parser.parse_args()

    # --- Assume --ioc is present due to required=True ---
    indicator_to_query = args.ioc
    print(f"[*] Received IOC: {indicator_to_query}")

    # --- Common Steps ---
    ioc_type = detect_ioc_type(indicator_to_query)
    print(f"[*] Detected IOC Type: {ioc_type}")

    print(f"[*] Querying local database...")
    local_results = query_ioc(indicator_to_query)

    # --- Enrichment ---
    print(f"[*] Starting external enrichment...")
    vt_data = None
    vt_api_key = config.VT_API_KEY

    abuseipdb_data = None
    abuseipdb_api_key = config.ABUSEIPDB_API_KEY

    otx_data = None
    otx_api_key = config.OTX_API_KEY

    misp_data = None
    misp_api_key = config.MISP_API_KEY
    misp_url = config.MISP_URL

    urlscan_data = None
    urlscan_api_key = config.URLSCAN_API_KEY

    shodan_data = None
    shodan_api_key = config.SHODAN_API_KEY

    if ioc_type == 'unknown':
        print("[!] Cannot perform enrichment on 'unknown' IOC type.")
    else:
        # --- Conditional VT Call ---
        if not args.no_VT:  # Check flag first
            if vt_api_key:
                print("[*] Querying VirusTotal...")
                vt_data = enrich_virustotal(indicator_to_query, ioc_type, vt_api_key)
            else:
                print("[!] Skipping VirusTotal (API key missing)")
        else:
            print("[!] Skipping VirusTotal (disabled by user flag --no_VT)")

        # --- Conditional AIPDB Call ---
        if ioc_type == 'ipv4':  # Only relevant for IPs
            if not args.no_AIPDB:  # Check flag first
                if abuseipdb_api_key:
                    print("[*] Querying AbuseIPDB...")
                    abuseipdb_data = enrich_abuseipdb(indicator_to_query, abuseipdb_api_key)
                else:
                    print("[!] Skipping AbuseIPDB (API key missing)")
            else:
                print("[!] Skipping AbuseIPDB (disabled by user flag --no_AIPDB)")
        elif args.no_AIPDB:
            print("\n" + "=" * 20)
            print("[!] --no_AIPDB flag ignored (IOC is not an IP)")
            print("\n" + "=" * 20)

        if otx_api_key and not args.no_OTX:
            print("[*] Querying AlienVault OTX...")
            otx_data = enrich_otx(indicator_to_query, ioc_type, otx_api_key)
        else:
            print("[!] Skipping OTX (API key missing)")

        # # --- MISP Call ---
        # if not args.no_MISP:  # Check flag
        #     if misp_url and misp_api_key:  # Check config
        #         print("[*] Querying MISP instance...")
        #         misp_data = enrich_misp(indicator_to_query, ioc_type)  # URL/Key implicitly from config
        #     else:
        #         print("[!] Skipping MISP (URL or API key missing)")
        # else:
        #     print("[!] Skipping MISP (disabled by user flag --no_MISP)")
        #
        # print("[*] Enrichment finished.")

        # --- Conditional URLSCAN Call ---
        if ioc_type in ['url', 'domain', 'ipv4', 'md5', 'sha1', 'sha256']:
            if not args.no_URLSCAN:
                if urlscan_api_key:
                    print("[*] Querying URLScan.io...")
                    urlscan_data = enrich_urlscan(indicator_to_query, ioc_type, urlscan_api_key)
                else:
                    print("[!] Skipping URLScan.io (API key missing)")
            else:
                print("[!] Skipping URLScan.io (disabled by user flag --no_URLSCAN)")
        else:
            print(f"[*] Skipping URLScan.io (type '{ioc_type}' not searchable)")

        # --- Shodan Call (IPs only) ---
        if ioc_type == 'ipv4':
            if not args.no_SHODAN:  # Check flag
                if shodan_api_key:  # Check key
                    print("[*] Querying Shodan...")
                    shodan_data = enrich_shodan(indicator_to_query, shodan_api_key)
                else:
                    print("[!] Skipping Shodan (API key missing)")
            else:
                print("[!] Skipping Shodan (disabled by user flag --no_SHODAN)")

    print("[*] Enrichment finished.")

    display_results(
        ioc_value=indicator_to_query,
        ioc_type=ioc_type,

        local_results=local_results,

        arg_VT_disabled=args.no_VT,
        arg_AIPDB_disabled=args.no_AIPDB,
        arg_OTX_disabled=args.no_OTX,
        arg_MISP_disabled=True,
        arg_URLSCAN_disabled=args.no_URLSCAN,
        arg_SHODAN_disabled=args.no_SHODAN,

        vt_results=vt_data,
        abuseipdb_results=abuseipdb_data,
        otx_results=otx_data,
        misp_results=misp_data,
        urlscan_results=urlscan_data,
        shodan_results=shodan_data,
    )


if __name__ == "__main__":
    main()
