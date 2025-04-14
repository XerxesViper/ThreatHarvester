import argparse
from src.db_manager import query_ioc
from src.utils import detect_ioc_type

from src import config
from src.enrichment_handler import enrich_virustotal, enrich_abuseipdb


def display_results(ioc_value, ioc_type, local_results, arg_VT, vt_results=None, abuseipdb_results=None):
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
        stats = vt_results.get('vt_last_seen_stats', {})
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        harmless = stats.get('harmless', 0)
        undetected = stats.get('undetected', 0)
        total = malicious + suspicious + harmless + undetected

        print(f"[+] Analysis Stats: Malicious={malicious}, Suspicious={suspicious}, Harmless={harmless}, Undetected={undetected} (Total={total})")
        print(f"[+] Reputation Score: {vt_results.get('44vt_reputation', 'N/A')}")

        # Print other VT fields based on what is extracted in enrich_virustotal
        if 'vt_owner' in vt_results: print(f"[+] AS Owner: {vt_results['vt_owner']}")
        if 'vt_country' in vt_results: print(f"[+] Country: {vt_results['vt_country']}")
        if 'vt_names' in vt_results: print(f"[+] Known Names: {vt_results['vt_names']}")

    elif arg_VT:
        print("[-] IOC lookup on VirusTotal skipped dues to user request.")
    elif vt_results is None and config.VT_API_KEY:
        print("[-] IOC not found in VirusTotal or an error occurred during lookup.")
    elif not config.VT_API_KEY:
        print("[!] VirusTotal lookup skipped (API key not configured).")
    else:  # Should not happen if vt_results is None, but safety catch
        print("[-] No VirusTotal data available.")

    # --- AbuseIPDB Enrichment (Only for IPv4) ---
    if ioc_type == 'ipv4':
        print("\n--- AbuseIPDB Enrichment ---")
        if abuseipdb_results:
            print(f"[+] Abuse Confidence Score: {abuseipdb_results.get('abuseipdb_score', 'N/A')}")
            print(f"[+] Country: {abuseipdb_results.get('abuseipdb_country', 'N/A')}")
            print(f"[+] ISP: {abuseipdb_results.get('abuseipdb_isp', 'N/A')}")
            print(f"[+] Domain: {abuseipdb_results.get('abuseipdb_domain', 'N/A')}")
            print(f"[+] Total Reports: {abuseipdb_results.get('abuseipdb_reports', 'N/A')}")
            print(f"[+] Last Reported: {abuseipdb_results.get('abuseipdb_last_reported', 'N/A')}")
        elif abuseipdb_results is None and config.ABUSEIPDB_API_KEY:
            print("[-] IP not found in AbuseIPDB or an error occurred during lookup.")
        elif not config.ABUSEIPDB_API_KEY:
            print("[!] AbuseIPDB lookup skipped (API key not configured).")
        else:
            print("[-] No AbuseIPDB data available.")

    print("\n" + "=" * 40)


def main():
    parser = argparse.ArgumentParser(
        description="Threat Intel Feed Correlator & Enrichment Tool"
    )

    # Available arguments
    parser.add_argument(
        '-i', "--ioc",  # flag name
        type=str,
        required=True,  # user input required for searching
        help="Indicator of Compromise to query (IP, domain, hash, URL)"
    )

    parser.add_argument(
        '--no_VT',
        type=bool,
        default=False,
        help="Indicator to remove VirusTotal enrichment"
    )

    args = parser.parse_args()
    # print(f"Arguments received: {args}")

    if args.ioc and not args.no_VT:
        indicator_to_query = args.ioc
        print(f"[*] Received IOC: {indicator_to_query}")

        ioc_type = detect_ioc_type(indicator_to_query)
        print(f"[*] Detected IOC Type: {ioc_type}")

        print(f"[*] Querying local database for: {indicator_to_query}")
        local_results = query_ioc(indicator_to_query)

        # --- External Enrichment ---
        print(f"[*] Starting external enrichment...")
        vt_data = None
        abuseipdb_data = None

        # Get API Keys
        vt_api_key = config.VT_API_KEY
        abuseipdb_api_key = config.ABUSEIPDB_API_KEY

        if ioc_type == 'unknown':
            print("[!] Cannot perform enrichment on 'unknown' IOC type.")
        else:
            # VirusTotal Lookup (IPs, Domains, Hashes, URLs)
            if vt_api_key:
                print("[*] Querying VirusTotal...")
                vt_data = enrich_virustotal(indicator_to_query, ioc_type, vt_api_key)
            else:
                print("[!] Skipping VirusTotal (API key missing)")

            # AbuseIPDB Lookup (IPs only)
            if ioc_type == 'ipv4':
                if abuseipdb_api_key:
                    print("[*] Querying AbuseIPDB...")
                    abuseipdb_data = enrich_abuseipdb(indicator_to_query, abuseipdb_api_key)
                else:
                    print("[!] Skipping AbuseIPDB (API key missing or IOC not IP)")

        print("[*] Enrichment finished.")

        # --- Display Combined Results ---
        display_results(
            ioc_value=indicator_to_query,
            ioc_type=ioc_type,
            local_results=local_results,
            arg_VT=args.no_VT,
            vt_results=vt_data,
            abuseipdb_results=abuseipdb_data
        )

    elif args.no_VT:
        indicator_to_query = args.ioc
        print(f"[*] Received IOC: {indicator_to_query}")

        ioc_type = detect_ioc_type(indicator_to_query)
        print(f"[*] Detected IOC Type: {ioc_type}")

        print(f"[*] Querying local database for: {indicator_to_query}")
        local_results = query_ioc(indicator_to_query)

        # --- External Enrichment ---
        print(f"[*] Starting external enrichment...")
        abuseipdb_data = None

        # Get API Keys
        abuseipdb_api_key = config.ABUSEIPDB_API_KEY

        if ioc_type == 'unknown':
            print("[!] Cannot perform enrichment on 'unknown' IOC type.")
        else:
            # AbuseIPDB Lookup (IPs only)
            if ioc_type == 'ipv4':
                if abuseipdb_api_key:
                    print("[*] Querying AbuseIPDB...")
                    abuseipdb_data = enrich_abuseipdb(indicator_to_query, abuseipdb_api_key)
                else:
                    print("[!] Skipping AbuseIPDB (API key missing or IOC not IP)")

        print("[*] Enrichment finished.")

        # --- Display Combined Results ---
        display_results(
            ioc_value=indicator_to_query,
            ioc_type=ioc_type,
            local_results=local_results,
            arg_VT=args.no_VT,
            vt_results=None,
            abuseipdb_results=abuseipdb_data
        )

    else:
        print("No IOC provided. Use --ioc <INDICATOR>")
        parser.print_help()


if __name__ == "__main__":
    main()
