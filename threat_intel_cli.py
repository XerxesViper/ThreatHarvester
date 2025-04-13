import argparse
from src.db_manager import query_ioc
from src.utils import detect_ioc_type


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

    args = parser.parse_args()
    # print(f"Arguments received: {args}")

    if args.ioc:
        indicator_to_query = args.ioc
        print(f"[*] Received IOC: {indicator_to_query}")

        ioc_type = detect_ioc_type(indicator_to_query)
        print(f"[*] Detected IOC Type: {ioc_type}")

        print(f"[*] Querying local database for: {indicator_to_query}")
        local_results = query_ioc(indicator_to_query)

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

    else:
        print("No IOC provided. Use --ioc <INDICATOR>")
        parser.print_help()


if __name__ == "__main__":
    main()
