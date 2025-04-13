import argparse


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
    print(f"Arguments received: {args}")

    if args.ioc:
        indicator_to_query = args.ioc
        print(f"Querying IOC: {indicator_to_query}")

    else:
        print("No IOC provided. Use --ioc <INDICATOR>")
        parser.print_help()


if __name__ == "__main__":
    main()
