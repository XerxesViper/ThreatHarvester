import re
import warnings


def is_hex(s):
    """Checks if a string contains only hexadecimal characters."""
    if not isinstance(s, str):
        return False

    if not s:
        return False
        # Using regex to match start(^) to end($) with one or more(+) hex chars
    return bool(re.match(r'^[0-9a-fA-F]+$', s))


# --- REGEX PATTERNS ---

# Basic IPv4 - Allows 0-255 in each octet
# Consider adding ^ and $ for full string match if needed depending on usage
IPV4_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)

# Basic Domain Name - Allows letters, numbers, hyphens (not at start/end)
# Does NOT validate TLDs strictly. Allows subdomains.
# Does NOT match localhost or single-word domains without TLD.
DOMAIN_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9]"  # First char
    r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"  # Subdomains/domain part
    r"[a-zA-Z]{2,}$"  # TLD (at least 2 letters)
)

# Simple URL check - looks for schema://
URL_PATTERN = re.compile(r"^[a-zA-Z]+://")


def detect_ioc_type(indicator):
    """
        Detects the type of Indicator of Compromise (IOC).

        Args:
            indicator (str): The IOC string to classify.

        Returns:
            str: The detected IOC type ('ipv4', 'domain', 'url',
                 'md5', 'sha1', 'sha256', or 'unknown').
    """

    if not isinstance(indicator, str):
        warnings.warn("Indicator type not recognised - May lead to unexpected or incorrect results. Please check the input again", FutureWarning)
        return 'unknown'

    indicator = indicator.strip()  # Remove leading/trailing whitespace

    # 1. Check for Hashes (by length and hex content)
    length = len(indicator)
    if length == 64 and is_hex(indicator):
        return 'sha256'
    if length == 40 and is_hex(indicator):
        return 'sha1'
    if length == 32 and is_hex(indicator):
        return 'md5'

    # 2. Check for IPv4
    if IPV4_PATTERN.match(indicator):
        return 'ipv4'

    # 3. Check for URL (basic check for schema)
    # Check URL before domain, as URLs contain domains
    if URL_PATTERN.match(indicator):
        return 'url'

    # 4. Check for Domain Name
    # Ensure it's not just an IP address that somehow failed the IP check
    if DOMAIN_PATTERN.match(indicator):
        return 'domain'

    # 5. If none of the above match
    return 'unknown'
