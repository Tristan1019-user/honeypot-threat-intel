"""
Shared IP-scrubbing utilities.

Centralises the two implementations that previously lived separately in
main.py and routers/intel.py.  Import from here — do not add new copies.
"""

import re

# Match RFC-1918 / loopback IPs that appear as a standalone address in text.
# Lookbehind/lookahead on [0-9.] prevents matching an IP that is a sub-string
# of a larger dotted-decimal string (e.g. 210.192.168.1.100 must not match).
INTERNAL_IP_RE = re.compile(
    r"(?<![0-9.])"
    r"(192\.168\.\d{1,3}\.\d{1,3}"
    r"|10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}"
    r"|127\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|169\.254\.\d{1,3}\.\d{1,3})"
    r"(?![0-9.])"
)

SENSOR_NAME = "honeypot-svr04"


def scrub_internal_ips(text: str) -> str:
    return INTERNAL_IP_RE.sub(SENSOR_NAME, text)


def scrub_dict(obj):
    """Recursively scrub internal IPs from strings inside dicts/lists."""
    if isinstance(obj, str):
        return scrub_internal_ips(obj)
    if isinstance(obj, dict):
        return {k: scrub_dict(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [scrub_dict(v) for v in obj]
    return obj
