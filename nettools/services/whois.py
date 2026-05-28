import socket
import re
import logging
import datetime
from ..utils import parse_domains

WHOIS_TIMEOUT = 5.0
logger = logging.getLogger(__name__)

def _query_whois_server(server: str, query: str) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(WHOIS_TIMEOUT)
            s.connect((server, 43))
            s.sendall(f"{query}\r\n".encode("utf-8"))
            response = b""
            while True:
                data = s.recv(4096)
                if not data:
                    break
                response += data
            return response.decode("utf-8", errors="replace")
    except Exception as e:
        logger.error("WHOIS query failed for server %s, query %s: %s", server, query, e)
        return ""

def _get_authoritative_server(domain: str) -> str:
    tld = domain.split(".")[-1]
    iana_response = _query_whois_server("whois.iana.org", tld)
    for line in iana_response.splitlines():
        line = line.strip()
        if line.lower().startswith(("whois:", "refer:")):
            parts = line.split(":", 1)
            if len(parts) == 2:
                return parts[1].strip()
    return "whois.iana.org"

def _parse_whois(raw_text: str) -> dict:
    registrar = "Unknown"
    expiry_date = "Unknown"
    nameservers = []

    # Regex matches
    registrar_match = re.search(r"(?i)(?:registrar|sponsoring registrar|registrar organization):\s*(.+)", raw_text)
    if registrar_match:
        registrar = registrar_match.group(1).strip()

    expiry_match = re.search(r"(?i)(?:registry expiry date|expiry date|expiration date|expiration time|expires|paid-till):\s*(.+)", raw_text)
    if expiry_match:
        expiry_date = expiry_match.group(1).strip()

    ns_matches = re.findall(r"(?i)(?:name server|nameserver|nserver):\s*(.+)", raw_text)
    for ns in ns_matches:
        # Clean up nameserver values (remove potential IP addresses or comments separated by spaces)
        ns_clean = ns.strip().lower().rstrip(".")
        if ns_clean:
            ns_clean = ns_clean.split()[0]
            if ns_clean and ns_clean not in nameservers:
                nameservers.append(ns_clean)

    return {
        "registrar": registrar,
        "expiry_date": expiry_date,
        "nameservers": nameservers,
    }

def _is_expired(expiry_date_str: str) -> bool | None:
    if not expiry_date_str or expiry_date_str.lower() in ("unknown", "none", ""):
        return None

    date_str = expiry_date_str.strip()

    # Try parsing ISO 8601 formats first (e.g., 2028-09-14T04:00:00Z)
    try:
        iso_str = date_str.replace("Z", "+00:00")
        dt = datetime.datetime.fromisoformat(iso_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt < datetime.datetime.now(datetime.timezone.utc)
    except ValueError:
        pass

    # Try common formats
    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%d",
        "%d-%b-%Y",
        "%d/%m/%Y",
        "%m/%d/%Y",
        "%Y.%m.%d",
        "%d.%m.%Y",
    ]
    for fmt in formats:
        try:
            dt = datetime.datetime.strptime(date_str, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.timezone.utc)
            return dt < datetime.datetime.now(datetime.timezone.utc)
        except ValueError:
            continue

    # Fallback to year extraction
    year_match = re.search(r"\b(19\d\d|20\d\d)\b", date_str)
    if year_match:
        try:
            year = int(year_match.group(1))
            current_year = datetime.datetime.now(datetime.timezone.utc).year
            if year < current_year:
                return True
            elif year > current_year:
                return False
        except ValueError:
            pass

    return None

def lookup_whois(raw_domains: str) -> dict:
    domains, input_errors = parse_domains(raw_domains)
    results = []
    for domain in domains:
        try:
            server = _get_authoritative_server(domain)
            raw_text = _query_whois_server(server, domain)
            parsed = _parse_whois(raw_text)
            results.append({
                "domain": domain,
                "registrar": parsed["registrar"],
                "expiry_date": parsed["expiry_date"],
                "is_expired": _is_expired(parsed["expiry_date"]),
                "nameservers": parsed["nameservers"],
                "error": None if raw_text else "Failed to retrieve WHOIS data from " + server,
            })
        except Exception as e:
            results.append({
                "domain": domain,
                "registrar": "Unknown",
                "expiry_date": "Unknown",
                "is_expired": None,
                "nameservers": [],
                "error": f"Error: {e}",
            })
    return {
        "input_errors": input_errors,
        "results": results,
    }
