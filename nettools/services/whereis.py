import ipaddress
import logging
import socket
from ..utils import parse_domains

try:
    import dns.exception
    import dns.reversename
    import dns.resolver
except ImportError:
    dns = None


DNS_TIMEOUT = 3.0
logger = logging.getLogger(__name__)


def lookup_domains(raw_domains: str) -> dict:
    domains, input_errors = parse_domains(raw_domains)
    if dns is None:
        return {
            "input_errors": input_errors
            + ["dnspython is not installed; WhereIs DNS lookups are unavailable"],
            "results": [],
        }

    resolver = dns.resolver.Resolver()
    resolver.nameservers = [
        "1.1.1.1",
        "8.8.8.8",
    ]
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT

    return {
        "input_errors": input_errors,
        "results": [_lookup_domain(resolver, domain) for domain in domains],
    }


def _lookup_domain(resolver, domain: str) -> dict:
    result = {
        "domain": domain,
        "a_records": [],
        "mx_records": [],
        "errors": [],
    }

    a_records, a_error = _lookup_a_records(resolver, domain)
    if a_error:
        result["errors"].append(a_error)

    result["a_records"] = [
        _build_ip_record(resolver, ip)
        for ip in a_records
    ]

    mx_records, mx_error = _lookup_mx_records(resolver, domain)
    if mx_error:
        result["errors"].append(mx_error)

    for mx_record in mx_records:
        mx_host = mx_record["host"]
        mx_ips, mx_a_error = _lookup_a_records(resolver, mx_host)
        if mx_a_error:
            result["errors"].append(mx_a_error)

        result["mx_records"].append(
            {
                "priority": mx_record["priority"],
                "host": mx_host,
                "a_records": [
                    _build_ip_record(resolver, ip)
                    for ip in mx_ips
                ],
            }
        )

    return result


def _build_ip_record(resolver, ip: str) -> dict:
    ptr, ptr_error = _lookup_ptr(resolver, ip)
    return {
        "ip": ip,
        "ptr": ptr,
        "ptr_error": ptr_error,
    }


def _lookup_a_records(resolver, hostname: str) -> tuple[list[str], str | None]:
    try:
        answers = resolver.resolve(hostname, "A")
        return sorted({answer.address for answer in answers}), None
    except dns.resolver.NoAnswer:
        return [], f"{hostname}: no A records"
    except dns.resolver.NXDOMAIN:
        return [], f"{hostname}: domain does not exist"
    except dns.exception.Timeout:
        return [], f"{hostname}: A lookup timed out"
    except dns.exception.DNSException as e:
        return [], f"{hostname}: A lookup failed ({e})"


def _lookup_mx_records(resolver, domain: str) -> tuple[list[dict], str | None]:
    try:
        answers = resolver.resolve(domain, "MX")
        records = [
            {
                "priority": answer.preference,
                "host": str(answer.exchange).rstrip(".").lower(),
            }
            for answer in answers
        ]
        return sorted(records, key=lambda record: (record["priority"], record["host"])), None
    except dns.resolver.NoAnswer:
        return [], f"{domain}: no MX records"
    except dns.resolver.NXDOMAIN:
        return [], f"{domain}: domain does not exist"
    except dns.exception.Timeout:
        return [], f"{domain}: MX lookup timed out"
    except dns.exception.DNSException as e:
        return [], f"{domain}: MX lookup failed ({e})"


def _lookup_ptr(resolver, ip: str) -> tuple[str | None, str | None]:
    try:
        ipaddress.ip_address(ip)
        reverse_name = dns.reversename.from_address(ip)
        answers = resolver.resolve(str(reverse_name), "PTR")
        return str(next(iter(answers))).rstrip("."), None
    except ValueError:
        logger.warning("PTR lookup skipped for invalid IP %s", ip)
        return None, "invalid IP"
    except StopIteration:
        logger.info("PTR lookup returned no answers for %s", ip)
        return _lookup_ptr_with_socket(ip, "no PTR answer")
    except dns.resolver.NXDOMAIN:
        logger.info("PTR lookup NXDOMAIN for %s", ip)
        return _lookup_ptr_with_socket(ip, "PTR does not exist")
    except dns.resolver.NoAnswer:
        logger.info("PTR lookup NoAnswer for %s", ip)
        return _lookup_ptr_with_socket(ip, "no PTR record")
    except dns.exception.Timeout:
        logger.warning("PTR lookup timed out for %s", ip)
        return _lookup_ptr_with_socket(ip, "PTR lookup timed out")
    except dns.exception.DNSException as e:
        logger.warning("PTR lookup failed for %s: %s", ip, e)
        return _lookup_ptr_with_socket(ip, f"PTR lookup failed ({e})")


def _lookup_ptr_with_socket(ip: str, fallback_error: str) -> tuple[str | None, str | None]:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname.rstrip("."), None
    except socket.herror as e:
        logger.info("socket PTR lookup found no host for %s: %s", ip, e)
    except OSError as e:
        logger.warning("socket PTR lookup failed for %s: %s", ip, e)

    return None, fallback_error
