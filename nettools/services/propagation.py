import dns.resolver
import collections
import logging
from ..utils import parse_domains

DNS_TIMEOUT = 2.0
logger = logging.getLogger(__name__)

# Easily customizable list of public DNS resolvers
RESOLVERS = [
    {"name": "Cloudflare", "ip": "1.1.1.1"},
    {"name": "Google", "ip": "8.8.8.8"},
    {"name": "DNS4EU - Protective", "ip": "86.54.11.1"},
    {"name": "DNS4EU - Unfiltered", "ip": "86.54.11.100"},
    {"name": "CleanBrowsing", "ip": "185.228.168.168"},
    {"name": "AdGuard", "ip": "94.140.14.14"},
    {"name": "Control D - Unfiltered", "ip": "76.76.2.0"},
    {"name": "Quad9 'secure'", "ip": "9.9.9.9"},
    {"name": "Quad9 'insecure'", "ip": "9.9.9.10"},
    {"name": "OpenDNS", "ip": "208.67.222.222"},
]


def lookup_propagation(raw_domains: str) -> dict:
    domains, input_errors = parse_domains(raw_domains)
    results = []

    for domain in domains:
        resolver_results = []
        ip_sets = []

        # 1. Query each configured resolver
        for res in RESOLVERS:
            res_ip = res["ip"]
            res_name = res["name"]

            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = [res_ip]
            resolver.timeout = DNS_TIMEOUT
            resolver.lifetime = DNS_TIMEOUT

            try:
                answers = resolver.resolve(domain, "A")
                ips = sorted([answer.address for answer in answers])
                error = None
            except dns.resolver.NoAnswer:
                ips = []
                error = "No A records"
            except dns.resolver.NXDOMAIN:
                ips = []
                error = "Domain does not exist"
            except Exception as e:
                ips = []
                error = f"Query failed: {e}"

            resolver_results.append(
                {
                    "name": res_name,
                    "ip": res_ip,
                    "ips": ips,
                    "error": error,
                    "is_mismatch": False,
                }
            )

            if not error and ips:
                ip_sets.append(tuple(ips))

        # 2. Determine consensus (most common non-empty set of resolved IPs)
        consensus = None
        if ip_sets:
            counter = collections.Counter(ip_sets)
            consensus = counter.most_common(1)[0][0]

        # 3. Flag resolvers that deviate from consensus
        all_match = True
        for res_res in resolver_results:
            if consensus:
                if res_res["error"] or tuple(res_res["ips"]) != consensus:
                    res_res["is_mismatch"] = True
                    all_match = False
            else:
                # If no consensus exists (all failed or returned empty)
                if res_res["error"]:
                    all_match = False

        results.append(
            {
                "domain": domain,
                "resolver_results": resolver_results,
                "all_match": all_match and len(ip_sets) == len(RESOLVERS),
                "has_records": len(ip_sets) > 0,
            }
        )

    return {
        "input_errors": input_errors,
        "results": results,
    }
