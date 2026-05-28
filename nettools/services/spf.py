import dns.resolver
import dns.exception
import re
import logging
from ..utils import parse_domains

DNS_TIMEOUT = 3.0
logger = logging.getLogger(__name__)

def _parse_spf_policy(record: str) -> tuple[str, str]:
    # Match any ending qualifier like -all, ~all, ?all, +all
    match = re.search(r"\b([+\-~?])all\b", record.lower())
    if match:
        qualifier = match.group(1)
        if qualifier == "-":
            return "Hard Fail (Reject)", "is-danger"
        elif qualifier == "~":
            return "Soft Fail", "is-warning"
        elif qualifier == "?":
            return "Neutral", "is-info"
        elif qualifier == "+":
            return "Pass (Open)", "is-success"

    if "all" in record.lower().split():
        return "Pass (Open)", "is-success"

    return "No explicit 'all' policy", "is-light"

def lookup_spf(raw_domains: str) -> dict:
    domains, input_errors = parse_domains(raw_domains)
    results = []

    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT

    for domain in domains:
        spf_records = []
        dns_error = None
        try:
            answers = resolver.resolve(domain, "TXT")
            for answer in answers:
                txt_content = "".join(chunk.decode("utf-8") for chunk in answer.strings)
                if txt_content.lower().startswith("v=spf1"):
                    spf_records.append(txt_content)
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            dns_error = "Domain does not exist"
        except dns.exception.Timeout:
            dns_error = "DNS lookup timed out"
        except dns.exception.DNSException as e:
            dns_error = f"DNS query failed: {e}"

        parsed_records = []
        for record in spf_records:
            policy_name, policy_class = _parse_spf_policy(record)

            # Highlight ~all / -all for clean display
            highlighted = record
            highlighted = re.sub(r"\b(~all)\b", r'<span class="has-text-weight-bold has-text-warning">\1</span>', highlighted, flags=re.IGNORECASE)
            highlighted = re.sub(r"\b(-all)\b", r'<span class="has-text-weight-bold has-text-danger">\1</span>', highlighted, flags=re.IGNORECASE)
            highlighted = re.sub(r"\b(\?all|\+all)\b", r'<span class="has-text-weight-bold has-text-info">\1</span>', highlighted, flags=re.IGNORECASE)

            parsed_records.append({
                "raw": record,
                "highlighted": highlighted,
                "policy": policy_name,
                "policy_class": policy_class,
            })

        results.append({
            "domain": domain,
            "records": parsed_records,
            "multiple_spf": len(spf_records) > 1,
            "error": dns_error,
        })

    return {
        "input_errors": input_errors,
        "results": results,
    }
