MAX_DOMAINS = 50

def parse_domains(raw_domains: str) -> tuple[list[str], list[str]]:
    domains = []
    errors = []
    for line_number, line in enumerate(raw_domains.splitlines(), start=1):
        domain = line.strip().lower().rstrip(".")
        if not domain:
            continue
        try:
            normalized = domain.encode("idna").decode("ascii")
        except UnicodeError:
            errors.append(f"Line {line_number}: invalid domain name")
            continue
        if "." not in normalized:
            errors.append(f"Line {line_number}: domain must contain a dot")
            continue
        if normalized not in domains:
            domains.append(normalized)
        if len(domains) >= MAX_DOMAINS:
            errors.append(f"Only the first {MAX_DOMAINS} domains were processed")
            break
    return domains, errors
