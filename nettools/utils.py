MAX_DOMAINS = 50
# imported in audit.py
INPUT_KIND_DOMAINS = "domains"
INPUT_KIND_IP_ADDRESSES = "ip_addresses"


def build_run_metadata(
    input_kind: str,
    targets: list[str],
    *,
    validation_errors: list[str] | None = None,
    **extra,
) -> dict:
    """Build a JSON-serializable metadata dict for a ToolRun."""
    data = {
        "input_kind": input_kind,
        "targets": targets,
        "target_count": len(targets),
    }
    if validation_errors:
        data["validation_errors"] = validation_errors
    data.update(extra)
    return data


def metadata_targets(metadata: dict) -> list[str]:
    return metadata.get("targets") or metadata.get("domains") or []


def metadata_target_count(metadata: dict) -> int:
    if "target_count" in metadata:
        return int(metadata["target_count"])
    return len(metadata_targets(metadata))


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
