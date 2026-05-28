from .models import ToolRun
from .utils import parse_domains, INPUT_KIND_DOMAINS, build_run_metadata


def record_tool_run(
    user,
    task: str,
    raw_input: str = "",
    lookup_result: dict | None = None,
    *,
    metadata: dict | None = None,
) -> ToolRun:
    if metadata is None:
        targets, validation_errors = parse_domains(raw_input)
        metadata = build_run_metadata(
            INPUT_KIND_DOMAINS,
            targets,
            validation_errors=validation_errors,
        )

    status = ToolRun.STATUS_SUCCESS
    if lookup_result is not None:
        has_results = bool(lookup_result.get("results"))
        has_errors = bool(lookup_result.get("input_errors"))
        if has_errors and not has_results:
            status = ToolRun.STATUS_FAILED

    return ToolRun.objects.create(
        task=task,
        user=user,
        status=status,
        metadata=metadata,
    )
