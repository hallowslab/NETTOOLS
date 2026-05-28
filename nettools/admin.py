import json

from django.contrib import admin
from django.utils.html import format_html

from .utils import metadata_targets
from .models import ToolRun


@admin.register(ToolRun)
class ToolRunAdmin(admin.ModelAdmin):
    list_display = (
        "executed_at",
        "task",
        "user",
        "status",
        "target_summary",
        "target_count",
    )
    list_filter = ("task", "status", "executed_at")
    search_fields = ("user__username",)
    readonly_fields = (
        "task",
        "user",
        "executed_at",
        "status",
        "target_count",
        "metadata",
        "metadata_pretty",
    )
    fields = readonly_fields

    @admin.display(description="Target count")
    def target_count(self, obj):
        return obj.target_count

    @admin.display(description="Targets")
    def target_summary(self, obj):
        targets = metadata_targets(obj.metadata)
        if not targets:
            return "—"
        preview = ", ".join(targets[:3])
        if len(targets) > 3:
            preview += f", … (+{len(targets) - 3})"
        return preview

    @admin.display(description="Metadata")
    def metadata_pretty(self, obj):
        return format_html(
            "<pre style='margin:0'>{}</pre>",
            json.dumps(obj.metadata, indent=2, sort_keys=True),
        )

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False
