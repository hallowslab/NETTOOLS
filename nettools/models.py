from django.contrib.auth.models import User
from django.db import models

from .utils import metadata_target_count, metadata_targets


class ToolRun(models.Model):
    TASK_WHEREIS = "whereis"
    TASK_WHOIS = "whois"
    TASK_SPF = "spf"
    TASK_PROPAGATION = "propagation"

    TASK_CHOICES = [
        (TASK_WHEREIS, "WhereIs"),
        (TASK_WHOIS, "WHOIS Lookup"),
        (TASK_SPF, "SPF Lookup"),
        (TASK_PROPAGATION, "DNS Propagation"),
    ]

    STATUS_SUCCESS = "SUCCESS"
    STATUS_FAILED = "FAILED"
    STATUS_CHOICES = [
        (STATUS_SUCCESS, "Success"),
        (STATUS_FAILED, "Failed"),
    ]

    task = models.CharField(max_length=20, choices=TASK_CHOICES, db_index=True)
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="nettools_runs"
    )
    executed_at = models.DateTimeField(auto_now_add=True, db_index=True)
    status = models.CharField(
        max_length=10, choices=STATUS_CHOICES, default=STATUS_SUCCESS
    )
    metadata = models.JSONField(
        default=dict,
        blank=True,
        help_text="Tool-specific key/value context (e.g. input_kind, targets).",
    )

    class Meta:
        ordering = ["-executed_at"]
        indexes = [
            models.Index(fields=["task", "executed_at"]),
            models.Index(fields=["user", "executed_at"]),
        ]

    @property
    def target_count(self) -> int:
        return metadata_target_count(self.metadata)

    @property
    def targets(self) -> list[str]:
        return metadata_targets(self.metadata)

    def __str__(self):
        return f"{self.get_task_display()} by {self.user} at {self.executed_at:%Y-%m-%d %H:%M}"
