from django.apps import AppConfig


class NettoolsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "nettools"
    verbose_name = "NETTOOLS"
    is_modular = True
    root_url = "/NETTOOLS"
    icon = "🗄️"

    def get_dashboard_stats(self):
        from django.db.models import Count

        from .models import ToolRun

        runs = ToolRun.objects.select_related("user")
        total_runs = runs.count()
        if total_runs == 0:
            return {"Total Runs": 0}

        success_runs = runs.filter(status=ToolRun.STATUS_SUCCESS).count()
        success_pct = success_runs / total_runs * 100

        stats = {
            "Total Runs": total_runs,
            "Success Rate": f"{success_pct:.1f}%",
        }

        task_labels = dict(ToolRun.TASK_CHOICES)
        counts_by_task = {
            row["task"]: row["count"]
            for row in runs.values("task").annotate(count=Count("id"))
        }
        for task_key, label in task_labels.items():
            stats[f"{label} Runs"] = counts_by_task.get(task_key, 0)

        last_run = runs.first()
        if last_run:
            stats["Last Run"] = (
                f"{last_run.user.username} — {last_run.get_task_display()} "
                f"at {last_run.executed_at:%Y-%m-%d %H:%M UTC}"
            )

        top_user = (
            runs.values("user__username")
            .annotate(count=Count("id"))
            .order_by("-count", "user__username")
            .first()
        )
        if top_user:
            stats["Most Active User"] = (
                f"{top_user['user__username']} ({top_user['count']} runs)"
            )

        return stats
