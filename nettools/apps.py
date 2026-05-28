from django.apps import AppConfig


class NettoolsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "nettools"
    verbose_name = "NETTOOLS"
    is_modular = True
    root_url = "/NETTOOLS"
    icon = "🗄️"

    def get_dashboard_stats(self):

        total_dbs_transferred = 60

        total_size_output_bytes = 234567890
        total_size_input_bytes = 1234567890

        total_size_output_gb = total_size_output_bytes / (1024**3)
        total_size_input_gb = total_size_input_bytes / (1024**3)

        return {
            "(WIP)Total DBs Transferred": total_dbs_transferred,
            "(WIP)Total output (GB)": f"{total_size_output_gb:.2f}",
            "(WIP)Total input (GB)": f"{total_size_input_gb:.2f}",
        }
