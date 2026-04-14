from django.apps import AppConfig


class NgaboConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'ngabo'

    def ready(self):
        # Load signal handlers for group initialization and role setup.
        from . import signals  # noqa: F401
