from django.apps import apps
from django.contrib.auth.models import Group
from django.db.models.signals import post_migrate
from django.dispatch import receiver


DEFAULT_GROUPS = ['Standard Users', 'Privileged Users']


@receiver(post_migrate)
def create_default_groups(sender, **kwargs):
    """Create the required authorization groups after migrations."""
    if sender.name != 'ngabo':
        return

    for group_name in DEFAULT_GROUPS:
        Group.objects.get_or_create(name=group_name)
