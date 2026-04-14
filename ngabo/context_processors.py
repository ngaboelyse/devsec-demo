from django.contrib.auth.models import Group


def role_flags(request):
    """Add role-based flags to template context."""
    user = request.user
    is_privileged = False
    if user.is_authenticated:
        is_privileged = user.is_superuser or user.groups.filter(name='Privileged Users').exists()
    return {
        'is_privileged_user': is_privileged,
    }
