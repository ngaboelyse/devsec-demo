from django.contrib import admin
from .models import UserProfile, LoginAttempt


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    """Admin interface for UserProfile model."""
    
    list_display = ('user', 'phone_number', 'created_at', 'updated_at')
    list_filter = ('created_at', 'updated_at')
    search_fields = ('user__username', 'user__email', 'phone_number')
    readonly_fields = ('created_at', 'updated_at')
    
    fieldsets = (
        ('User Information', {
            'fields': ('user',)
        }),
        ('Profile Details', {
            'fields': ('bio', 'phone_number', 'date_of_birth', 'profile_picture', 'document')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(LoginAttempt)
class LoginAttemptAdmin(admin.ModelAdmin):
    """Admin interface for LoginAttempt model for security monitoring."""
    
    list_display = ('username', 'ip_address', 'success', 'timestamp')
    list_filter = ('success', 'timestamp')
    search_fields = ('username', 'ip_address')
    readonly_fields = ('username', 'ip_address', 'timestamp', 'success')
    
    fieldsets = (
        ('Login Information', {
            'fields': ('username', 'ip_address', 'success', 'timestamp')
        }),
    )
    
    def has_add_permission(self, request):
        """Prevent manual addition of login attempts from admin."""
        return False
    
    def has_delete_permission(self, request, obj=None):
        """Allow deletion only for security reasons."""
        return request.user.is_superuser
