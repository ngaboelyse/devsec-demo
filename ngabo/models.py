import os
import uuid
from django.db import models
from django.contrib.auth.models import User
from django.core.validators import MinValueValidator, MaxValueValidator
from django.utils import timezone

def get_secure_upload_path(instance, filename, folder):
    """Generate a random UUID-based filename to prevent collisions and traversal."""
    ext = filename.split('.')[-1]
    new_filename = f"{uuid.uuid4()}.{ext}"
    return os.path.join(folder, new_filename)

def profile_pic_path(instance, filename):
    return get_secure_upload_path(instance, filename, 'profile_pictures')

def document_upload_path(instance, filename):
    return get_secure_upload_path(instance, filename, 'user_documents')


class UserProfile(models.Model):
    """Extended user profile to store additional user information."""
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    bio = models.TextField(blank=True, help_text="User biography")
    profile_picture = models.ImageField(
        upload_to=profile_pic_path, 
        blank=True, 
        null=True,
        help_text="User profile picture (Max 2MB)"
    )
    phone_number = models.CharField(
        max_length=20, 
        blank=True,
        help_text="Contact phone number"
    )
    date_of_birth = models.DateField(
        blank=True, 
        null=True,
        help_text="User's date of birth"
    )
    document = models.FileField(
        upload_to=document_upload_path,
        blank=True,
        null=True,
        help_text="Relevant documents (PDF/DOCX, Max 5MB)"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = "User Profile"
        verbose_name_plural = "User Profiles"
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Profile of {self.user.username}"


class LoginAttempt(models.Model):
    """Track login attempts for security monitoring."""
    
    username = models.CharField(max_length=150)
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField(auto_now_add=True)
    success = models.BooleanField(default=False)
    
    class Meta:
        verbose_name = "Login Attempt"
        verbose_name_plural = "Login Attempts"
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['username', 'timestamp']),
            models.Index(fields=['ip_address', 'timestamp']),
        ]
    
    def __str__(self):
        status = "Success" if self.success else "Failed"
        return f"{self.username} - {status} ({self.timestamp})"
