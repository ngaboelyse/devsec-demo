from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm, PasswordChangeForm
from django.core.exceptions import ValidationError
from django.utils.html import strip_tags
from .models import UserProfile


class RegistrationForm(UserCreationForm):
    """Form for user registration with email and profile fields."""
    
    email = forms.EmailField(
        required=True,
        help_text="A valid email address.",
        widget=forms.EmailInput(attrs={'class': 'form-control'})
    )
    first_name = forms.CharField(
        max_length=30,
        required=False,
        widget=forms.TextInput(attrs={'class': 'form-control'})
    )
    last_name = forms.CharField(
        max_length=30,
        required=False,
        widget=forms.TextInput(attrs={'class': 'form-control'})
    )
    
    class Meta:
        model = User
        fields = ('username', 'email', 'first_name', 'last_name', 'password1', 'password2')
        widgets = {
            'username': forms.TextInput(attrs={'class': 'form-control'}),
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['password1'].widget.attrs.update({'class': 'form-control'})
        self.fields['password2'].widget.attrs.update({'class': 'form-control'})
        self.fields['password1'].help_text = "Password must be at least 8 characters and not entirely numeric."
        self.fields['password2'].help_text = "Enter the same password as before for verification."
    
    def clean_email(self):
        """Validate that email is unique."""
        email = self.cleaned_data.get('email')
        if User.objects.filter(email=email).exists():
            raise ValidationError("An account with this email address already exists.")
        return email
    
    def clean_username(self):
        """Validate that username is unique and properly formatted."""
        username = self.cleaned_data.get('username')
        if User.objects.filter(username=username).exists():
            raise ValidationError("This username is already taken.")
        if len(username) < 3:
            raise ValidationError("Username must be at least 3 characters long.")
        return username
    
    def clean_first_name(self):
        return strip_tags(self.cleaned_data.get('first_name', ''))

    def clean_last_name(self):
        return strip_tags(self.cleaned_data.get('last_name', ''))

    def save(self, commit=True):
        """Save user and create associated profile."""
        user = super().save(commit=False)
        user.email = self.cleaned_data['email']
        # Ensure first and last name are sanitized and persisted
        user.first_name = self.cleaned_data.get('first_name', '')
        user.last_name = self.cleaned_data.get('last_name', '')

        if commit:
            user.save()
            UserProfile.objects.get_or_create(user=user)
        return user


class LoginForm(forms.Form):
    """Form for user login."""
    
    username = forms.CharField(
        max_length=150,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your username'
        })
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your password'
        })
    )
    remember_me = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'})
    )


class CustomPasswordChangeForm(PasswordChangeForm):
    """Extended password change form with custom styling."""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['old_password'].widget.attrs.update({'class': 'form-control'})
        self.fields['new_password1'].widget.attrs.update({'class': 'form-control'})
        self.fields['new_password2'].widget.attrs.update({'class': 'form-control'})
        self.fields['old_password'].widget.attrs.update({'placeholder': 'Enter your current password'})
        self.fields['new_password1'].widget.attrs.update({'placeholder': 'Enter new password'})
        self.fields['new_password2'].widget.attrs.update({'placeholder': 'Confirm new password'})


class UserProfileForm(forms.ModelForm):
    """Form for editing user profile information."""
    
    first_name = forms.CharField(
        max_length=30,
        required=False,
        widget=forms.TextInput(attrs={'class': 'form-control'})
    )
    last_name = forms.CharField(
        max_length=30,
        required=False,
        widget=forms.TextInput(attrs={'class': 'form-control'})
    )
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={'class': 'form-control'})
    )
    profile_picture = forms.ImageField(
        required=False,
        widget=forms.ClearableFileInput(attrs={'class': 'form-control'}),
        help_text="Optional profile image upload."
    )
    
    class Meta:
        model = UserProfile
        fields = ['bio', 'phone_number', 'date_of_birth', 'profile_picture']
        widgets = {
            'bio': forms.Textarea(attrs={'class': 'form-control', 'rows': 4}),
            'phone_number': forms.TextInput(attrs={'class': 'form-control', 'type': 'tel'}),
            'date_of_birth': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance and self.instance.user:
            self.fields['first_name'].initial = self.instance.user.first_name
            self.fields['last_name'].initial = self.instance.user.last_name
            self.fields['email'].initial = self.instance.user.email
    
    def clean_bio(self):
        return strip_tags(self.cleaned_data.get('bio', ''))

    def clean_first_name(self):
        return strip_tags(self.cleaned_data.get('first_name', ''))

    def clean_last_name(self):
        return strip_tags(self.cleaned_data.get('last_name', ''))

    def clean_phone_number(self):
        return strip_tags(self.cleaned_data.get('phone_number', ''))

    def save(self, commit=True):
        """Save profile and update associated user data."""
        profile = super().save(commit=False)
        if profile.user:
            profile.user.first_name = self.cleaned_data.get('first_name', '')
            profile.user.last_name = self.cleaned_data.get('last_name', '')
            profile.user.email = self.cleaned_data.get('email', '')
            if commit:
                profile.user.save()
        if commit:
            profile.save()
        return profile
