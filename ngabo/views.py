from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import Group, User
from django.contrib import messages
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_protect
from django.db import transaction
from django.http import HttpResponseForbidden

from .forms import RegistrationForm, LoginForm, CustomPasswordChangeForm, UserProfileForm
from .models import UserProfile, LoginAttempt

STANDARD_GROUP_NAME = 'Standard Users'
PRIVILEGED_GROUP_NAME = 'Privileged Users'


def get_client_ip(request):
    """Extract client IP address from request."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def assign_default_group(user):
    """Assign a registered user to the default standard role group."""
    group, _ = Group.objects.get_or_create(name=STANDARD_GROUP_NAME)
    user.groups.add(group)


def is_privileged_user(user):
    """Check whether the user belongs to a privileged role."""
    return user.is_authenticated and (user.is_superuser or user.groups.filter(name=PRIVILEGED_GROUP_NAME).exists())


def reject_external_user_reference(request):
    """Reject requests that attempt to override current user object ownership.

    This prevents future IDOR risks when external identifiers are supplied.
    """
    candidate_fields = ('user_id', 'profile_id', 'username')
    if any(field in request.GET or field in request.POST for field in candidate_fields):
        return HttpResponseForbidden("Invalid direct object reference.")
    return None


def get_owned_user_profile(user):
    """Resolve the authenticated user's profile without using external identifiers."""
    profile = UserProfile.objects.filter(user=user).first()
    if profile is None:
        profile = UserProfile.objects.create(user=user)
    return profile


@require_http_methods(["GET", "POST"])
@csrf_protect
def register(request):
    """Handle user registration."""
    if request.user.is_authenticated:
        return redirect('ngabo:dashboard')
    
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            try:
                with transaction.atomic():
                    user = form.save()
                    assign_default_group(user)
                    messages.success(
                        request, 
                        "Registration successful! You can now log in."
                    )
                    return redirect('ngabo:login')
            except Exception as e:
                messages.error(request, f"Registration failed: {str(e)}")
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f"{field}: {error}")
    else:
        form = RegistrationForm()
    
    return render(request, 'ngabo/register.html', {'form': form})


@require_http_methods(["GET", "POST"])
@csrf_protect
def login_view(request):
    """Handle user login with attempt tracking."""
    if request.user.is_authenticated:
        return redirect('ngabo:dashboard')
    
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            ip_address = get_client_ip(request)
            
            user = authenticate(request, username=username, password=password)
            
            # Log the login attempt
            LoginAttempt.objects.create(
                username=username,
                ip_address=ip_address,
                success=user is not None
            )
            
            if user is not None:
                login(request, user)
                
                # Set session timeout based on remember_me preference
                if not form.cleaned_data.get('remember_me'):
                    request.session.set_expiry(0)  # End session on browser close
                
                messages.success(request, f"Welcome back, {user.username}!")
                return redirect('ngabo:dashboard')
            else:
                messages.error(request, "Invalid username or password.")
    else:
        form = LoginForm()
    
    return render(request, 'ngabo/login.html', {'form': form})


@require_http_methods(["POST"])
@login_required(login_url='ngabo:login')
def logout_view(request):
    """Handle user logout."""
    username = request.user.username
    logout(request)
    messages.success(request, "You have been logged out successfully.")
    return redirect('ngabo:login')


@login_required(login_url='ngabo:login')
def dashboard(request):
    """Protected dashboard view for authenticated users."""
    access_denied = reject_external_user_reference(request)
    if access_denied:
        return access_denied

    profile = get_owned_user_profile(request.user)
    
    context = {
        'profile': profile,
        'user': request.user,
    }
    return render(request, 'ngabo/dashboard.html', context)


@require_http_methods(["GET", "POST"])
@login_required(login_url='ngabo:login')
@csrf_protect
def change_password(request):
    """Allow users to change their password."""
    if request.method == 'POST':
        form = CustomPasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            messages.success(request, "Your password has been changed successfully.")
            return redirect('ngabo:dashboard')
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f"{field}: {error}")
    else:
        form = CustomPasswordChangeForm(request.user)
    
    return render(request, 'ngabo/change_password.html', {'form': form})


@require_http_methods(["GET", "POST"])
@login_required(login_url='ngabo:login')
@csrf_protect
def profile(request):
    """Allow users to view and edit their profile."""
    access_denied = reject_external_user_reference(request)
    if access_denied:
        return access_denied

    user_profile = get_owned_user_profile(request.user)
    
    if request.method == 'POST':
        form = UserProfileForm(request.POST, request.FILES, instance=user_profile)
        if form.is_valid():
            form.save()
            messages.success(request, "Your profile has been updated successfully.")
            return redirect('ngabo:profile')
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f"{field}: {error}")
    else:
        form = UserProfileForm(instance=user_profile)
    
    context = {
        'form': form,
        'profile': user_profile,
    }
    return render(request, 'ngabo/profile.html', context)


@login_required(login_url='ngabo:login')
def account_settings(request):
    """View for account settings and security options."""
    access_denied = reject_external_user_reference(request)
    if access_denied:
        return access_denied

    profile = get_owned_user_profile(request.user)
    
    context = {
        'profile': profile,
        'user': request.user,
    }
    return render(request, 'ngabo/account_settings.html', context)


@login_required(login_url='ngabo:login')
def privileged_area(request):
    """Privileged view only for staff or members of the privileged role group."""
    if not is_privileged_user(request.user):
        return HttpResponseForbidden("You do not have permission to access this page.")

    return render(request, 'ngabo/privileged_area.html', {
        'user': request.user,
    })

