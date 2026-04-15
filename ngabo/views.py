import logging
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import Group, User
from django.contrib import messages
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_protect
from django.db import transaction
from django.http import HttpResponseForbidden
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme
from datetime import timedelta

from .forms import RegistrationForm, LoginForm, CustomPasswordChangeForm, UserProfileForm
from .models import UserProfile, LoginAttempt

# Set up audit logger for security-relevant events
audit_logger = logging.getLogger('ngabo.audit')

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


def assign_default_group(user, ip_address=None):
    """Assign a registered user to the default standard role group."""
    group, _ = Group.objects.get_or_create(name=STANDARD_GROUP_NAME)
    user.groups.add(group)
    audit_logger.info(f"Audit: Action=GroupAssignment, User={user.username}, Group={STANDARD_GROUP_NAME}, IP={ip_address}")



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
    profile, _ = UserProfile.objects.get_or_create(user=user)
    return profile


@require_http_methods(["GET", "POST"])
@csrf_protect
def register(request):
    """Handle user registration."""
    if request.user.is_authenticated:
        return redirect('ngabo:dashboard')

    # Capture the redirection target from GET or POST
    next_url = request.POST.get('next') or request.GET.get('next')

    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            try:
                with transaction.atomic():
                    user = form.save()
                    ip_address = get_client_ip(request)
                    assign_default_group(user, ip_address=ip_address)
                    messages.success(
                        request, 
                        "Registration successful! You can now log in."
                    )
                    audit_logger.info(f"Audit: Action=Registration, User={user.username}, IP={ip_address}")
                    return redirect('ngabo:login')
            except Exception as e:
                messages.error(request, f"Registration failed: {str(e)}")
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f"{field}: {error}")
    else:
        form = RegistrationForm()
    
    return render(request, 'ngabo/register.html', {'form': form, 'next': next_url})


MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

@require_http_methods(["GET", "POST"])
@csrf_protect
def login_view(request):
    """Handle user login with attempt tracking and brute force protection."""
    if request.user.is_authenticated:
        return redirect('ngabo:dashboard')
    
    # Capture the redirection target from GET or POST
    next_url = request.POST.get('next') or request.GET.get('next')

    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            ip_address = get_client_ip(request)
            
            # --- Brute-force protection: check previous failed attempts ---
            lockout_time = timezone.now() - timedelta(minutes=LOCKOUT_MINUTES)
            
            # Check for failed attempts tied to both the username AND ip address
            recent_failed_attempts = LoginAttempt.objects.filter(
                username=username,
                ip_address=ip_address,
                success=False,
                timestamp__gte=lockout_time
            ).count()

            if recent_failed_attempts >= MAX_FAILED_ATTEMPTS:
                audit_logger.warning(f"Audit: Action=Login, Status=Lockout, User={username}, IP={ip_address}")
                messages.error(request, "Too many failed login attempts. Please try again later.")
                return render(request, 'ngabo/login.html', {'form': form})
            
            # Allow the login check
            user = authenticate(request, username=username, password=password)
            
            # Log the login attempt
            LoginAttempt.objects.create(
                username=username,
                ip_address=ip_address,
                success=user is not None
            )
            
            if user is not None:
                audit_logger.info(f"Audit: Action=Login, Status=Success, User={user.username}, IP={ip_address}")
            else:
                audit_logger.warning(f"Audit: Action=Login, Status=Failure, User={username}, IP={ip_address}")

            if user is not None:
                login(request, user)
                
                # Set session timeout based on remember_me preference
                if not form.cleaned_data.get('remember_me'):
                    request.session.set_expiry(0)  # End session on browser close
                
                messages.success(request, f"Welcome back, {user.username}!")

                # Validate redirect target to prevent open redirects
                if next_url and url_has_allowed_host_and_scheme(
                    url=next_url,
                    allowed_hosts={request.get_host()},
                    require_https=request.is_secure(),
                ):
                    return redirect(next_url)
                return redirect('ngabo:dashboard')
            else:
                messages.error(request, "Invalid username or password.")
    else:
        form = LoginForm()

    return render(request, 'ngabo/login.html', {'form': form, 'next': next_url})


@require_http_methods(["POST"])
@login_required(login_url='ngabo:login')
@csrf_protect
def logout_view(request):
    """Handle user logout."""
    username = request.user.username if request.user.is_authenticated else "Anonymous"
    ip_address = get_client_ip(request)
    next_url = request.POST.get('next') or request.GET.get('next')
    logout(request)
    audit_logger.info(f"Audit: Action=Logout, User={username}, IP={ip_address}")
    messages.success(request, "You have been logged out successfully.")

    if next_url and url_has_allowed_host_and_scheme(
        url=next_url,
        allowed_hosts={request.get_host()},
        require_https=request.is_secure(),
    ):
        return redirect(next_url)
    return redirect('ngabo:login')


@require_http_methods(["GET"])
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
    ip_address = get_client_ip(request)
    if request.method == 'POST':
        form = CustomPasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            audit_logger.info(f"Audit: Action=PasswordChange, User={user.username}, IP={ip_address}")
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
            if 'profile_picture' in request.FILES or 'document' in request.FILES:
                ip_address = get_client_ip(request)
                audit_logger.info(f"Audit: Action=FileUpload, User={request.user.username}, IP={ip_address}")
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


@require_http_methods(["GET"])
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


@require_http_methods(["GET"])
@login_required(login_url='ngabo:login')
def privileged_area(request):
    """Privileged view only for staff or members of the privileged role group."""
    ip_address = get_client_ip(request)
    if not is_privileged_user(request.user):
        audit_logger.warning(f"Audit: Action=PrivilegedAccess, Status=Denied, User={request.user.username}, IP={ip_address}")
        return HttpResponseForbidden("You do not have permission to access this page.")

    audit_logger.info(f"Audit: Action=PrivilegedAccess, Status=Granted, User={request.user.username}, IP={ip_address}")
    return render(request, 'ngabo/privileged_area.html', {
        'user': request.user,
    })
