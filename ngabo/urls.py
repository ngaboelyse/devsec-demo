from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

app_name = 'ngabo'

urlpatterns = [
    path('register/', views.register, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('profile/', views.profile, name='profile'),
    path('change-password/', views.change_password, name='change_password'),
    path('account-settings/', views.account_settings, name='account_settings'),
    path('privileged-area/', views.privileged_area, name='privileged_area'),

    # ── Secure password-reset flow (Django built-in views) ─────────────
    # Step 1: User submits their email address.
    path(
        'password-reset/',
        auth_views.PasswordResetView.as_view(
            template_name='ngabo/password_reset_request.html',
            email_template_name='ngabo/password_reset_email.html',
            subject_template_name='ngabo/password_reset_subject.txt',
            success_url='/auth/password-reset/done/',
        ),
        name='password_reset',
    ),
    # Step 2: Confirmation page shown after the form is submitted.
    # The same message is displayed whether or not an account exists
    # to prevent user-enumeration attacks.
    path(
        'password-reset/done/',
        auth_views.PasswordResetDoneView.as_view(
            template_name='ngabo/password_reset_done.html',
        ),
        name='password_reset_done',
    ),
    # Step 3: User clicks the link in the email and sets a new password.
    # Django validates the HMAC token before rendering the form.
    path(
        'password-reset-confirm/<uidb64>/<token>/',
        auth_views.PasswordResetConfirmView.as_view(
            template_name='ngabo/password_reset_confirm.html',
            success_url='/auth/password-reset-complete/',
        ),
        name='password_reset_confirm',
    ),
    # Step 4: Success page after the password has been updated.
    path(
        'password-reset-complete/',
        auth_views.PasswordResetCompleteView.as_view(
            template_name='ngabo/password_reset_complete.html',
        ),
        name='password_reset_complete',
    ),
]
