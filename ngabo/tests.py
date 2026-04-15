import logging
from django.test import TestCase, Client
from django.contrib.auth.models import Group, User
from django.contrib.auth.tokens import default_token_generator
from django.core import mail
from django.template import Template
from django.test.utils import _TestState
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from .models import UserProfile, LoginAttempt


def restore_template_render_method():
    """Restore Django's original template render method to avoid instrumentation bugs."""
    try:
        if hasattr(_TestState, 'saved_data') and hasattr(_TestState.saved_data, 'template_render'):
            Template._render = _TestState.saved_data.template_render
    except Exception:
        pass


class BaseAuthTestCase(TestCase):
    @classmethod
    def setUpClass(cls):
        restore_template_render_method()
        super().setUpClass()


class UserAuthenticationTestCase(BaseAuthTestCase):
    """Test cases for user registration functionality."""
    
    def setUp(self):
        """Set up test client and test data."""
        self.client = Client()
        self.register_url = reverse('ngabo:register')
        self.login_url = reverse('ngabo:login')
        self.dashboard_url = reverse('ngabo:dashboard')
        
    def test_register_page_loads(self):
        """Test that registration page loads successfully."""
        response = self.client.get(self.register_url)
        self.assertEqual(response.status_code, 200)
    
    def test_user_registration_success(self):
        """Test successful user registration."""
        data = {
            'username': 'testuser',
            'email': 'testuser@example.com',
            'first_name': 'Test',
            'last_name': 'User',
            'password1': 'TestPassword123',
            'password2': 'TestPassword123'
        }
        response = self.client.post(self.register_url, data)
        
        self.assertEqual(response.status_code, 302)  # Redirect after successful registration
        self.assertTrue(User.objects.filter(username='testuser').exists())
        self.assertTrue(UserProfile.objects.filter(user__username='testuser').exists())
    
    def test_user_registration_duplicate_username(self):
        """Test registration fails with duplicate username."""
        User.objects.create_user(username='testuser', email='test1@example.com', password='TestPassword123')
        
        data = {
            'username': 'testuser',
            'email': 'testuser2@example.com',
            'password1': 'TestPassword123',
            'password2': 'TestPassword123'
        }
        response = self.client.post(self.register_url, data)
        
        self.assertEqual(response.status_code, 200)  # Stay on registration page
        self.assertEqual(User.objects.filter(username='testuser').count(), 1)
    
    def test_user_registration_duplicate_email(self):
        """Test registration fails with duplicate email."""
        User.objects.create_user(username='testuser1', email='test@example.com', password='TestPassword123')
        
        data = {
            'username': 'testuser2',
            'email': 'test@example.com',
            'password1': 'TestPassword123',
            'password2': 'TestPassword123'
        }
        response = self.client.post(self.register_url, data)
        
        self.assertEqual(response.status_code, 200)  # Stay on registration page
        self.assertEqual(User.objects.filter(email='test@example.com').count(), 1)
    
    def test_user_registration_password_mismatch(self):
        """Test registration fails when passwords don't match."""
        data = {
            'username': 'testuser',
            'email': 'testuser@example.com',
            'password1': 'TestPassword123',
            'password2': 'TestPassword456'
        }
        response = self.client.post(self.register_url, data)
        
        self.assertEqual(response.status_code, 200)  # Stay on registration page
        self.assertFalse(User.objects.filter(username='testuser').exists())
    
    def test_user_registration_short_username(self):
        """Test registration fails with username less than 3 characters."""
        data = {
            'username': 'ab',
            'email': 'testuser@example.com',
            'password1': 'TestPassword123',
            'password2': 'TestPassword123'
        }
        response = self.client.post(self.register_url, data)
        
        self.assertEqual(response.status_code, 200)  # Stay on registration page
        self.assertFalse(User.objects.filter(username='ab').exists())

    def test_user_is_assigned_standard_group_after_registration(self):
        """Test that new users are assigned the standard role group."""
        data = {
            'username': 'groupuser',
            'email': 'groupuser@example.com',
            'password1': 'TestPassword123',
            'password2': 'TestPassword123'
        }
        self.client.post(self.register_url, data)
        user = User.objects.get(username='groupuser')
        self.assertTrue(user.groups.filter(name='Standard Users').exists())


class UserLoginTestCase(BaseAuthTestCase):
    """Test cases for user login functionality."""
    
    def setUp(self):
        """Set up test client and test users."""
        self.client = Client()
        self.login_url = reverse('ngabo:login')
        self.dashboard_url = reverse('ngabo:dashboard')
        self.logout_url = reverse('ngabo:logout')
        
        self.user = User.objects.create_user(
            username='testuser',
            email='testuser@example.com',
            password='TestPassword123'
        )
        UserProfile.objects.create(user=self.user)
    
    def test_login_page_loads(self):
        """Test that login page loads successfully."""
        response = self.client.get(self.login_url)
        self.assertEqual(response.status_code, 200)
    
    def test_user_login_success(self):
        """Test successful user login."""
        data = {
            'username': 'testuser',
            'password': 'TestPassword123',
            'remember_me': False
        }
        response = self.client.post(self.login_url, data)
        
        self.assertEqual(response.status_code, 302)  # Redirect after successful login
        self.assertIn('_auth_user_id', self.client.session)  # Session contains user ID
    
    def test_user_login_invalid_password(self):
        """Test login fails with invalid password."""
        data = {
            'username': 'testuser',
            'password': 'WrongPassword',
            'remember_me': False
        }
        response = self.client.post(self.login_url, data)
        
        self.assertEqual(response.status_code, 200)  # Stay on login page
        self.assertNotIn('_auth_user_id', self.client.session)  # No user session
    
    def test_user_login_nonexistent_user(self):
        """Test login fails for non-existent user."""
        data = {
            'username': 'nonexistent',
            'password': 'TestPassword123',
            'remember_me': False
        }
        response = self.client.post(self.login_url, data)
        
        self.assertEqual(response.status_code, 200)  # Stay on login page
        self.assertNotIn('_auth_user_id', self.client.session)
    
    def test_login_attempt_recorded_success(self):
        """Test that successful login attempts are recorded."""
        data = {
            'username': 'testuser',
            'password': 'TestPassword123',
            'remember_me': False
        }
        self.client.post(self.login_url, data)
        
        login_attempt = LoginAttempt.objects.filter(username='testuser', success=True).first()
        self.assertIsNotNone(login_attempt)
    
    def test_login_attempt_recorded_failure(self):
        """Test that failed login attempts are recorded."""
        data = {
            'username': 'testuser',
            'password': 'WrongPassword',
            'remember_me': False
        }
        self.client.post(self.login_url, data)
        
        login_attempt = LoginAttempt.objects.filter(username='testuser', success=False).first()
        self.assertIsNotNone(login_attempt)

    def test_brute_force_lockout(self):
        """Test that 5 failed attempts trigger the lockout feature."""
        # 1. Attempt 5 wrong logins
        data = {
            'username': 'testuser',
            'password': 'WrongPassword',
            'remember_me': False
        }

        for _ in range(5):
            self.client.post(self.login_url, data)
        
        # 2. Attempt 6th login (should trigger rate limit / lockout message)
        data_correct = {
            'username': 'testuser',
            'password': 'TestPassword123',  # correct password, but should still fail due to lockout
            'remember_me': False
        }
        response = self.client.post(self.login_url, data_correct)
        
        self.assertEqual(response.status_code, 200) # does not log the user in
        self.assertContains(response, 'Too many failed login attempts')
        self.assertNotIn('_auth_user_id', self.client.session) # not logged in


class RoleBasedAccessTestCase(BaseAuthTestCase):
    """Test cases for role-based authorization rules."""

    def setUp(self):
        self.client = Client()
        self.privileged_url = reverse('ngabo:privileged_area')
        self.login_url = reverse('ngabo:login')

        self.standard_user = User.objects.create_user(
            username='standard',
            email='standard@example.com',
            password='TestPassword123'
        )
        self.privileged_group, _ = Group.objects.get_or_create(name='Privileged Users')
        self.privileged_user = User.objects.create_user(
            username='privileged',
            email='privileged@example.com',
            password='TestPassword123'
        )
        self.privileged_user.groups.add(self.privileged_group)

    def test_anonymous_user_redirected_from_privileged_area(self):
        response = self.client.get(self.privileged_url)
        self.assertEqual(response.status_code, 302)
        self.assertIn(self.login_url, response.url)

    def test_standard_user_denied_privileged_area(self):
        self.client.login(username='standard', password='TestPassword123')
        response = self.client.get(self.privileged_url)
        self.assertEqual(response.status_code, 403)

    def test_privileged_user_can_access_privileged_area(self):
        self.client.login(username='privileged', password='TestPassword123')
        response = self.client.get(self.privileged_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Privileged Area')


class ProtectedViewsTestCase(BaseAuthTestCase):
    """Test cases for protected views and access control."""
    
    def setUp(self):
        """Set up test client and users."""
        self.client = Client()
        self.dashboard_url = reverse('ngabo:dashboard')
        self.profile_url = reverse('ngabo:profile')
        self.change_password_url = reverse('ngabo:change_password')
        self.account_settings_url = reverse('ngabo:account_settings')
        self.login_url = reverse('ngabo:login')
        
        self.user = User.objects.create_user(
            username='testuser',
            email='testuser@example.com',
            password='TestPassword123'
        )
        UserProfile.objects.create(user=self.user)
    
    def test_dashboard_requires_login(self):
        """Test that dashboard redirects to login for unauthenticated users."""
        response = self.client.get(self.dashboard_url)
        self.assertEqual(response.status_code, 302)
        self.assertIn(self.login_url, response.url)
    
    def test_profile_requires_login(self):
        """Test that profile page redirects to login for unauthenticated users."""
        response = self.client.get(self.profile_url)
        self.assertEqual(response.status_code, 302)
        self.assertIn(self.login_url, response.url)
    
    def test_change_password_requires_login(self):
        """Test that change password page redirects to login for unauthenticated users."""
        response = self.client.get(self.change_password_url)
        self.assertEqual(response.status_code, 302)
        self.assertIn(self.login_url, response.url)
    
    def test_authenticated_user_can_access_dashboard(self):
        """Test that authenticated users can access dashboard."""
        self.client.login(username='testuser', password='TestPassword123')
        response = self.client.get(self.dashboard_url)
        self.assertEqual(response.status_code, 200)
    
    def test_authenticated_user_can_access_profile(self):
        """Test that authenticated users can access profile page."""
        self.client.login(username='testuser', password='TestPassword123')
        response = self.client.get(self.profile_url)
        self.assertEqual(response.status_code, 200)

    def test_profile_rejects_external_user_identifiers(self):
        """Test that profile access ignores or rejects external user/profile identifiers."""
        other_user = User.objects.create_user(
            username='otheruser',
            email='otheruser@example.com',
            password='TestPassword123'
        )
        UserProfile.objects.create(user=other_user)

        self.client.login(username='testuser', password='TestPassword123')

        response = self.client.get(self.profile_url, {'user_id': other_user.id})
        self.assertEqual(response.status_code, 403)

        response = self.client.get(self.profile_url, {'profile_id': other_user.profile.id})
        self.assertEqual(response.status_code, 403)

        response = self.client.post(self.profile_url, {
            'bio': 'Attempted override',
            'user_id': other_user.id
        })
        self.assertEqual(response.status_code, 403)

    def test_account_settings_rejects_external_user_identifiers(self):
        """Test that account settings cannot be accessed with other user identifiers."""
        other_user = User.objects.create_user(
            username='otheruser2',
            email='otheruser2@example.com',
            password='TestPassword123'
        )
        UserProfile.objects.create(user=other_user)

        self.client.login(username='testuser', password='TestPassword123')

        response = self.client.get(self.account_settings_url, {'user_id': other_user.id})
        self.assertEqual(response.status_code, 403)


class PasswordChangeTestCase(BaseAuthTestCase):
    """Test cases for password change functionality."""
    
    def setUp(self):
        """Set up test client and users."""
        self.client = Client()
        self.change_password_url = reverse('ngabo:change_password')
        
        self.user = User.objects.create_user(
            username='testuser',
            email='testuser@example.com',
            password='OldPassword123'
        )
        UserProfile.objects.create(user=self.user)
    
    def test_password_change_success(self):
        """Test successful password change."""
        self.client.login(username='testuser', password='OldPassword123')
        
        data = {
            'old_password': 'OldPassword123',
            'new_password1': 'NewPassword123',
            'new_password2': 'NewPassword123'
        }
        response = self.client.post(self.change_password_url, data)
        
        self.assertEqual(response.status_code, 302)  # Redirect after success
        
        # Verify old password doesn't work anymore
        self.client.logout()
        login_success = self.client.login(username='testuser', password='OldPassword123')
        self.assertFalse(login_success)
        
        # Verify new password works
        login_success = self.client.login(username='testuser', password='NewPassword123')
        self.assertTrue(login_success)
    
    def test_password_change_wrong_old_password(self):
        """Test password change fails with wrong old password."""
        self.client.login(username='testuser', password='OldPassword123')
        
        data = {
            'old_password': 'WrongPassword',
            'new_password1': 'NewPassword123',
            'new_password2': 'NewPassword123'
        }
        response = self.client.post(self.change_password_url, data)
        
        self.assertEqual(response.status_code, 200)  # Stay on change password page
        
        # Verify old password still works
        self.client.logout()
        login_success = self.client.login(username='testuser', password='OldPassword123')
        self.assertTrue(login_success)


class UserProfileModelTestCase(BaseAuthTestCase):
    """Test cases for UserProfile model."""
    
    def setUp(self):
        """Set up test users."""
        self.user = User.objects.create_user(
            username='testuser',
            email='testuser@example.com',
            password='TestPassword123'
        )
    
    def test_user_profile_creation(self):
        """Test that UserProfile is created with User."""
        profile = UserProfile.objects.create(user=self.user)
        self.assertEqual(profile.user, self.user)
        self.assertEqual(str(profile), f"Profile of {self.user.username}")
    
    def test_user_profile_one_to_one_relationship(self):
        """Test that UserProfile has one-to-one relationship with User."""
        profile1 = UserProfile.objects.create(user=self.user)
        
        # Attempting to create another profile for same user should raise error
        with self.assertRaises(Exception):
            UserProfile.objects.create(user=self.user)
    
    def test_user_profile_fields(self):
        """Test UserProfile fields."""
        profile = UserProfile.objects.create(
            user=self.user,
            bio="Test bio",
            phone_number="123-456-7890"
        )
        self.assertEqual(profile.bio, "Test bio")
        self.assertEqual(profile.phone_number, "123-456-7890")


class LoginAttemptModelTestCase(BaseAuthTestCase):
    """Test cases for LoginAttempt model."""
    
    def test_login_attempt_recording(self):
        """Test that login attempts are recorded correctly."""
        attempt = LoginAttempt.objects.create(
            username='testuser',
            ip_address='127.0.0.1',
            success=True
        )
        self.assertEqual(attempt.username, 'testuser')
        self.assertEqual(attempt.ip_address, '127.0.0.1')
        self.assertTrue(attempt.success)
    
    def test_login_attempt_string_representation(self):
        """Test string representation of LoginAttempt."""
        attempt = LoginAttempt.objects.create(
            username='testuser',
            ip_address='127.0.0.1',
            success=True
        )
        self.assertIn('testuser', str(attempt))
        self.assertIn('Success', str(attempt))


class PasswordResetFlowTestCase(BaseAuthTestCase):
    """Test cases for the secure password reset workflow.

    Security properties tested:
    - User enumeration prevention (same response for known / unknown emails)
    - HMAC-based token validity and expiry
    - Password validation enforcement on reset
    - CSRF protection on all forms
    - One-time token usage (token invalidated after password change)
    """

    def setUp(self):
        self.client = Client()
        self.password_reset_url = reverse('ngabo:password_reset')
        self.password_reset_done_url = reverse('ngabo:password_reset_done')
        self.password_reset_complete_url = reverse('ngabo:password_reset_complete')
        self.login_url = reverse('ngabo:login')

        self.user = User.objects.create_user(
            username='resetuser',
            email='resetuser@example.com',
            password='OldPassword123'
        )
        UserProfile.objects.create(user=self.user)

    # ── Helper ─────────────────────────────────────────────────────────
    def _get_reset_url(self, user=None):
        """Generate a valid password-reset confirmation URL for *user*."""
        user = user or self.user
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        return reverse(
            'ngabo:password_reset_confirm',
            kwargs={'uidb64': uid, 'token': token},
        )

    # ── Page Load Tests ────────────────────────────────────────────────
    def test_password_reset_request_page_loads(self):
        """Test that the password reset request page loads successfully."""
        response = self.client.get(self.password_reset_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Reset Your Password')

    def test_password_reset_done_page_loads(self):
        """Test that the 'email sent' confirmation page loads."""
        response = self.client.get(self.password_reset_done_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Check Your Email')

    # ── Email Dispatch Tests ───────────────────────────────────────────
    def test_password_reset_sends_email_for_valid_user(self):
        """Test that submitting a valid email dispatches a reset email."""
        response = self.client.post(
            self.password_reset_url,
            {'email': 'resetuser@example.com'},
        )
        self.assertRedirects(
            response,
            self.password_reset_done_url,
            fetch_redirect_response=False,
        )
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn('resetuser@example.com', mail.outbox[0].to)
        # The email body should contain a reset link
        self.assertIn('/password-reset-confirm/', mail.outbox[0].body)

    def test_password_reset_no_email_for_unknown_address(self):
        """Test that submitting an unknown email does NOT send mail
        but still redirects to the 'done' page (prevents user enumeration)."""
        response = self.client.post(
            self.password_reset_url,
            {'email': 'nobody@example.com'},
        )
        # Must still redirect – identical UX for attacker
        self.assertRedirects(
            response,
            self.password_reset_done_url,
            fetch_redirect_response=False,
        )
        self.assertEqual(len(mail.outbox), 0)

    # ── Token Validation & Full Flow ───────────────────────────────────
    def test_valid_token_shows_new_password_form(self):
        """Test that a valid token link shows the set-new-password form."""
        url = self._get_reset_url()
        # Django's PasswordResetConfirmView uses an internal redirect
        # (stores token in session) since Django 3.0.
        response = self.client.get(url, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Set New Password')

    def test_full_password_reset_flow(self):
        """Test the complete happy-path password reset flow end-to-end."""
        # Step 1 – request the reset
        self.client.post(
            self.password_reset_url,
            {'email': 'resetuser@example.com'},
        )
        self.assertEqual(len(mail.outbox), 1)

        # Step 2 – follow the link from the email
        url = self._get_reset_url()
        response = self.client.get(url, follow=True)
        self.assertEqual(response.status_code, 200)

        # Step 3 – submit the new password via the redirected set-password URL
        # After GET, Django redirects to a URL with token replaced by
        # 'set-password'. We POST to the final URL in the redirect chain.
        final_url = response.redirect_chain[-1][0]
        response = self.client.post(final_url, {
            'new_password1': 'NewSecurePass99',
            'new_password2': 'NewSecurePass99',
        })
        self.assertRedirects(
            response,
            self.password_reset_complete_url,
            fetch_redirect_response=False,
        )

        # Step 4 – verify old password no longer works
        self.assertFalse(
            self.client.login(username='resetuser', password='OldPassword123')
        )
        # Step 5 – verify new password works
        self.assertTrue(
            self.client.login(username='resetuser', password='NewSecurePass99')
        )

    # ── Invalid / Expired Token ────────────────────────────────────────
    def test_invalid_token_shows_error(self):
        """Test that a tampered token shows the 'invalid link' message."""
        uid = urlsafe_base64_encode(force_bytes(self.user.pk))
        bad_url = reverse(
            'ngabo:password_reset_confirm',
            kwargs={'uidb64': uid, 'token': 'bad-token-value'},
        )
        response = self.client.get(bad_url, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Invalid or Expired Link')

    def test_invalid_uid_shows_error(self):
        """Test that a fabricated UID shows the 'invalid link' message."""
        token = default_token_generator.make_token(self.user)
        bad_url = reverse(
            'ngabo:password_reset_confirm',
            kwargs={'uidb64': 'AAAA', 'token': token},
        )
        response = self.client.get(bad_url, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Invalid or Expired Link')

    def test_token_invalidated_after_password_change(self):
        """Test that a token cannot be reused after the password has
        been changed (one-time use enforced by Django's HMAC scheme)."""
        url = self._get_reset_url()
        # Use the token to reset password
        response = self.client.get(url, follow=True)
        final_url = response.redirect_chain[-1][0]
        self.client.post(final_url, {
            'new_password1': 'NewSecurePass99',
            'new_password2': 'NewSecurePass99',
        })

        # Try the same token again – should fail
        response = self.client.get(url, follow=True)
        self.assertContains(response, 'Invalid or Expired Link')

    # ── Password Validation on Reset ───────────────────────────────────
    def test_password_reset_enforces_validation_rules(self):
        """Test that Django's password validators are enforced during reset."""
        url = self._get_reset_url()
        response = self.client.get(url, follow=True)
        final_url = response.redirect_chain[-1][0]

        # Submit a too-short / too-common password
        response = self.client.post(final_url, {
            'new_password1': '123',
            'new_password2': '123',
        })
        # Should stay on the form (200), not redirect
        self.assertEqual(response.status_code, 200)
        # Old password should still work
        self.assertTrue(
            self.client.login(username='resetuser', password='OldPassword123')
        )

    def test_password_reset_mismatched_passwords(self):
        """Test that mismatched passwords are rejected during reset."""
        url = self._get_reset_url()
        response = self.client.get(url, follow=True)
        final_url = response.redirect_chain[-1][0]

        response = self.client.post(final_url, {
            'new_password1': 'NewSecurePass99',
            'new_password2': 'DifferentPass99',
        })
        self.assertEqual(response.status_code, 200)
        # Password unchanged
        self.assertTrue(
            self.client.login(username='resetuser', password='OldPassword123')
        )

    # ── CSRF Protection ────────────────────────────────────────────────
    def test_password_reset_request_requires_csrf(self):
        """Test that the reset request form is protected by CSRF."""
        csrf_client = Client(enforce_csrf_checks=True)
        response = csrf_client.post(
            self.password_reset_url,
            {'email': 'resetuser@example.com'},
        )
        self.assertEqual(response.status_code, 403)

    # ── Login Page Link ────────────────────────────────────────────────
    def test_login_page_has_password_reset_link(self):
        """Test that the login page contains a link to the reset flow."""
        response = self.client.get(self.login_url)
        self.assertContains(response, 'Forgot your password?')
        self.assertContains(response, self.password_reset_url)

    # ── Complete Page ──────────────────────────────────────────────────
    def test_password_reset_complete_page_loads(self):
        """Test that the 'reset complete' page loads and links to login."""
        response = self.client.get(self.password_reset_complete_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Password Reset Successful')
        self.assertContains(response, 'Sign In')


class CsrfProtectionTestCase(BaseAuthTestCase):
    """Test cases to ensure CSRF protection is active on state-changing views."""

    def setUp(self):
        """Set up test client with CSRF enforcement enabled."""
        self.client = Client(enforce_csrf_checks=True)
        self.user = User.objects.create_user(
            username='csrfuser',
            email='csrf@example.com',
            password='TestPassword123'
        )
        self.logout_url = reverse('ngabo:logout')
        self.profile_url = reverse('ngabo:profile')

    def test_logout_requires_csrf_token(self):
        """Verify that logout POST request fails without a CSRF token."""
        self.client.login(username='csrfuser', password='TestPassword123')
        response = self.client.post(self.logout_url)
        self.assertEqual(response.status_code, 403)  # Forbidden due to missing CSRF

    def test_profile_update_requires_csrf_token(self):
        """Verify that profile update POST request fails without a CSRF token."""
        self.client.login(username='csrfuser', password='TestPassword123')
        response = self.client.post(self.profile_url, {'bio': 'Attempting CSRF update'})
        self.assertEqual(response.status_code, 403)


class OpenRedirectTestCase(BaseAuthTestCase):
    """Test cases for preventing open redirect vulnerabilities in auth flows."""

    def setUp(self):
        super().setUp()
        self.client = Client()
        self.login_url = reverse('ngabo:login')
        self.logout_url = reverse('ngabo:logout')
        self.dashboard_url = reverse('ngabo:dashboard')
        self.user = User.objects.create_user(username='redirectuser', password='TestPassword123')

    def test_login_safe_redirect(self):
        """Verify login redirects to safe internal URLs."""
        safe_url = '/auth/profile/'
        response = self.client.post(self.login_url, {
            'username': 'redirectuser',
            'password': 'TestPassword123',
            'next': safe_url
        })
        self.assertRedirects(response, safe_url, fetch_redirect_response=False)

    def test_login_unsafe_redirect_fallback(self):
        """Verify login ignores malicious external URLs."""
        unsafe_url = 'https://malicious-site.com'
        response = self.client.post(self.login_url, {
            'username': 'redirectuser',
            'password': 'TestPassword123',
            'next': unsafe_url
        })
        self.assertRedirects(response, self.dashboard_url)

    def test_logout_safe_redirect(self):
        """Verify logout redirects to safe internal URLs."""
        self.client.login(username='redirectuser', password='TestPassword123')
        safe_url = '/auth/login/'
        response = self.client.post(self.logout_url + '?next=' + safe_url)
        self.assertRedirects(response, safe_url, fetch_redirect_response=False)


class AuditLoggingTestCase(BaseAuthTestCase):
    """Test cases to ensure security-relevant events are logged correctly."""

    def setUp(self):
        super().setUp()
        self.client = Client()
        self.login_url = reverse('ngabo:login')
        self.register_url = reverse('ngabo:register')
        self.logout_url = reverse('ngabo:logout')
        self.change_password_url = reverse('ngabo:change_password')
        self.privileged_url = reverse('ngabo:privileged_area')
        self.user = User.objects.create_user(username='audituser', password='TestPassword123')

    def test_registration_audit_log(self):
        """Verify user registration generates an audit log entry."""
        data = {
            'username': 'newuser',
            'email': 'new@example.com',
            'password1': 'NewPass123!',
            'password2': 'NewPass123!'
        }
        with self.assertLogs('ngabo.audit', level='INFO') as cm:
            self.client.post(self.register_url, data)
            self.assertTrue(any("Audit: Action=Registration, User=newuser" in output for output in cm.output))

    def test_login_success_audit_log(self):
        """Verify successful login generates an audit log entry."""
        with self.assertLogs('ngabo.audit', level='INFO') as cm:
            self.client.post(self.login_url, {'username': 'audituser', 'password': 'TestPassword123'})
            self.assertTrue(any("Audit: Action=Login, Status=Success, User=audituser" in output for output in cm.output))

    def test_login_failure_audit_log(self):
        """Verify failed login generates a warning audit log entry."""
        with self.assertLogs('ngabo.audit', level='WARNING') as cm:
            self.client.post(self.login_url, {'username': 'audituser', 'password': 'WrongPassword'})
            self.assertTrue(any("Audit: Action=Login, Status=Failure, User=audituser" in output for output in cm.output))

    def test_privileged_access_audit_logs(self):
        """Verify privileged access attempts are logged."""
        # Case: Denied
        self.client.login(username='audituser', password='TestPassword123')
        with self.assertLogs('ngabo.audit', level='WARNING') as cm:
            self.client.get(self.privileged_url)
            self.assertTrue(any("Audit: Action=PrivilegedAccess, Status=Denied" in output for output in cm.output))

    def test_password_change_audit_log(self):
        """Verify password change generates an audit log entry."""
        self.client.login(username='audituser', password='TestPassword123')
        data = {
            'old_password': 'TestPassword123',
            'new_password1': 'NewSecurePass99!',
            'new_password2': 'NewSecurePass99!'
        }
        with self.assertLogs('ngabo.audit', level='INFO') as cm:
            self.client.post(self.change_password_url, data)
            self.assertTrue(any("Audit: Action=PasswordChange, User=audituser" in output for output in cm.output))
