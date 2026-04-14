from django.test import TestCase, Client
from django.contrib.auth.models import Group, User
from django.template import Template
from django.test.utils import _TestState
from django.urls import reverse
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

