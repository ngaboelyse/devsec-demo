# devsec-demo

## Django-based User Authentication Service (UAS)

This demo project includes a complete Django authentication app named `ngabo`.

### Features
- User registration with email validation and secure password handling
- User login with optional "remember me" session support
- CSRF-protected logout via POST
- Protected dashboard and profile pages requiring authentication
- Password change workflow using Django's secure password validators
- Profile editing with optional profile picture upload
- Admin integration for `UserProfile` and `LoginAttempt`

### App structure
- `ngabo/` — the dedicated authentication app
- `ngabo/models.py` — `UserProfile` and `LoginAttempt` models
- `ngabo/forms.py` — registration, login, password change, and profile forms
- `ngabo/views.py` — views for registration, login, logout, dashboard, profile, and password change
- `ngabo/urls.py` — app-specific URL routes
- `ngabo/templates/ngabo/` — user-facing templates for authentication pages
- `ngabo/tests.py` — tests covering registration, login, password change, and protected page access

### Setup
1. Create a virtual environment and activate it.
2. Install dependencies:
   ```bash
   python -m pip install -r requirements.txt
   ```
3. Apply migrations:
   ```bash
   python manage.py migrate
   ```
4. Run the development server:
   ```bash
   python manage.py runserver
   ```

### Usage
- Register: `/auth/register/`
- Login: `/auth/login/`
- Logout: `/auth/logout/`
- Dashboard: `/auth/dashboard/`
- Profile: `/auth/profile/`
- Change password: `/auth/change-password/`
- Account settings: `/auth/account-settings/`

### Testing
Run the app tests with:
```bash
python manage.py test ngabo
```

### Notes
- The app reuses Django's built-in authentication system and secure password validators.
- `ngabo` is registered in `devsec_demo/settings.py` and included under `devsec_demo/urls.py`.
- `MEDIA_URL` and `MEDIA_ROOT` are configured for image uploads.
- Profile and settings routes now resolve resources using `request.user` only and explicitly reject external `user_id`, `profile_id`, or `username` parameters to prevent IDOR risks.
