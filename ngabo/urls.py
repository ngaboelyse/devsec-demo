from django.urls import path
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
]
