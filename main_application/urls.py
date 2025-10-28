"""
Wajir County Government ERP System - URL Configuration
"""

from django.urls import path
from . import views

urlpatterns = [
    # Authentication
    path('', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('resend-2fa/', views.resend_tfa_code, name='resend_tfa_code'),
    
    # Dashboard Router
    path('dashboard/', views.dashboard, name='dashboard'),
    
    # Role-specific Dashboards
    path('dashboard/admin/', views.admin_dashboard, name='admin_dashboard'),
    path('dashboard/revenue/', views.revenue_dashboard, name='revenue_dashboard'),
    path('dashboard/health/', views.health_dashboard, name='health_dashboard'),
    path('dashboard/fleet/', views.fleet_dashboard, name='fleet_dashboard'),
    path('dashboard/hr/', views.hr_dashboard, name='hr_dashboard'),
    path('dashboard/finance/', views.finance_dashboard, name='finance_dashboard'),
    path('dashboard/lands/', views.lands_dashboard, name='lands_dashboard'),
    path('dashboard/general/', views.general_dashboard, name='general_dashboard'),
]