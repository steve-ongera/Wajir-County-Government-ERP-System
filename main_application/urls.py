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

    # Citizen Management
    path('citizens/', views.citizen_list, name='citizen_list'),
    path('citizens/create/', views.citizen_create, name='citizen_create'),
    path('citizens/<str:unique_identifier>/', views.citizen_detail, name='citizen_detail'),
    path('citizens/<str:unique_identifier>/update/', views.citizen_update, name='citizen_update'),
    path('citizens/<str:unique_identifier>/delete/', views.citizen_delete, name='citizen_delete'),
    path('citizens/export/excel/', views.citizen_export_excel, name='citizen_export_excel'),
    path('api/wards-by-subcounty/', views.get_wards_by_subcounty, name='get_wards_by_subcounty'),

    # Analytics Dashboard
    path('analytics/', views.analytics_dashboard, name='analytics_dashboard'),
    path('analytics/export/', views.export_analytics_data, name='export_analytics'),
    path('api/wards/', views.get_wards_api, name='api_wards'),

    # REVENUE STREAMS

    path('streams/', views.revenue_stream_list, name='stream_list'),
    path('streams/<int:stream_id>/', views.revenue_stream_detail, name='revenue_stream_detail'),
    path('streams/export/', views.revenue_stream_export, name='revenue_stream_export'),
    path('charge-rates/', views.charge_rate_list, name='charge_rate_list'),
    path('charge-rates/export/', views.charge_rate_export, name='charge_rate_export'),
    path('budgets/', views.revenue_budget_list, name='budget_list'),
    path('budgets/export/', views.revenue_budget_export, name='budget_export'),
    path('collections/report/', views.collection_report, name='collection_report'),
    path('collections/report/export/', views.collection_report_export, name='collection_report_export'),
]