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

    # Bill List
    path('bills/', views.bill_list, name='bill_list'),
    path('bills/<int:bill_id>/', views.bill_detail, name='bill_detail'),
    path('bills/generate/', views.generate_bills, name='generate_bills'),
    path('bills/overdue/', views.overdue_bills, name='overdue_bills'),
    path('bills/reports/', views.bill_reports, name='bill_reports'),
    path('bills/export/', views.export_bills_excel, name='export_bills_excel'),
    path('bills/overdue/export/', views.export_overdue_bills_excel, name='export_overdue_bills_excel'),

    # Payment Management
    path('payments/', views.payment_list, name='payment_list'),
    path('payments/<int:payment_id>/', views.payment_detail, name='payment_detail'),
    path('payments/<int:payment_id>/update/', views.payment_update, name='payment_update'),
    path('payments/<int:payment_id>/delete/', views.payment_delete, name='payment_delete'),
    path('payments/<int:payment_id>/reverse/', views.payment_reverse, name='payment_reverse'),
    path('payment-methods/', views.payment_method_list, name='payment_method_list'),
    path('payment-methods/<int:pk>/', views.payment_method_detail, name='payment_method_detail'),
    path('payment-methods/<int:pk>/update/', views.payment_method_update, name='payment_method_update'),
    path('payment-methods/<int:pk>/delete/', views.payment_method_delete, name='payment_method_delete'),
    path('payment-methods/<int:pk>/toggle-active/', views.payment_method_toggle_active, name='payment_method_toggle_active'),
    path('payment-methods/create/', views.payment_method_create, name='payment_method_create'),
    path('reconciliation/', views.reconciliation_list, name='reconciliation_list'),
    path('reconciliations/create/', views.reconciliation_create, name='reconciliation_create'),
    path('reversals/', views.reversal_list, name='reversal_list'),

    # Vehicle Management
    path('fleet/vehicles/', views.vehicle_list, name='vehicle_list'),
    path('fleet/vehicles/create/', views.vehicle_create, name='vehicle_create'),
    path('fleet/vehicles/<str:fleet_number>/', views.vehicle_detail, name='vehicle_detail'),
    path('fleet/vehicles/<str:fleet_number>/update/', views.vehicle_update, name='vehicle_update'),
    path('fleet/vehicles/<str:fleet_number>/delete/', views.vehicle_delete, name='vehicle_delete'),
    path('fleet/vehicles/export/excel/', views.vehicle_export_excel, name='vehicle_export_excel'),
    
    # Fuel Management
    path('fleet/fuel/', views.fuel_transaction_list, name='fuel_transaction_list'),
    path('fleet/fuel/create/', views.fuel_transaction_create, name='fuel_transaction_create'),
    path('fleet/fuel/export/excel/', views.fuel_export_excel, name='fuel_export_excel'),
    
    # Maintenance Management
    path('fleet/maintenance/', views.maintenance_list, name='maintenance_list'),
    path('fleet/maintenance/create/', views.maintenance_create, name='maintenance_create'),
    path('fleet/maintenance/<str:maintenance_number>/update/', views.maintenance_update, name='maintenance_update'),
    path('fleet/maintenance/<str:maintenance_number>/delete/', views.maintenance_delete, name='maintenance_delete'),
    
    # Trips & Work Tickets
    path('fleet/trips/', views.trip_list, name='trip_list'),
    path('fleet/trips/create/', views.trip_create, name='trip_create'),
    path('fleet/trips/<str:trip_number>/update/', views.trip_update, name='trip_update'),
    path('fleet/trips/<str:trip_number>/delete/', views.trip_delete, name='trip_delete'),

    # All Facilities
    path('facility/', views.facility_list, name='facility_list'),
    path('facility/create/', views.facility_create, name='facility_create'),
    path('facility/<str:code>/', views.facility_detail, name='facility_detail'),
    path('facility/<str:code>/update/', views.facility_update, name='facility_update'),
    path('facility/<str:code>/delete/', views.facility_delete, name='facility_delete'),
    path('facility/export/excel/', views.facility_export_excel, name='facility_export_excel'),
    path('facility-markets/', views.market_list, name='market_list'),
    path('facility-stalls/', views.stall_list, name='stall_list'),
    path('facility-housing/', views.housing_list, name='housing_list'),
    path('facility-bookings/', views.booking_list, name='booking_list'),
    path('facility-bookings/<str:booking_number>/', views.booking_detail, name='booking_detail'),
    path('facility-tenancies/', views.tenancy_list, name='tenancy_list'),
    path('facility-tenancies/<str:tenancy_number>/', views.tenancy_detail, name='tenancy_detail'),
    path('facility-tenancies/export/excel/', views.tenancy_export_excel, name='tenancy_export_excel'),

    # ================= USERS =================
    path('users/', views.user_list, name='user_list'),
    path('users/create/', views.user_create, name='user_create'),
    path('users/<int:pk>/', views.user_detail, name='user_detail'),
    path('users/<int:pk>/edit/', views.user_update, name='user_update'),
    path('users/<int:pk>/delete/', views.user_delete, name='user_delete'),
    path('users/export/excel/', views.user_export_excel, name='user_export_excel'),

    # ================= ROLES =================
    path('roles/', views.role_list, name='role_list'),
    path('roles/create/', views.role_create, name='role_create'),
    path('roles/<int:pk>/', views.role_detail, name='role_detail'),
    path('roles/<int:pk>/edit/', views.role_update, name='role_update'),
    path('roles/<int:pk>/delete/', views.role_delete, name='role_delete'),
    path('permissions/', views.permission_list, name='permission_list'),
    path('notifications/', views.notification_list, name='notification_list'),
    path('notifications/<int:pk>/mark-read/', views.notification_mark_read, name='notification_mark_read'),
    path('notifications/mark-all-read/', views.notification_mark_all_read, name='notification_mark_all_read'),
    path('audit/', views.audit_trail_list, name='audit_trail_list'),
    path('audit/export/', views.audit_trail_export, name='audit_trail_export'),
    path('settings/', views.system_settings, name='system_settings'),
    path('settings/update/', views.system_settings_update, name='system_settings_update'),

]