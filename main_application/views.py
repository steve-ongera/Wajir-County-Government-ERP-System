"""
Wajir County Government ERP System - Views
Role-based authentication and dashboard views
"""

from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db.models import Sum, Count, Q
from django.utils import timezone
from datetime import datetime, timedelta
from decimal import Decimal
from .models import *


# ============================================================================
# AUTHENTICATION VIEWS
# ============================================================================

def login_view(request):
    """Login view for all user types"""
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            login(request, user)
            messages.success(request, f'Welcome back, {user.get_full_name()}!')
            return redirect('dashboard')
        else:
            messages.error(request, 'Invalid username or password')
    
    return render(request, 'auth/login.html')


def logout_view(request):
    """Logout view"""
    logout(request)
    messages.success(request, 'You have been logged out successfully')
    return redirect('login')


@login_required(login_url='login')
def dashboard(request):
    """Route users to appropriate dashboard based on their role"""
    user = request.user
    
    # Get user's primary role
    user_role = UserRole.objects.filter(user=user, is_active=True).first()
    
    if user.is_superuser or (user_role and user_role.role.name == 'System Administrator'):
        return redirect('admin_dashboard')
    elif user_role:
        role_name = user_role.role.name
        
        if role_name == 'Revenue Officer':
            return redirect('revenue_dashboard')
        elif role_name == 'Health Worker':
            return redirect('health_dashboard')
        elif role_name == 'Fleet Manager':
            return redirect('fleet_dashboard')
        elif role_name == 'HR Manager':
            return redirect('hr_dashboard')
        elif role_name == 'Finance Officer':
            return redirect('finance_dashboard')
        elif role_name == 'Lands Officer':
            return redirect('lands_dashboard')
    
    # Default dashboard if no specific role
    return redirect('general_dashboard')


# ============================================================================
# SYSTEM ADMINISTRATOR DASHBOARD
# ============================================================================

@login_required(login_url='login')
def admin_dashboard(request):
    """System Administrator Dashboard"""
    # System-wide statistics
    context = {
        'total_users': User.objects.filter(is_active=True).count(),
        'total_citizens': Citizen.objects.filter(is_active=True).count(),
        'total_departments': Department.objects.filter(is_active=True).count(),
        'total_revenue_streams': RevenueStream.objects.filter(is_active=True).count(),
        
        # Recent activities
        'recent_users': User.objects.filter(is_active=True).order_by('-date_joined')[:5],
        'recent_audit_logs': AuditLog.objects.order_by('-timestamp')[:10],
        
        # System health
        'active_sessions': User.objects.filter(last_login__gte=timezone.now() - timedelta(hours=24)).count(),
        'pending_notifications': Notification.objects.filter(status='pending').count(),
        
        # Module statistics
        'total_bills': Bill.objects.count(),
        'total_payments': Payment.objects.count(),
        'total_assets': Asset.objects.count(),
        'total_vehicles': FleetVehicle.objects.count(),
        'total_patients': Patient.objects.count(),
        'total_properties': Property.objects.count(),
    }
    
    return render(request, 'dashboards/admin_dashboard.html', context)


# ============================================================================
# REVENUE OFFICER DASHBOARD
# ============================================================================

@login_required(login_url='login')
def revenue_dashboard(request):
    """Revenue Officer Dashboard"""
    today = timezone.now().date()
    
    # Revenue statistics
    total_bills = Bill.objects.filter(status__in=['issued', 'partially_paid', 'overdue'])
    total_bills_amount = total_bills.aggregate(Sum('total_amount'))['total_amount__sum'] or 0
    total_collected = Payment.objects.filter(status='completed').aggregate(Sum('amount'))['amount__sum'] or 0
    
    # Today's collections
    today_collections = Payment.objects.filter(
        payment_date__date=today,
        status='completed'
    ).aggregate(Sum('amount'))['amount__sum'] or 0
    
    # This month's collections
    month_start = today.replace(day=1)
    month_collections = Payment.objects.filter(
        payment_date__date__gte=month_start,
        status='completed'
    ).aggregate(Sum('amount'))['amount__sum'] or 0
    
    # Revenue by stream
    revenue_by_stream = Payment.objects.filter(
        status='completed',
        payment_date__date__gte=month_start
    ).values('revenue_stream__name').annotate(
        total=Sum('amount')
    ).order_by('-total')[:5]
    
    context = {
        'total_bills': total_bills.count(),
        'total_bills_amount': total_bills_amount,
        'total_collected': total_collected,
        'collection_rate': (total_collected / total_bills_amount * 100) if total_bills_amount > 0 else 0,
        
        'today_collections': today_collections,
        'month_collections': month_collections,
        
        'pending_bills': Bill.objects.filter(status='issued').count(),
        'overdue_bills': Bill.objects.filter(status='overdue').count(),
        
        'revenue_by_stream': revenue_by_stream,
        'recent_payments': Payment.objects.filter(status='completed').order_by('-payment_date')[:10],
        'recent_bills': Bill.objects.order_by('-created_at')[:10],
        
        # Sub-county breakdown
        'sub_county': request.user.sub_county,
    }
    
    return render(request, 'dashboards/revenue_dashboard.html', context)


# ============================================================================
# HEALTH WORKER DASHBOARD
# ============================================================================

@login_required(login_url='login')
def health_dashboard(request):
    """Health Worker Dashboard"""
    today = timezone.now().date()
    
    # Get user's facility if assigned
    user_facility = None
    if hasattr(request.user, 'department'):
        # Assuming health workers are assigned to facilities
        user_facility = HealthFacility.objects.filter(is_active=True).first()
    
    # Patient statistics
    total_patients = Patient.objects.filter(is_active=True).count()
    
    # Today's visits
    today_visits = Visit.objects.filter(visit_date__date=today)
    
    # Current admissions
    current_admissions = Admission.objects.filter(status='admitted')
    
    # Pending lab tests
    pending_lab_tests = LabTest.objects.filter(status='pending')
    
    # Pending prescriptions
    pending_prescriptions = Prescription.objects.filter(status='pending')
    
    context = {
        'total_patients': total_patients,
        'today_visits': today_visits.count(),
        'current_admissions': current_admissions.count(),
        'pending_lab_tests': pending_lab_tests.count(),
        'pending_prescriptions': pending_prescriptions.count(),
        
        'user_facility': user_facility,
        'recent_visits': Visit.objects.order_by('-visit_date')[:10],
        'recent_admissions': Admission.objects.order_by('-admission_date')[:5],
        'pending_tests': pending_lab_tests[:10],
        
        # Facility statistics
        'facilities': HealthFacility.objects.filter(is_active=True),
        'total_beds': HealthFacility.objects.aggregate(Sum('bed_capacity'))['bed_capacity__sum'] or 0,
    }
    
    return render(request, 'dashboards/health_dashboard.html', context)


# ============================================================================
# FLEET MANAGER DASHBOARD
# ============================================================================

@login_required(login_url='login')
def fleet_dashboard(request):
    """Fleet Manager Dashboard"""
    today = timezone.now().date()
    
    # Fleet statistics
    total_vehicles = FleetVehicle.objects.all()
    active_vehicles = total_vehicles.filter(status='active')
    maintenance_vehicles = total_vehicles.filter(status='maintenance')
    
    # Fuel consumption today
    today_fuel = FuelTransaction.objects.filter(
        transaction_date__date=today
    ).aggregate(
        total_liters=Sum('quantity_liters'),
        total_cost=Sum('total_amount')
    )
    
    # This month's fuel
    month_start = today.replace(day=1)
    month_fuel = FuelTransaction.objects.filter(
        transaction_date__date__gte=month_start
    ).aggregate(
        total_liters=Sum('quantity_liters'),
        total_cost=Sum('total_amount')
    )
    
    # Upcoming maintenance
    upcoming_maintenance = VehicleMaintenance.objects.filter(
        status='scheduled',
        scheduled_date__gte=today
    ).order_by('scheduled_date')[:5]
    
    # Active trips
    active_trips = VehicleTrip.objects.filter(status='in_progress')
    
    context = {
        'total_vehicles': total_vehicles.count(),
        'active_vehicles': active_vehicles.count(),
        'maintenance_vehicles': maintenance_vehicles.count(),
        'inactive_vehicles': total_vehicles.filter(status='inactive').count(),
        
        'today_fuel_liters': today_fuel['total_liters'] or 0,
        'today_fuel_cost': today_fuel['total_cost'] or 0,
        'month_fuel_liters': month_fuel['total_liters'] or 0,
        'month_fuel_cost': month_fuel['total_cost'] or 0,
        
        'upcoming_maintenance': upcoming_maintenance,
        'active_trips': active_trips,
        
        'recent_fuel_transactions': FuelTransaction.objects.order_by('-transaction_date')[:10],
        'vehicles': active_vehicles[:10],
        'vehicle_types': total_vehicles.values('vehicle_type').annotate(count=Count('id')),
    }
    
    return render(request, 'dashboards/fleet_dashboard.html', context)


# ============================================================================
# HR MANAGER DASHBOARD
# ============================================================================

@login_required(login_url='login')
def hr_dashboard(request):
    """HR Manager Dashboard"""
    today = timezone.now().date()
    
    # Staff statistics
    total_staff = User.objects.filter(is_active=True, is_active_staff=True)
    
    # Leave statistics
    pending_leaves = LeaveApplication.objects.filter(status='pending')
    approved_leaves = LeaveApplication.objects.filter(
        status='approved',
        start_date__lte=today,
        end_date__gte=today
    )
    
    # Pending transfers
    pending_transfers = Transfer.objects.filter(status='pending')
    
    # Attendance today
    today_attendance = Attendance.objects.filter(attendance_date=today)
    checked_in = today_attendance.filter(attendance_type='check_in').values('employee').distinct().count()
    
    # Upcoming trainings
    upcoming_trainings = TrainingProgram.objects.filter(
        start_date__gte=today,
        is_active=True
    ).order_by('start_date')[:5]
    
    # Open disciplinary cases
    open_cases = DisciplinaryCase.objects.exclude(status='closed')
    
    context = {
        'total_staff': total_staff.count(),
        'pending_leaves': pending_leaves.count(),
        'approved_leaves': approved_leaves.count(),
        'pending_transfers': pending_transfers.count(),
        
        'checked_in_today': checked_in,
        'attendance_rate': (checked_in / total_staff.count() * 100) if total_staff.count() > 0 else 0,
        
        'upcoming_trainings': upcoming_trainings,
        'open_cases': open_cases.count(),
        
        'recent_leaves': LeaveApplication.objects.order_by('-created_at')[:10],
        'recent_transfers': Transfer.objects.order_by('-created_at')[:5],
        'recent_attendance': today_attendance.order_by('-attendance_time')[:10],
        
        # Department breakdown
        'staff_by_department': total_staff.values('department__name').annotate(count=Count('id')).order_by('-count')[:5],
    }
    
    return render(request, 'dashboards/hr_dashboard.html', context)


# ============================================================================
# FINANCE OFFICER DASHBOARD
# ============================================================================

@login_required(login_url='login')
def finance_dashboard(request):
    """Finance Officer Dashboard"""
    today = timezone.now().date()
    month_start = today.replace(day=1)
    
    # Financial statistics
    total_revenue = Payment.objects.filter(
        status='completed',
        payment_date__date__gte=month_start
    ).aggregate(Sum('amount'))['amount__sum'] or 0
    
    # Pending payments
    pending_payments = Payment.objects.filter(status='pending')
    
    # Bills statistics
    total_bills_amount = Bill.objects.filter(
        bill_date__gte=month_start
    ).aggregate(Sum('total_amount'))['total_amount__sum'] or 0
    
    outstanding_amount = Bill.objects.filter(
        status__in=['issued', 'partially_paid', 'overdue']
    ).aggregate(Sum('balance'))['balance__sum'] or 0
    
    # Revenue by stream
    revenue_by_stream = Payment.objects.filter(
        status='completed',
        payment_date__date__gte=month_start
    ).values('revenue_stream__name').annotate(
        total=Sum('amount')
    ).order_by('-total')[:10]
    
    # Budget vs actual
    budgets = RevenueBudget.objects.filter(
        period_start__lte=today,
        period_end__gte=today
    )
    
    # Bank reconciliation status
    pending_reconciliation = BankReconciliation.objects.filter(is_reconciled=False).count()
    
    context = {
        'total_revenue': total_revenue,
        'total_bills_amount': total_bills_amount,
        'outstanding_amount': outstanding_amount,
        'collection_rate': (total_revenue / total_bills_amount * 100) if total_bills_amount > 0 else 0,
        
        'pending_payments': pending_payments.count(),
        'pending_reconciliation': pending_reconciliation,
        
        'revenue_by_stream': revenue_by_stream,
        'budgets': budgets,
        
        'recent_payments': Payment.objects.filter(status='completed').order_by('-payment_date')[:15],
        'recent_reversals': PaymentReversal.objects.order_by('-created_at')[:5],
        
        # Payment methods breakdown
        'payment_by_method': Payment.objects.filter(
            status='completed',
            payment_date__date__gte=month_start
        ).values('payment_method__name').annotate(
            total=Sum('amount'),
            count=Count('id')
        ).order_by('-total'),
    }
    
    return render(request, 'dashboards/finance_dashboard.html', context)


# ============================================================================
# LANDS OFFICER DASHBOARD
# ============================================================================

@login_required(login_url='login')
def lands_dashboard(request):
    """Lands Officer Dashboard"""
    today = timezone.now().date()
    
    # Property statistics
    total_properties = Property.objects.filter(status='active')
    
    # Land rates collection
    land_rate_stream = RevenueStream.objects.filter(code='LND-RT').first()
    if land_rate_stream:
        land_rates_collected = Payment.objects.filter(
            revenue_stream=land_rate_stream,
            status='completed'
        ).aggregate(Sum('amount'))['amount__sum'] or 0
    else:
        land_rates_collected = 0
    
    # Development applications
    pending_applications = DevelopmentApplication.objects.filter(status='submitted')
    under_review = DevelopmentApplication.objects.filter(status='under_review')
    
    # Recent property transactions
    recent_transfers = PropertyOwnershipHistory.objects.order_by('-transfer_date')[:10]
    
    # Active caveats
    active_caveats = PropertyCaveat.objects.filter(is_active=True)
    
    # Property valuations
    recent_valuations = PropertyValuation.objects.filter(is_current=True).order_by('-valuation_date')[:5]
    
    context = {
        'total_properties': total_properties.count(),
        'land_rates_collected': land_rates_collected,
        
        'pending_applications': pending_applications.count(),
        'under_review': under_review.count(),
        'active_caveats': active_caveats.count(),
        
        'recent_transfers': recent_transfers,
        'recent_valuations': recent_valuations,
        'recent_applications': DevelopmentApplication.objects.order_by('-application_date')[:10],
        
        # Property type breakdown
        'property_by_type': total_properties.values('property_type__name').annotate(count=Count('id')).order_by('-count'),
        'property_by_subcounty': total_properties.values('sub_county__name').annotate(count=Count('id')).order_by('-count'),
        
        # Subdivisions and amalgamations
        'recent_subdivisions': PropertySubdivision.objects.order_by('-subdivision_date')[:5],
        'recent_amalgamations': PropertyAmalgamation.objects.order_by('-amalgamation_date')[:5],
    }
    
    return render(request, 'dashboards/lands_dashboard.html', context)


# ============================================================================
# GENERAL DASHBOARD (FOR USERS WITHOUT SPECIFIC ROLES)
# ============================================================================

@login_required(login_url='login')
def general_dashboard(request):
    """General Dashboard for users without specific roles"""
    context = {
        'user': request.user,
        'department': request.user.department,
        'sub_county': request.user.sub_county,
        'recent_notifications': Notification.objects.filter(
            recipient=request.user
        ).order_by('-created_at')[:10],
    }
    
    return render(request, 'dashboards/general_dashboard.html', context)