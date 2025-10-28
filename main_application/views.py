"""
Wajir County Government ERP System - Enhanced Authentication Views
Includes 2FA, account locking, login attempt tracking
"""

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse
from django.db.models import Sum, Count, Q
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from datetime import datetime, timedelta
from decimal import Decimal
import logging
import random
import string

from .models import *

logger = logging.getLogger(__name__)


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def get_client_ip(request):
    """Get client IP address"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def get_session_key(request):
    """Get or create session key"""
    if not hasattr(request.session, 'session_key') or not request.session.session_key:
        request.session.create()
    return request.session.session_key or 'no-session'


def send_security_email(user, subject, message):
    """Send security notification email"""
    try:
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            fail_silently=False,
        )
        return True
    except Exception as e:
        logger.error(f"Failed to send security email to {user.email}: {str(e)}")
        return False


def create_security_notification(user, notification_type, ip_address, message):
    """Create a security notification record"""
    notification = SecurityNotification.objects.create(
        user=user,
        notification_type=notification_type,
        ip_address=ip_address,
        message=message
    )
    
    # Subject mapping
    subject_map = {
        'failed_login': 'Security Alert: Failed Login Attempt',
        'account_locked': 'Security Alert: Account Locked',
        'tfa_code': 'Your 2FA Verification Code',
        'successful_login': 'Security: Successful Login',
        'account_unlocked': 'Security: Account Unlocked'
    }
    
    subject = subject_map.get(notification_type, 'Security Notification')
    email_sent = send_security_email(user, subject, message)
    
    if email_sent:
        notification.email_sent = True
        notification.email_sent_at = timezone.now()
        notification.save()


def check_account_lock(username, ip_address=None):
    """Check if account is locked and return lock status"""
    try:
        user = User.objects.get(username=username)
        account_lock, created = AccountLock.objects.get_or_create(
            user=user,
            defaults={
                'failed_attempts': 0,
                'is_locked': False,
                'last_attempt_ip': ip_address or '127.0.0.1'
            }
        )
        
        if account_lock.is_account_locked():
            return True, account_lock, user
        return False, account_lock, user
    except User.DoesNotExist:
        return False, None, None


def handle_failed_login(username, ip_address, user_agent):
    """Handle failed login attempt"""
    # Log the attempt
    LoginAttempt.objects.create(
        username=username,
        ip_address=ip_address,
        success=False,
        user_agent=user_agent
    )
    
    try:
        user = User.objects.get(username=username)
        account_lock, created = AccountLock.objects.get_or_create(
            user=user,
            defaults={'failed_attempts': 0, 'is_locked': False, 'last_attempt_ip': ip_address}
        )
        
        account_lock.failed_attempts += 1
        account_lock.last_attempt_ip = ip_address
        
        if account_lock.failed_attempts >= 5:  # Lock after 5 failed attempts
            account_lock.is_locked = True
            account_lock.unlock_time = timezone.now() + timedelta(minutes=30)  # Lock for 30 minutes
            account_lock.save()
            
            # Send security notification
            message = f"""
Security Alert: Your account has been locked due to multiple failed login attempts.

Details:
- Time: {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}
- IP Address: {ip_address}
- Failed Attempts: {account_lock.failed_attempts}

Your account will be automatically unlocked after 30 minutes, or contact the system administrator.

If this wasn't you, please contact support immediately.
            """.strip()
            
            create_security_notification(user, 'account_locked', ip_address, message)
            return True  # Account was locked
        else:
            account_lock.save()
            
            # Send failed attempt notification
            attempts_left = 5 - account_lock.failed_attempts
            message = f"""
Security Alert: Failed login attempt detected on your account.

Details:
- Time: {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}
- IP Address: {ip_address}
- Attempts remaining: {attempts_left}

If this wasn't you, please contact support immediately.
            """.strip()
            
            create_security_notification(user, 'failed_login', ip_address, message)
    
    except User.DoesNotExist:
        pass
    
    return False


def generate_tfa_code(user, ip_address, session_key):
    """Generate and send 2FA code"""
    # Invalidate any existing unused codes for this user
    TwoFactorCode.objects.filter(user=user, used=False).update(used=True)
    
    # Create new 2FA code
    tfa_code = TwoFactorCode.objects.create(
        user=user,
        ip_address=ip_address,
        session_key=session_key
    )
    
    # Send code via email
    message = f"""
Your verification code for Wajir County ERP System:

{tfa_code.code}

This code will expire in 2 minutes at {tfa_code.expires_at.strftime('%H:%M:%S')}.

Time: {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}
IP Address: {ip_address}

If you didn't request this code, please contact support immediately.
    """.strip()
    
    create_security_notification(user, 'tfa_code', ip_address, message)
    
    return tfa_code


def get_user_dashboard_url(user):
    """Get appropriate dashboard URL based on user's role"""
    # Check if superuser
    if user.is_superuser:
        return 'admin_dashboard'
    
    # Get user's primary active role
    user_role = UserRole.objects.filter(user=user, is_active=True).first()
    
    if user_role:
        role_name = user_role.role.name.lower()
        
        # Role-based dashboard routing
        role_dashboard_map = {
            'system administrator': 'admin_dashboard',
            'revenue officer': 'revenue_dashboard',
            'health worker': 'health_dashboard',
            'fleet manager': 'fleet_dashboard',
            'hr manager': 'hr_dashboard',
            'finance officer': 'finance_dashboard',
            'lands officer': 'lands_dashboard',
            'asset manager': 'asset_dashboard',
            'inventory manager': 'inventory_dashboard',
        }
        
        for key, dashboard in role_dashboard_map.items():
            if key in role_name:
                return dashboard
    
    # Default dashboard
    return 'general_dashboard'


# ============================================================================
# AUTHENTICATION VIEWS
# ============================================================================

def login_view(request):
    """Enhanced login view with 2FA and security features"""
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    # Check if session expired
    session_expired = request.session.pop('session_expired', False)
    redirect_after_login = request.session.get('redirect_after_login')
    
    # Get the 'next' parameter from URL
    next_url = request.GET.get('next', redirect_after_login)
    
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        tfa_code = request.POST.get('tfa_code', '').strip()
        
        ip_address = get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        
        # Check if account is locked
        is_locked, account_lock, user_obj = check_account_lock(username, ip_address)
        if is_locked:
            minutes_left = int((account_lock.unlock_time - timezone.now()).total_seconds() / 60)
            messages.error(
                request, 
                f'Account is temporarily locked. Please try again in {minutes_left} minutes.'
            )
            return render(request, 'auth/login.html', {'next': next_url})
        
        # If 2FA code is provided, verify it
        if tfa_code:
            return handle_tfa_verification(request, username, tfa_code, ip_address, next_url)
        
        # Regular authentication
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            # Log successful authentication
            LoginAttempt.objects.create(
                username=username,
                ip_address=ip_address,
                success=True,
                user_agent=user_agent
            )
            
            # Reset failed attempts on successful authentication
            if hasattr(user, 'account_lock'):
                account_lock = user.account_lock
                account_lock.failed_attempts = 0
                account_lock.is_locked = False
                account_lock.unlock_time = None
                account_lock.save()
            
            # Check if user requires 2FA (all staff members)
            if user.is_active_staff or user.is_superuser:
                # Require 2FA for staff and admin users
                session_key = get_session_key(request)
                tfa_code_obj = generate_tfa_code(user, ip_address, session_key)
                
                # Store pending login data in session
                request.session['pending_login_user_id'] = user.id
                request.session['pending_login_time'] = timezone.now().isoformat()
                request.session['tfa_code_id'] = tfa_code_obj.id
                request.session['pending_next_url'] = next_url
                
                messages.info(request, 'Verification code sent to your email. Please check and enter the code.')
                return render(request, 'auth/login.html', {
                    'show_tfa': True,
                    'username': username,
                    'expires_at': tfa_code_obj.expires_at.isoformat(),
                    'next': next_url,
                })
            else:
                # Direct login for citizen portal users
                login(request, user)
                
                # Initialize session activity tracking
                request.session['last_activity'] = timezone.now().isoformat()
                
                # Clear the redirect flag
                request.session.pop('redirect_after_login', None)
                
                messages.success(request, f'Welcome back, {user.get_full_name()}!')
                
                # Redirect to next URL or default dashboard
                if next_url and next_url != '/':
                    return redirect(next_url)
                else:
                    return redirect('citizen_dashboard')
        else:
            # Handle failed login
            was_locked = handle_failed_login(username, ip_address, user_agent)
            if was_locked:
                messages.error(request, 'Account locked due to multiple failed attempts. Check your email for details.')
            else:
                messages.error(request, 'Invalid username or password')
    
    # Show session expired message if applicable
    if session_expired:
        messages.warning(request, 'Your session expired due to inactivity. Please log in again.')
    
    return render(request, 'auth/login.html', {'next': next_url})


def handle_tfa_verification(request, username, tfa_code, ip_address, next_url=None):
    """Handle 2FA code verification with redirect support"""
    try:
        # Get pending login data from session
        pending_user_id = request.session.get('pending_login_user_id')
        tfa_code_id = request.session.get('tfa_code_id')
        stored_next_url = request.session.get('pending_next_url', next_url)
        
        if not pending_user_id or not tfa_code_id:
            messages.error(request, 'Session expired. Please login again.')
            return redirect('login')
        
        user = get_object_or_404(User, id=pending_user_id, username=username)
        code_obj = get_object_or_404(TwoFactorCode, id=tfa_code_id, user=user)
        
        # Check if code is valid
        if not code_obj.is_valid():
            messages.error(request, 'Verification code has expired or already been used.')
            return render(request, 'auth/login.html', {
                'show_tfa': True,
                'username': username,
                'code_expired': True,
                'next': stored_next_url,
            })
        
        # Verify the code
        if code_obj.code == tfa_code:
            # Mark code as used
            code_obj.mark_as_used()
            
            # Clear session data
            request.session.pop('pending_login_user_id', None)
            request.session.pop('pending_login_time', None)
            request.session.pop('tfa_code_id', None)
            request.session.pop('pending_next_url', None)
            request.session.pop('redirect_after_login', None)
            
            # Log the user in
            login(request, user)
            
            # Initialize session activity tracking
            request.session['last_activity'] = timezone.now().isoformat()
            
            # Send successful login notification
            message = f"""
Successful login to your account:

Time: {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}
IP Address: {ip_address}
Department: {user.department.name if user.department else 'N/A'}

If this wasn't you, please contact support immediately.
            """.strip()
            
            create_security_notification(user, 'successful_login', ip_address, message)
            
            messages.success(request, f'Welcome back, {user.get_full_name()}!')
            
            # Redirect based on stored URL or user role
            if stored_next_url and stored_next_url != '/':
                return redirect(stored_next_url)
            else:
                dashboard_url = get_user_dashboard_url(user)
                return redirect(dashboard_url)
        else:
            messages.error(request, 'Invalid verification code.')
            return render(request, 'auth/login.html', {
                'show_tfa': True,
                'username': username,
                'expires_at': code_obj.expires_at.isoformat(),
                'next': stored_next_url,
            })
    
    except Exception as e:
        logger.error(f"2FA verification error: {str(e)}")
        messages.error(request, 'An error occurred during verification. Please try again.')
        return redirect('login')


def resend_tfa_code(request):
    """Resend 2FA code via AJAX"""
    if request.method == 'POST':
        try:
            username = request.POST.get('username')
            pending_user_id = request.session.get('pending_login_user_id')
            
            if not pending_user_id:
                return JsonResponse({'success': False, 'message': 'Session expired'})
            
            user = get_object_or_404(User, id=pending_user_id, username=username)
            ip_address = get_client_ip(request)
            
            # Generate new code
            session_key = get_session_key(request)
            tfa_code_obj = generate_tfa_code(user, ip_address, session_key)
            request.session['tfa_code_id'] = tfa_code_obj.id
            
            return JsonResponse({
                'success': True,
                'message': 'New verification code sent to your email.',
                'expires_at': tfa_code_obj.expires_at.isoformat(),
            })
        
        except Exception as e:
            logger.error(f"Resend 2FA code error: {str(e)}")
            return JsonResponse({'success': False, 'message': 'Failed to send code'})
    
    return JsonResponse({'success': False, 'message': 'Invalid request'})


def logout_view(request):
    """Logout user and clear session"""
    # Clear any pending login data
    request.session.pop('pending_login_user_id', None)
    request.session.pop('pending_login_time', None)
    request.session.pop('tfa_code_id', None)
    
    logout(request)
    messages.success(request, 'You have been logged out successfully.')
    return redirect('login')


@login_required(login_url='login')
def dashboard(request):
    """Route users to appropriate dashboard based on their role"""
    dashboard_url = get_user_dashboard_url(request.user)
    return redirect(dashboard_url)

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