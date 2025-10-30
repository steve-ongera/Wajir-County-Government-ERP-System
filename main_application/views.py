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
    """Admin dashboard with comprehensive statistics and analytics"""
    from django.db.models import Sum, Count, Q, Avg
    from datetime import datetime, timedelta
    import json
    
    # Get current date and time ranges
    today = timezone.now().date()
    thirty_days_ago = today - timedelta(days=30)
    six_months_ago = today - timedelta(days=180)
    current_year = today.year
    
    # ============================================================================
    # REVENUE STATISTICS
    # ============================================================================
    
    # Total revenue collected
    total_revenue = Payment.objects.filter(
        status='completed'
    ).aggregate(total=Sum('amount'))['total'] or 0
    
    # Revenue this month
    revenue_this_month = Payment.objects.filter(
        status='completed',
        payment_date__year=today.year,
        payment_date__month=today.month
    ).aggregate(total=Sum('amount'))['total'] or 0
    
    # Revenue today
    revenue_today = Payment.objects.filter(
        status='completed',
        payment_date__date=today
    ).aggregate(total=Sum('amount'))['total'] or 0
    
    # Total bills
    total_bills = Bill.objects.count()
    pending_bills = Bill.objects.filter(status__in=['issued', 'overdue']).count()
    paid_bills = Bill.objects.filter(status='paid').count()
    
    # Outstanding amount
    outstanding_amount = Bill.objects.filter(
        status__in=['issued', 'overdue', 'partially_paid']
    ).aggregate(total=Sum('balance'))['total'] or 0
    
    # ============================================================================
    # CITIZEN & SERVICE STATISTICS
    # ============================================================================
    
    total_citizens = Citizen.objects.filter(is_active=True).count()
    total_licenses = License.objects.count()
    active_licenses = License.objects.filter(status='active').count()
    expired_licenses = License.objects.filter(status='expired').count()
    
    total_properties = Property.objects.filter(status='active').count()
    total_vehicles = Vehicle.objects.filter(is_active=True).count()
    
    # ============================================================================
    # HEALTH STATISTICS
    # ============================================================================
    
    total_patients = Patient.objects.filter(is_active=True).count()
    visits_today = Visit.objects.filter(visit_date__date=today).count()
    visits_this_month = Visit.objects.filter(
        visit_date__year=today.year,
        visit_date__month=today.month
    ).count()
    
    pending_lab_tests = LabTest.objects.filter(status='pending').count()
    active_admissions = Admission.objects.filter(status='admitted').count()
    
    # ============================================================================
    # FLEET & ASSETS STATISTICS
    # ============================================================================
    
    total_vehicles_fleet = FleetVehicle.objects.filter(status='active').count()
    vehicles_maintenance = FleetVehicle.objects.filter(status='maintenance').count()
    
    fuel_cost_month = FuelTransaction.objects.filter(
        transaction_date__year=today.year,
        transaction_date__month=today.month
    ).aggregate(total=Sum('total_amount'))['total'] or 0
    
    total_assets = Asset.objects.filter(status='active').count()
    
    # ============================================================================
    # HR STATISTICS
    # ============================================================================
    
    total_employees = User.objects.filter(is_active_staff=True, is_active=True).count()
    present_today = Attendance.objects.filter(
        attendance_date=today,
        attendance_type='check_in'
    ).values('employee').distinct().count()
    
    pending_leaves = LeaveApplication.objects.filter(status='pending').count()
    
    # ============================================================================
    # CHART DATA - Revenue Trends
    # ============================================================================
    
    # Monthly revenue for last 6 months
    monthly_revenue_data = []
    monthly_labels = []
    
    for i in range(5, -1, -1):
        date = today - timedelta(days=i*30)
        month_start = date.replace(day=1)
        if i == 0:
            month_end = today
        else:
            next_month = month_start.replace(day=28) + timedelta(days=4)
            month_end = next_month - timedelta(days=next_month.day)
        
        revenue = Payment.objects.filter(
            status='completed',
            payment_date__range=[month_start, month_end]
        ).aggregate(total=Sum('amount'))['total'] or 0
        
        monthly_revenue_data.append(float(revenue))
        monthly_labels.append(month_start.strftime('%b %Y'))
    
    revenue_chart_data = json.dumps({
        'labels': monthly_labels,
        'data': monthly_revenue_data
    })
    
    # ============================================================================
    # CHART DATA - Revenue by Stream (Donut Chart)
    # ============================================================================
    
    revenue_by_stream = Payment.objects.filter(
        status='completed'
    ).values('revenue_stream__name').annotate(
        total=Sum('amount')
    ).order_by('-total')[:6]
    
    stream_labels = [item['revenue_stream__name'] for item in revenue_by_stream]
    stream_data = [float(item['total']) for item in revenue_by_stream]
    stream_colors = ['#139145', '#C18B5A', '#CD4F27', '#3B82F6', '#8B5CF6', '#06B6D4']
    
    revenue_stream_chart = json.dumps({
        'labels': stream_labels,
        'data': stream_data,
        'colors': stream_colors
    })
    
    # ============================================================================
    # CHART DATA - Bills Status (Pie Chart)
    # ============================================================================
    
    bill_status_data = Bill.objects.values('status').annotate(
        count=Count('id')
    )
    
    bill_labels = [item['status'].replace('_', ' ').title() for item in bill_status_data]
    bill_counts = [item['count'] for item in bill_status_data]
    bill_colors = ['#139145', '#C18B5A', '#CD4F27', '#EF4444', '#F59E0B']
    
    bill_status_chart = json.dumps({
        'labels': bill_labels,
        'data': bill_counts,
        'colors': bill_colors
    })
    
    # ============================================================================
    # CHART DATA - Daily Revenue (Last 30 Days - Area Chart)
    # ============================================================================
    
    daily_revenue_data = []
    daily_labels = []
    
    for i in range(29, -1, -1):
        date = today - timedelta(days=i)
        revenue = Payment.objects.filter(
            status='completed',
            payment_date__date=date
        ).aggregate(total=Sum('amount'))['total'] or 0
        
        daily_revenue_data.append(float(revenue))
        daily_labels.append(date.strftime('%b %d'))
    
    daily_revenue_chart = json.dumps({
        'labels': daily_labels,
        'data': daily_revenue_data
    })
    
    # ============================================================================
    # CHART DATA - Revenue by Sub-County (Bar Chart)
    # ============================================================================
    
    subcounty_revenue = Payment.objects.filter(
        status='completed'
    ).values('sub_county__name').annotate(
        total=Sum('amount')
    ).order_by('-total')[:10]
    
    subcounty_labels = [item['sub_county__name'] or 'Unknown' for item in subcounty_revenue]
    subcounty_data = [float(item['total']) for item in subcounty_revenue]
    
    subcounty_chart = json.dumps({
        'labels': subcounty_labels,
        'data': subcounty_data
    })
    
    # ============================================================================
    # CHART DATA - Patients by Month (Line Chart)
    # ============================================================================
    
    patient_monthly_data = []
    patient_labels = []
    
    for i in range(5, -1, -1):
        date = today - timedelta(days=i*30)
        month_start = date.replace(day=1)
        if i == 0:
            month_end = today
        else:
            next_month = month_start.replace(day=28) + timedelta(days=4)
            month_end = next_month - timedelta(days=next_month.day)
        
        visits = Visit.objects.filter(
            visit_date__range=[month_start, month_end]
        ).count()
        
        patient_monthly_data.append(visits)
        patient_labels.append(month_start.strftime('%b'))
    
    patient_chart = json.dumps({
        'labels': patient_labels,
        'data': patient_monthly_data
    })
    
    # ============================================================================
    # CHART DATA - License Status (Donut Chart)
    # ============================================================================
    
    license_status = License.objects.values('status').annotate(
        count=Count('id')
    )
    
    license_labels = [item['status'].replace('_', ' ').title() for item in license_status]
    license_counts = [item['count'] for item in license_status]
    license_colors = ['#139145', '#C18B5A', '#CD4F27', '#EF4444', '#F59E0B', '#3B82F6']
    
    license_chart = json.dumps({
        'labels': license_labels,
        'data': license_counts,
        'colors': license_colors
    })
    
    # ============================================================================
    # CHART DATA - Fleet Fuel Consumption (Bar Chart)
    # ============================================================================
    
    fuel_by_vehicle = FuelTransaction.objects.filter(
        transaction_date__gte=thirty_days_ago
    ).values('vehicle__registration_number').annotate(
        total_liters=Sum('quantity_liters'),
        total_cost=Sum('total_amount')
    ).order_by('-total_cost')[:10]
    
    fuel_labels = [item['vehicle__registration_number'] for item in fuel_by_vehicle]
    fuel_data = [float(item['total_cost']) for item in fuel_by_vehicle]
    
    fuel_chart = json.dumps({
        'labels': fuel_labels,
        'data': fuel_data
    })
    
    # ============================================================================
    # CHART DATA - Payment Methods Distribution (Pie Chart)
    # ============================================================================
    
    payment_methods = Payment.objects.filter(
        status='completed'
    ).values('payment_method__name').annotate(
        count=Count('id'),
        total=Sum('amount')
    ).order_by('-total')
    
    method_labels = [item['payment_method__name'] for item in payment_methods]
    method_data = [float(item['total']) for item in payment_methods]
    method_colors = ['#139145', '#C18B5A', '#CD4F27', '#3B82F6', '#8B5CF6']
    
    payment_method_chart = json.dumps({
        'labels': method_labels,
        'data': method_data,
        'colors': method_colors
    })
    
    # ============================================================================
    # Recent Activities
    # ============================================================================
    
    recent_payments = Payment.objects.filter(
        status='completed'
    ).select_related('citizen', 'revenue_stream', 'payment_method').order_by('-payment_date')[:10]
    
    recent_bills = Bill.objects.select_related(
        'citizen', 'revenue_stream'
    ).order_by('-created_at')[:10]
    
    # ============================================================================
    # Alerts & Notifications
    # ============================================================================
    
    overdue_bills_count = Bill.objects.filter(
        status='overdue',
        due_date__lt=today
    ).count()
    
    expiring_licenses = License.objects.filter(
        status='active',
        expiry_date__range=[today, today + timedelta(days=30)]
    ).count()
    
    context = {
        # Revenue Stats
        'total_revenue': total_revenue,
        'revenue_this_month': revenue_this_month,
        'revenue_today': revenue_today,
        'total_bills': total_bills,
        'pending_bills': pending_bills,
        'paid_bills': paid_bills,
        'outstanding_amount': outstanding_amount,
        
        # Citizen Stats
        'total_citizens': total_citizens,
        'total_licenses': total_licenses,
        'active_licenses': active_licenses,
        'expired_licenses': expired_licenses,
        'total_properties': total_properties,
        'total_vehicles': total_vehicles,
        
        # Health Stats
        'total_patients': total_patients,
        'visits_today': visits_today,
        'visits_this_month': visits_this_month,
        'pending_lab_tests': pending_lab_tests,
        'active_admissions': active_admissions,
        
        # Fleet & Assets
        'total_vehicles_fleet': total_vehicles_fleet,
        'vehicles_maintenance': vehicles_maintenance,
        'fuel_cost_month': fuel_cost_month,
        'total_assets': total_assets,
        
        # HR Stats
        'total_employees': total_employees,
        'present_today': present_today,
        'pending_leaves': pending_leaves,
        
        # Chart Data
        'revenue_chart_data': revenue_chart_data,
        'revenue_stream_chart': revenue_stream_chart,
        'bill_status_chart': bill_status_chart,
        'daily_revenue_chart': daily_revenue_chart,
        'subcounty_chart': subcounty_chart,
        'patient_chart': patient_chart,
        'license_chart': license_chart,
        'fuel_chart': fuel_chart,
        'payment_method_chart': payment_method_chart,
        
        # Recent Data
        'recent_payments': recent_payments,
        'recent_bills': recent_bills,
        
        # Alerts
        'overdue_bills_count': overdue_bills_count,
        'expiring_licenses': expiring_licenses,
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


"""
Citizen Management Views
Handles CRUD operations, search, filtering, and export
"""

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.db.models import Q, Count, Sum
from django.http import HttpResponse, JsonResponse
from django.utils import timezone
from datetime import datetime, timedelta
import openpyxl
from openpyxl.styles import Font, Alignment, PatternFill, Border, Side
from openpyxl.utils import get_column_letter

from main_application.models import (
    Citizen, SubCounty, Ward, User, Bill, Payment,
    CitizenDocument
)


@login_required
def citizen_list(request):
    """
    List all citizens with search, filter, and pagination
    """
    # Base queryset
    citizens = Citizen.objects.select_related(
        'sub_county', 'ward', 'created_by'
    ).prefetch_related('bills', 'payments')
    
    # Search functionality
    search_query = request.GET.get('search', '').strip()
    if search_query:
        citizens = citizens.filter(
            Q(unique_identifier__icontains=search_query) |
            Q(first_name__icontains=search_query) |
            Q(last_name__icontains=search_query) |
            Q(business_name__icontains=search_query) |
            Q(phone_primary__icontains=search_query) |
            Q(email__icontains=search_query) |
            Q(registration_number__icontains=search_query)
        )
    
    # Filters
    entity_type = request.GET.get('entity_type', '')
    sub_county_id = request.GET.get('sub_county', '')
    ward_id = request.GET.get('ward', '')
    status = request.GET.get('status', '')
    has_portal = request.GET.get('has_portal', '')
    date_from = request.GET.get('date_from', '')
    date_to = request.GET.get('date_to', '')
    
    if entity_type:
        citizens = citizens.filter(entity_type=entity_type)
    
    if sub_county_id:
        citizens = citizens.filter(sub_county_id=sub_county_id)
    
    if ward_id:
        citizens = citizens.filter(ward_id=ward_id)
    
    if status:
        is_active = status == 'active'
        citizens = citizens.filter(is_active=is_active)
    
    if has_portal:
        has_access = has_portal == 'true'
        citizens = citizens.filter(has_portal_access=has_access)
    
    if date_from:
        try:
            date_from_obj = datetime.strptime(date_from, '%Y-%m-%d').date()
            citizens = citizens.filter(created_at__date__gte=date_from_obj)
        except ValueError:
            pass
    
    if date_to:
        try:
            date_to_obj = datetime.strptime(date_to, '%Y-%m-%d').date()
            citizens = citizens.filter(created_at__date__lte=date_to_obj)
        except ValueError:
            pass
    
    # Order by most recent
    citizens = citizens.order_by('-created_at')
    
    # Statistics
    total_citizens = Citizen.objects.count()
    active_citizens = Citizen.objects.filter(is_active=True).count()
    individuals = Citizen.objects.filter(entity_type='individual').count()
    businesses = Citizen.objects.filter(entity_type='business').count()
    portal_users = Citizen.objects.filter(has_portal_access=True).count()
    
    # Recent registrations (last 30 days)
    thirty_days_ago = timezone.now() - timedelta(days=30)
    recent_registrations = Citizen.objects.filter(
        created_at__gte=thirty_days_ago
    ).count()
    
    stats = {
        'total': total_citizens,
        'active': active_citizens,
        'individuals': individuals,
        'businesses': businesses,
        'portal_users': portal_users,
        'recent_registrations': recent_registrations,
    }
    
    # Pagination
    paginator = Paginator(citizens, 25)  # 25 citizens per page
    page = request.GET.get('page', 1)
    
    try:
        page_obj = paginator.page(page)
    except PageNotAnInteger:
        page_obj = paginator.page(1)
    except EmptyPage:
        page_obj = paginator.page(paginator.num_pages)
    
    # Get filter options
    sub_counties = SubCounty.objects.filter(is_active=True).order_by('name')
    wards = Ward.objects.filter(is_active=True).select_related('sub_county').order_by('name')
    
    context = {
        'page_obj': page_obj,
        'stats': stats,
        'search_query': search_query,
        'sub_counties': sub_counties,
        'wards': wards,
        'current_entity_type': entity_type,
        'current_sub_county': sub_county_id,
        'current_ward': ward_id,
        'current_status': status,
        'current_has_portal': has_portal,
        'date_from': date_from,
        'date_to': date_to,
    }
    
    return render(request, 'admin/citizens/citizen_list.html', context)


@login_required
def citizen_detail(request, unique_identifier):
    """
    View detailed information about a specific citizen
    Uses unique_identifier (ID number or business registration number)
    """
    citizen = get_object_or_404(
        Citizen.objects.select_related('sub_county', 'ward', 'created_by', 'portal_user'),
        unique_identifier=unique_identifier
    )
    
    # Get related records
    bills = citizen.bills.select_related('revenue_stream').order_by('-created_at')[:10]
    payments = citizen.payments.select_related('payment_method', 'revenue_stream').order_by('-created_at')[:10]
    documents = citizen.documents.select_related('uploaded_by').order_by('-uploaded_at')
    
    # Financial summary
    total_billed = citizen.bills.aggregate(Sum('total_amount'))['total_amount__sum'] or 0
    total_paid = citizen.payments.filter(status='completed').aggregate(Sum('amount'))['amount__sum'] or 0
    outstanding_balance = citizen.bills.filter(
        status__in=['issued', 'partially_paid', 'overdue']
    ).aggregate(Sum('balance'))['balance__sum'] or 0
    
    # Bill statistics
    bill_stats = {
        'total': citizen.bills.count(),
        'paid': citizen.bills.filter(status='paid').count(),
        'pending': citizen.bills.filter(status__in=['issued', 'partially_paid']).count(),
        'overdue': citizen.bills.filter(status='overdue').count(),
    }
    
    context = {
        'citizen': citizen,
        'bills': bills,
        'payments': payments,
        'documents': documents,
        'total_billed': total_billed,
        'total_paid': total_paid,
        'outstanding_balance': outstanding_balance,
        'bill_stats': bill_stats,
    }
    
    return render(request, 'admin/citizens/citizen_detail.html', context)


@login_required
def citizen_create(request):
    """
    Create a new citizen record
    """
    if request.method == 'POST':
        entity_type = request.POST.get('entity_type')
        unique_identifier = request.POST.get('unique_identifier')
        
        # Check if unique identifier already exists
        if Citizen.objects.filter(unique_identifier=unique_identifier).exists():
            messages.error(request, f'A citizen with ID/Registration number {unique_identifier} already exists.')
            return render(request, 'admin/citizens/citizen_create.html', {
                'sub_counties': SubCounty.objects.filter(is_active=True),
                'wards': Ward.objects.filter(is_active=True),
                'post_data': request.POST,
            })
        
        # Check for duplicate phone
        phone_primary = request.POST.get('phone_primary')
        if Citizen.objects.filter(phone_primary=phone_primary).exists():
            messages.error(request, f'A citizen with phone number {phone_primary} already exists.')
            return render(request, 'admin/citizens/citizen_create.html', {
                'sub_counties': SubCounty.objects.filter(is_active=True),
                'wards': Ward.objects.filter(is_active=True),
                'post_data': request.POST,
            })
        
        # Check for duplicate email if provided
        email = request.POST.get('email', '').strip()
        if email and Citizen.objects.filter(email=email).exists():
            messages.error(request, f'A citizen with email {email} already exists.')
            return render(request, 'admin/citizens/citizen_create.html', {
                'sub_counties': SubCounty.objects.filter(is_active=True),
                'wards': Ward.objects.filter(is_active=True),
                'post_data': request.POST,
            })
        
        try:
            # Create citizen based on entity type
            citizen_data = {
                'entity_type': entity_type,
                'unique_identifier': unique_identifier,
                'phone_primary': phone_primary,
                'email': email if email else None,
                'phone_secondary': request.POST.get('phone_secondary', ''),
                'postal_address': request.POST.get('postal_address', ''),
                'physical_address': request.POST.get('physical_address', ''),
                'sub_county_id': request.POST.get('sub_county'),
                'ward_id': request.POST.get('ward'),
                'created_by': request.user,
                'is_active': True,
            }
            
            if entity_type == 'individual':
                citizen_data.update({
                    'first_name': request.POST.get('first_name'),
                    'middle_name': request.POST.get('middle_name', ''),
                    'last_name': request.POST.get('last_name'),
                    'gender': request.POST.get('gender'),
                })
                
                # Parse date of birth
                dob = request.POST.get('date_of_birth')
                if dob:
                    try:
                        citizen_data['date_of_birth'] = datetime.strptime(dob, '%Y-%m-%d').date()
                    except ValueError:
                        pass
            
            else:  # business or organization
                citizen_data.update({
                    'business_name': request.POST.get('business_name'),
                    'registration_number': request.POST.get('registration_number', ''),
                })
            
            citizen = Citizen.objects.create(**citizen_data)
            
            messages.success(
                request,
                f'Citizen {citizen} registered successfully with ID: {unique_identifier}'
            )
            return redirect('citizen_detail', unique_identifier=citizen.unique_identifier)
            
        except Exception as e:
            messages.error(request, f'Error creating citizen: {str(e)}')
    
    context = {
        'sub_counties': SubCounty.objects.filter(is_active=True).order_by('name'),
        'wards': Ward.objects.filter(is_active=True).select_related('sub_county').order_by('name'),
    }
    
    return render(request, 'admin/citizens/citizen_create.html', context)


@login_required
def citizen_update(request, unique_identifier):
    """
    Update citizen information
    """
    citizen = get_object_or_404(Citizen, unique_identifier=unique_identifier)
    
    if request.method == 'POST':
        try:
            # Update common fields
            citizen.phone_primary = request.POST.get('phone_primary')
            citizen.phone_secondary = request.POST.get('phone_secondary', '')
            citizen.email = request.POST.get('email', '') or None
            citizen.postal_address = request.POST.get('postal_address', '')
            citizen.physical_address = request.POST.get('physical_address', '')
            citizen.sub_county_id = request.POST.get('sub_county')
            citizen.ward_id = request.POST.get('ward')
            
            # Update type-specific fields
            if citizen.entity_type == 'individual':
                citizen.first_name = request.POST.get('first_name')
                citizen.middle_name = request.POST.get('middle_name', '')
                citizen.last_name = request.POST.get('last_name')
                citizen.gender = request.POST.get('gender')
                
                dob = request.POST.get('date_of_birth')
                if dob:
                    try:
                        citizen.date_of_birth = datetime.strptime(dob, '%Y-%m-%d').date()
                    except ValueError:
                        pass
            else:
                citizen.business_name = request.POST.get('business_name')
                citizen.registration_number = request.POST.get('registration_number', '')
            
            citizen.save()
            
            messages.success(request, f'Citizen {citizen} updated successfully.')
            return redirect('citizen_detail', unique_identifier=citizen.unique_identifier)
            
        except Exception as e:
            messages.error(request, f'Error updating citizen: {str(e)}')
    
    context = {
        'citizen': citizen,
        'sub_counties': SubCounty.objects.filter(is_active=True).order_by('name'),
        'wards': Ward.objects.filter(is_active=True).select_related('sub_county').order_by('name'),
    }
    
    return render(request, 'admin/citizens/citizen_update.html', context)


@login_required
def citizen_delete(request, unique_identifier):
    """
    Soft delete a citizen (mark as inactive)
    """
    if request.method == 'POST':
        citizen = get_object_or_404(Citizen, unique_identifier=unique_identifier)
        
        # Check if citizen has active bills
        active_bills = citizen.bills.filter(
            status__in=['issued', 'partially_paid']
        ).count()
        
        if active_bills > 0:
            messages.error(
                request,
                f'Cannot delete citizen with {active_bills} active bill(s). Please settle all bills first.'
            )
            return redirect('citizen_detail', unique_identifier=unique_identifier)
        
        # Soft delete
        citizen.is_active = False
        citizen.save()
        
        messages.success(request, f'Citizen {citizen} has been deactivated.')
        return redirect('citizen_list')
    
    return redirect('citizen_list')


@login_required
def citizen_export_excel(request):
    """
    Export filtered citizens to Excel
    """
    # Apply same filters as list view
    citizens = Citizen.objects.select_related('sub_county', 'ward', 'created_by')
    
    # Search
    search_query = request.GET.get('search', '').strip()
    if search_query:
        citizens = citizens.filter(
            Q(unique_identifier__icontains=search_query) |
            Q(first_name__icontains=search_query) |
            Q(last_name__icontains=search_query) |
            Q(business_name__icontains=search_query) |
            Q(phone_primary__icontains=search_query) |
            Q(email__icontains=search_query)
        )
    
    # Filters
    entity_type = request.GET.get('entity_type', '')
    sub_county_id = request.GET.get('sub_county', '')
    ward_id = request.GET.get('ward', '')
    status = request.GET.get('status', '')
    has_portal = request.GET.get('has_portal', '')
    date_from = request.GET.get('date_from', '')
    date_to = request.GET.get('date_to', '')
    
    if entity_type:
        citizens = citizens.filter(entity_type=entity_type)
    if sub_county_id:
        citizens = citizens.filter(sub_county_id=sub_county_id)
    if ward_id:
        citizens = citizens.filter(ward_id=ward_id)
    if status:
        is_active = status == 'active'
        citizens = citizens.filter(is_active=is_active)
    if has_portal:
        has_access = has_portal == 'true'
        citizens = citizens.filter(has_portal_access=has_access)
    if date_from:
        try:
            date_from_obj = datetime.strptime(date_from, '%Y-%m-%d').date()
            citizens = citizens.filter(created_at__date__gte=date_from_obj)
        except ValueError:
            pass
    if date_to:
        try:
            date_to_obj = datetime.strptime(date_to, '%Y-%m-%d').date()
            citizens = citizens.filter(created_at__date__lte=date_to_obj)
        except ValueError:
            pass
    
    citizens = citizens.order_by('-created_at')
    
    # Create workbook
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Citizens Export"
    
    # Styling
    header_fill = PatternFill(start_color="3498db", end_color="3498db", fill_type="solid")
    header_font = Font(bold=True, color="FFFFFF", size=12)
    border = Border(
        left=Side(style='thin'),
        right=Side(style='thin'),
        top=Side(style='thin'),
        bottom=Side(style='thin')
    )
    
    # Headers
    headers = [
        'ID/Registration #',
        'Entity Type',
        'Full Name/Business Name',
        'Gender',
        'Date of Birth',
        'Phone Primary',
        'Phone Secondary',
        'Email',
        'Sub-County',
        'Ward',
        'Physical Address',
        'Postal Address',
        'Portal Access',
        'Status',
        'Registration Date',
        'Created By',
    ]
    
    for col_num, header in enumerate(headers, 1):
        cell = ws.cell(row=1, column=col_num)
        cell.value = header
        cell.fill = header_fill
        cell.font = header_font
        cell.alignment = Alignment(horizontal='center', vertical='center')
        cell.border = border
    
    # Data rows
    for row_num, citizen in enumerate(citizens, 2):
        if citizen.entity_type == 'individual':
            full_name = f"{citizen.first_name} {citizen.middle_name} {citizen.last_name}".strip()
            gender = citizen.gender or ''
            dob = citizen.date_of_birth.strftime('%Y-%m-%d') if citizen.date_of_birth else ''
        else:
            full_name = citizen.business_name or ''
            gender = 'N/A'
            dob = 'N/A'
        
        row_data = [
            citizen.unique_identifier,
            citizen.get_entity_type_display(),
            full_name,
            gender,
            dob,
            citizen.phone_primary,
            citizen.phone_secondary or '',
            citizen.email or '',
            citizen.sub_county.name if citizen.sub_county else '',
            citizen.ward.name if citizen.ward else '',
            citizen.physical_address or '',
            citizen.postal_address or '',
            'Yes' if citizen.has_portal_access else 'No',
            'Active' if citizen.is_active else 'Inactive',
            citizen.created_at.strftime('%Y-%m-%d %H:%M'),
            citizen.created_by.get_full_name() if citizen.created_by else '',
        ]
        
        for col_num, value in enumerate(row_data, 1):
            cell = ws.cell(row=row_num, column=col_num)
            cell.value = value
            cell.border = border
            
            # Alignment
            if col_num in [1, 5, 6, 15]:  # ID, phones, date
                cell.alignment = Alignment(horizontal='left')
            else:
                cell.alignment = Alignment(horizontal='left', wrap_text=True)
    
    # Adjust column widths
    column_widths = {
        'A': 20,  # ID
        'B': 15,  # Entity Type
        'C': 30,  # Name
        'D': 10,  # Gender
        'E': 15,  # DOB
        'F': 15,  # Phone 1
        'G': 15,  # Phone 2
        'H': 25,  # Email
        'I': 20,  # Sub-County
        'J': 20,  # Ward
        'K': 35,  # Physical Address
        'L': 20,  # Postal Address
        'M': 12,  # Portal
        'N': 10,  # Status
        'O': 18,  # Reg Date
        'P': 20,  # Created By
    }
    
    for col, width in column_widths.items():
        ws.column_dimensions[col].width = width
    
    # Freeze header row
    ws.freeze_panes = 'A2'
    
    # Prepare response
    response = HttpResponse(
        content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )
    
    filename = f'citizens_export_{timezone.now().strftime("%Y%m%d_%H%M%S")}.xlsx'
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    
    wb.save(response)
    return response


@login_required
def get_wards_by_subcounty(request):
    """
    AJAX endpoint to get wards by sub-county
    """
    sub_county_id = request.GET.get('sub_county_id')
    
    if not sub_county_id:
        return JsonResponse({'wards': []})
    
    wards = Ward.objects.filter(
        sub_county_id=sub_county_id,
        is_active=True
    ).values('id', 'name').order_by('name')
    
    return JsonResponse({'wards': list(wards)})


"""
Wajir County Analytics Dashboard View
Dynamic analytics with filtering, graphs, and export capabilities
"""

from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.db.models import Sum, Count, Avg, Q, F
from django.db.models.functions import TruncMonth, TruncWeek, TruncDay, TruncYear
from django.http import JsonResponse, HttpResponse
from django.utils import timezone
from datetime import timedelta, datetime
from decimal import Decimal
import json
import csv
from io import BytesIO
import xlsxwriter

# Import your models
from .models import (
    Payment, Bill, Citizen, RevenueStream, License, 
    Patient, Visit, FleetVehicle, FuelTransaction,
    SubCounty, Ward, Property, Business, Fine,
    Attendance, LeaveApplication, Asset, Store,
    HealthFacility, Department
)


@login_required
def analytics_dashboard(request):
    """
    Main analytics dashboard view with dynamic filtering
    """
    # Get filter parameters
    date_range = request.GET.get('date_range', '30')  # days, or custom
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    sub_county_id = request.GET.get('sub_county')
    ward_id = request.GET.get('ward')
    revenue_stream_id = request.GET.get('revenue_stream')
    department_id = request.GET.get('department')
    
    # Calculate date range
    today = timezone.now().date()
    
    if start_date and end_date:
        # Custom date range
        start = datetime.strptime(start_date, '%Y-%m-%d').date()
        end = datetime.strptime(end_date, '%Y-%m-%d').date()
    else:
        # Predefined ranges
        if date_range == '7':
            start = today - timedelta(days=7)
        elif date_range == '30':
            start = today - timedelta(days=30)
        elif date_range == '90':
            start = today - timedelta(days=90)
        elif date_range == '180':
            start = today - timedelta(days=180)
        elif date_range == '365':
            start = today - timedelta(days=365)
        elif date_range == 'ytd':
            start = datetime(today.year, 1, 1).date()
        elif date_range == 'month':
            start = datetime(today.year, today.month, 1).date()
        else:
            start = today - timedelta(days=30)
        end = today
    
    # Build base querysets with filters
    payments_qs = Payment.objects.filter(
        payment_date__date__gte=start,
        payment_date__date__lte=end,
        status='completed'
    )
    
    bills_qs = Bill.objects.filter(
        bill_date__gte=start,
        bill_date__lte=end
    )
    
    # Apply location filters
    if sub_county_id:
        payments_qs = payments_qs.filter(sub_county_id=sub_county_id)
        bills_qs = bills_qs.filter(sub_county_id=sub_county_id)
    
    if ward_id:
        payments_qs = payments_qs.filter(ward_id=ward_id)
        bills_qs = bills_qs.filter(ward_id=ward_id)
    
    if revenue_stream_id:
        payments_qs = payments_qs.filter(revenue_stream_id=revenue_stream_id)
        bills_qs = bills_qs.filter(revenue_stream_id=revenue_stream_id)
    
    # =====================================================================
    # REVENUE ANALYTICS
    # =====================================================================
    
    # Total revenue collected
    total_revenue = payments_qs.aggregate(
        total=Sum('amount')
    )['total'] or Decimal('0.00')
    
    # Total billed amount
    total_billed = bills_qs.aggregate(
        total=Sum('total_amount')
    )['total'] or Decimal('0.00')
    
    # Outstanding amount
    outstanding = bills_qs.filter(
        status__in=['issued', 'partially_paid', 'overdue']
    ).aggregate(
        total=Sum('balance')
    )['total'] or Decimal('0.00')
    
    # Collection rate
    collection_rate = (total_revenue / total_billed * 100) if total_billed > 0 else 0
    
    # Revenue growth (compare with previous period)
    period_days = (end - start).days
    prev_start = start - timedelta(days=period_days)
    prev_end = start - timedelta(days=1)
    
    prev_revenue = Payment.objects.filter(
        payment_date__date__gte=prev_start,
        payment_date__date__lte=prev_end,
        status='completed'
    ).aggregate(total=Sum('amount'))['total'] or Decimal('0.00')
    
    revenue_growth = ((total_revenue - prev_revenue) / prev_revenue * 100) if prev_revenue > 0 else 0
    
    # =====================================================================
    # REVENUE TREND CHARTS
    # =====================================================================
    
    # Determine grouping based on date range
    days_diff = (end - start).days
    
    if days_diff <= 31:
        # Daily grouping
        trunc_func = TruncDay
        date_format = '%b %d'
    elif days_diff <= 90:
        # Weekly grouping
        trunc_func = TruncWeek
        date_format = 'Week %W'
    elif days_diff <= 365:
        # Monthly grouping
        trunc_func = TruncMonth
        date_format = '%b %Y'
    else:
        # Yearly grouping
        trunc_func = TruncYear
        date_format = '%Y'
    
    # Revenue trend over time
    revenue_trend = payments_qs.annotate(
        period=trunc_func('payment_date')
    ).values('period').annotate(
        revenue=Sum('amount'),
        count=Count('id')
    ).order_by('period')
    
    revenue_trend_data = {
        'labels': [item['period'].strftime(date_format) for item in revenue_trend],
        'data': [float(item['revenue']) for item in revenue_trend],
        'counts': [item['count'] for item in revenue_trend]
    }
    
    # Revenue by stream
    revenue_by_stream = payments_qs.values(
        'revenue_stream__name'
    ).annotate(
        revenue=Sum('amount')
    ).order_by('-revenue')[:10]
    
    revenue_stream_data = {
        'labels': [item['revenue_stream__name'] for item in revenue_by_stream],
        'data': [float(item['revenue']) for item in revenue_by_stream],
        'colors': ['#139145', '#C18B5A', '#CD4F27', '#3B82F6', '#8B5CF6', 
                   '#06B6D4', '#F59E0B', '#EF4444', '#10B981', '#6366F1']
    }
    
    # Revenue by sub-county
    revenue_by_subcounty = payments_qs.values(
        'sub_county__name'
    ).annotate(
        revenue=Sum('amount')
    ).order_by('-revenue')[:10]
    
    subcounty_revenue_data = {
        'labels': [item['sub_county__name'] or 'Unknown' for item in revenue_by_subcounty],
        'data': [float(item['revenue']) for item in revenue_by_subcounty]
    }
    
    # Revenue by payment method
    revenue_by_method = payments_qs.values(
        'payment_method__name'
    ).annotate(
        revenue=Sum('amount'),
        count=Count('id')
    ).order_by('-revenue')
    
    payment_method_data = {
        'labels': [item['payment_method__name'] for item in revenue_by_method],
        'data': [float(item['revenue']) for item in revenue_by_method],
        'counts': [item['count'] for item in revenue_by_method],
        'colors': ['#139145', '#C18B5A', '#CD4F27', '#3B82F6', '#8B5CF6']
    }
    
    # =====================================================================
    # BILLS ANALYTICS
    # =====================================================================
    
    bills_by_status = bills_qs.values('status').annotate(
        count=Count('id'),
        amount=Sum('total_amount')
    ).order_by('-count')
    
    bills_status_data = {
        'labels': [item['status'].replace('_', ' ').title() for item in bills_by_status],
        'data': [item['count'] for item in bills_by_status],
        'amounts': [float(item['amount']) for item in bills_by_status],
        'colors': ['#139145', '#C18B5A', '#CD4F27', '#3B82F6', '#8B5CF6', '#06B6D4']
    }
    
    # Bill statistics
    total_bills = bills_qs.count()
    paid_bills = bills_qs.filter(status='paid').count()
    overdue_bills = bills_qs.filter(status='overdue').count()
    pending_bills = bills_qs.filter(status__in=['issued', 'partially_paid']).count()
    
    # =====================================================================
    # CITIZEN ANALYTICS
    # =====================================================================
    
    total_citizens = Citizen.objects.filter(is_active=True).count()
    new_citizens = Citizen.objects.filter(
        created_at__date__gte=start,
        created_at__date__lte=end
    ).count()
    
    citizens_by_type = Citizen.objects.values('entity_type').annotate(
        count=Count('id')
    ).order_by('-count')
    
    citizen_type_data = {
        'labels': [item['entity_type'].title() for item in citizens_by_type],
        'data': [item['count'] for item in citizens_by_type],
        'colors': ['#139145', '#C18B5A', '#CD4F27', '#3B82F6']
    }
    
    # =====================================================================
    # HEALTH SERVICES ANALYTICS
    # =====================================================================
    
    total_patients = Patient.objects.filter(is_active=True).count()
    
    visits_in_period = Visit.objects.filter(
        visit_date__date__gte=start,
        visit_date__date__lte=end
    )
    
    total_visits = visits_in_period.count()
    
    # Visits trend
    visits_trend = visits_in_period.annotate(
        period=trunc_func('visit_date')
    ).values('period').annotate(
        count=Count('id')
    ).order_by('period')
    
    visits_trend_data = {
        'labels': [item['period'].strftime(date_format) for item in visits_trend],
        'data': [item['count'] for item in visits_trend]
    }
    
    # Visits by facility
    visits_by_facility = visits_in_period.values(
        'facility__name'
    ).annotate(
        count=Count('id')
    ).order_by('-count')[:10]
    
    facility_visits_data = {
        'labels': [item['facility__name'] for item in visits_by_facility],
        'data': [item['count'] for item in visits_by_facility]
    }
    
    # Visits by type
    visits_by_type = visits_in_period.values('visit_type').annotate(
        count=Count('id')
    ).order_by('-count')
    
    visit_type_data = {
        'labels': [item['visit_type'].title() for item in visits_by_type],
        'data': [item['count'] for item in visits_by_type],
        'colors': ['#139145', '#C18B5A', '#CD4F27']
    }
    
    # =====================================================================
    # LICENSE & BUSINESS ANALYTICS
    # =====================================================================
    
    total_licenses = License.objects.filter(status='active').count()
    expiring_licenses = License.objects.filter(
        expiry_date__gte=today,
        expiry_date__lte=today + timedelta(days=30),
        status='active'
    ).count()
    
    licenses_issued = License.objects.filter(
        issue_date__gte=start,
        issue_date__lte=end
    ).count()
    
    licenses_by_status = License.objects.values('status').annotate(
        count=Count('id')
    ).order_by('-count')
    
    license_status_data = {
        'labels': [item['status'].replace('_', ' ').title() for item in licenses_by_status],
        'data': [item['count'] for item in licenses_by_status],
        'colors': ['#139145', '#C18B5A', '#CD4F27', '#3B82F6', '#8B5CF6']
    }
    
    # Businesses by category
    businesses_by_category = Business.objects.filter(
        is_active=True
    ).values(
        'business_category__name'
    ).annotate(
        count=Count('id')
    ).order_by('-count')[:10]
    
    business_category_data = {
        'labels': [item['business_category__name'] for item in businesses_by_category],
        'data': [item['count'] for item in businesses_by_category]
    }
    
    # =====================================================================
    # FLEET & FUEL ANALYTICS
    # =====================================================================
    
    active_vehicles = FleetVehicle.objects.filter(status='active').count()
    
    fuel_transactions = FuelTransaction.objects.filter(
        transaction_date__date__gte=start,
        transaction_date__date__lte=end
    )
    
    total_fuel_cost = fuel_transactions.aggregate(
        total=Sum('total_amount')
    )['total'] or Decimal('0.00')
    
    total_fuel_liters = fuel_transactions.aggregate(
        total=Sum('quantity_liters')
    )['total'] or Decimal('0.00')
    
    # Fuel consumption by vehicle
    fuel_by_vehicle = fuel_transactions.values(
        'vehicle__registration_number'
    ).annotate(
        cost=Sum('total_amount'),
        liters=Sum('quantity_liters')
    ).order_by('-cost')[:10]
    
    fuel_vehicle_data = {
        'labels': [item['vehicle__registration_number'] for item in fuel_by_vehicle],
        'data': [float(item['cost']) for item in fuel_by_vehicle],
        'liters': [float(item['liters']) for item in fuel_by_vehicle]
    }
    
    # Fuel trend
    fuel_trend = fuel_transactions.annotate(
        period=trunc_func('transaction_date')
    ).values('period').annotate(
        cost=Sum('total_amount'),
        liters=Sum('quantity_liters')
    ).order_by('period')
    
    fuel_trend_data = {
        'labels': [item['period'].strftime(date_format) for item in fuel_trend],
        'data': [float(item['cost']) for item in fuel_trend],
        'liters': [float(item['liters']) for item in fuel_trend]
    }
    
    # =====================================================================
    # HR ANALYTICS
    # =====================================================================
    
    total_employees = User.objects.filter(is_active=True, is_staff=True).count()
    
    # Attendance for the period
    attendance_records = Attendance.objects.filter(
        attendance_date__gte=start,
        attendance_date__lte=end
    )
    
    total_attendance = attendance_records.values('employee').distinct().count()
    
    # Leave applications
    leave_applications = LeaveApplication.objects.filter(
        start_date__gte=start,
        start_date__lte=end
    )
    
    leaves_by_status = leave_applications.values('status').annotate(
        count=Count('id')
    ).order_by('-count')
    
    leave_status_data = {
        'labels': [item['status'].title() for item in leaves_by_status],
        'data': [item['count'] for item in leaves_by_status],
        'colors': ['#139145', '#C18B5A', '#CD4F27', '#3B82F6']
    }
    
    # =====================================================================
    # PROPERTY & FINES ANALYTICS
    # =====================================================================
    
    total_properties = Property.objects.filter(status='active').count()
    
    fines_in_period = Fine.objects.filter(
        issued_date__gte=start,
        issued_date__lte=end
    )
    
    total_fines_amount = fines_in_period.aggregate(
        total=Sum('fine_amount')
    )['total'] or Decimal('0.00')
    
    fines_collected = fines_in_period.filter(
        status='paid'
    ).aggregate(
        total=Sum('fine_amount')
    )['total'] or Decimal('0.00')
    
    # Fines by category
    fines_by_category = fines_in_period.values(
        'category__name'
    ).annotate(
        count=Count('id'),
        amount=Sum('fine_amount')
    ).order_by('-amount')[:10]
    
    fines_category_data = {
        'labels': [item['category__name'] for item in fines_by_category],
        'data': [float(item['amount']) for item in fines_by_category],
        'counts': [item['count'] for item in fines_by_category]
    }
    
    # =====================================================================
    # PERFORMANCE METRICS
    # =====================================================================
    
    # Revenue per citizen
    revenue_per_citizen = total_revenue / total_citizens if total_citizens > 0 else 0
    
    # Average bill amount
    avg_bill_amount = bills_qs.aggregate(avg=Avg('total_amount'))['avg'] or Decimal('0.00')
    
    # Average payment amount
    avg_payment_amount = payments_qs.aggregate(avg=Avg('amount'))['avg'] or Decimal('0.00')
    
    # Top revenue streams
    top_revenue_streams = payments_qs.values(
        'revenue_stream__name',
        'revenue_stream__code'
    ).annotate(
        revenue=Sum('amount'),
        count=Count('id')
    ).order_by('-revenue')[:5]
    
    # =====================================================================
    # FILTER OPTIONS FOR DROPDOWNS
    # =====================================================================
    
    sub_counties = SubCounty.objects.filter(is_active=True).order_by('name')
    wards = Ward.objects.filter(is_active=True).order_by('name')
    if sub_county_id:
        wards = wards.filter(sub_county_id=sub_county_id)
    
    revenue_streams = RevenueStream.objects.filter(is_active=True).order_by('name')
    departments = Department.objects.filter(is_active=True).order_by('name')
    
    # =====================================================================
    # CONTEXT DATA
    # =====================================================================
    
    context = {
        # Filter parameters
        'date_range': date_range,
        'start_date': start.isoformat(),
        'end_date': end.isoformat(),
        'selected_sub_county': sub_county_id,
        'selected_ward': ward_id,
        'selected_revenue_stream': revenue_stream_id,
        'selected_department': department_id,
        
        # Filter options
        'sub_counties': sub_counties,
        'wards': wards,
        'revenue_streams': revenue_streams,
        'departments': departments,
        
        # Summary metrics
        'total_revenue': total_revenue,
        'total_billed': total_billed,
        'outstanding': outstanding,
        'collection_rate': round(collection_rate, 2),
        'revenue_growth': round(revenue_growth, 2),
        'total_bills': total_bills,
        'paid_bills': paid_bills,
        'overdue_bills': overdue_bills,
        'pending_bills': pending_bills,
        'total_citizens': total_citizens,
        'new_citizens': new_citizens,
        'total_licenses': total_licenses,
        'expiring_licenses': expiring_licenses,
        'licenses_issued': licenses_issued,
        'total_patients': total_patients,
        'total_visits': total_visits,
        'active_vehicles': active_vehicles,
        'total_fuel_cost': total_fuel_cost,
        'total_fuel_liters': total_fuel_liters,
        'total_employees': total_employees,
        'total_attendance': total_attendance,
        'total_properties': total_properties,
        'total_fines_amount': total_fines_amount,
        'fines_collected': fines_collected,
        'revenue_per_citizen': round(revenue_per_citizen, 2),
        'avg_bill_amount': avg_bill_amount,
        'avg_payment_amount': avg_payment_amount,
        
        # Top performers
        'top_revenue_streams': top_revenue_streams,
        
        # Chart data (JSON serialized)
        'revenue_trend_data': json.dumps(revenue_trend_data),
        'revenue_stream_data': json.dumps(revenue_stream_data),
        'subcounty_revenue_data': json.dumps(subcounty_revenue_data),
        'payment_method_data': json.dumps(payment_method_data),
        'bills_status_data': json.dumps(bills_status_data),
        'citizen_type_data': json.dumps(citizen_type_data),
        'visits_trend_data': json.dumps(visits_trend_data),
        'facility_visits_data': json.dumps(facility_visits_data),
        'visit_type_data': json.dumps(visit_type_data),
        'license_status_data': json.dumps(license_status_data),
        'business_category_data': json.dumps(business_category_data),
        'fuel_vehicle_data': json.dumps(fuel_vehicle_data),
        'fuel_trend_data': json.dumps(fuel_trend_data),
        'leave_status_data': json.dumps(leave_status_data),
        'fines_category_data': json.dumps(fines_category_data),
    }
    
    return render(request, 'admin/analytics/analytics_dashboard.html', context)


@login_required
def export_analytics_data(request):
    """
    Export analytics data to CSV or Excel
    """
    export_format = request.GET.get('format', 'csv')
    report_type = request.GET.get('type', 'revenue')
    
    # Get same filters as dashboard
    date_range = request.GET.get('date_range', '30')
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    
    # Calculate dates (same logic as above)
    today = timezone.now().date()
    if start_date and end_date:
        start = datetime.strptime(start_date, '%Y-%m-%d').date()
        end = datetime.strptime(end_date, '%Y-%m-%d').date()
    else:
        if date_range == '7':
            start = today - timedelta(days=7)
        elif date_range == '30':
            start = today - timedelta(days=30)
        elif date_range == '90':
            start = today - timedelta(days=90)
        else:
            start = today - timedelta(days=30)
        end = today
    
    if export_format == 'csv':
        return export_to_csv(report_type, start, end)
    else:
        return export_to_excel(report_type, start, end)


def export_to_csv(report_type, start_date, end_date):
    """Export data to CSV"""
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="wajir_{report_type}_{start_date}_{end_date}.csv"'
    
    writer = csv.writer(response)
    
    if report_type == 'revenue':
        # Revenue report
        writer.writerow(['Receipt Number', 'Date', 'Payer', 'Revenue Stream', 'Amount', 'Method', 'Status'])
        
        payments = Payment.objects.filter(
            payment_date__date__gte=start_date,
            payment_date__date__lte=end_date
        ).select_related('revenue_stream', 'payment_method')
        
        for payment in payments:
            writer.writerow([
                payment.receipt_number,
                payment.payment_date.strftime('%Y-%m-%d %H:%M'),
                payment.payer_name,
                payment.revenue_stream.name,
                payment.amount,
                payment.payment_method.name,
                payment.get_status_display()
            ])
    
    elif report_type == 'bills':
        # Bills report
        writer.writerow(['Bill Number', 'Date', 'Citizen', 'Revenue Stream', 'Amount', 'Paid', 'Balance', 'Status'])
        
        bills = Bill.objects.filter(
            bill_date__gte=start_date,
            bill_date__lte=end_date
        ).select_related('citizen', 'revenue_stream')
        
        for bill in bills:
            citizen_name = f"{bill.citizen.first_name} {bill.citizen.last_name}" if bill.citizen.entity_type == 'individual' else bill.citizen.business_name
            writer.writerow([
                bill.bill_number,
                bill.bill_date.strftime('%Y-%m-%d'),
                citizen_name,
                bill.revenue_stream.name,
                bill.total_amount,
                bill.amount_paid,
                bill.balance,
                bill.get_status_display()
            ])
    
    return response


def export_to_excel(report_type, start_date, end_date):
    """Export data to Excel"""
    output = BytesIO()
    workbook = xlsxwriter.Workbook(output)
    worksheet = workbook.add_worksheet(report_type.title())
    
    # Formats
    header_format = workbook.add_format({
        'bold': True,
        'bg_color': '#139145',
        'font_color': 'white',
        'border': 1
    })
    
    money_format = workbook.add_format({'num_format': '#,##0.00'})
    
    if report_type == 'revenue':
        # Headers
        headers = ['Receipt Number', 'Date', 'Payer', 'Revenue Stream', 'Amount', 'Method', 'Status']
        for col, header in enumerate(headers):
            worksheet.write(0, col, header, header_format)
        
        # Data
        payments = Payment.objects.filter(
            payment_date__date__gte=start_date,
            payment_date__date__lte=end_date
        ).select_related('revenue_stream', 'payment_method')
        
        for row, payment in enumerate(payments, start=1):
            worksheet.write(row, 0, payment.receipt_number)
            worksheet.write(row, 1, payment.payment_date.strftime('%Y-%m-%d %H:%M'))
            worksheet.write(row, 2, payment.payer_name)
            worksheet.write(row, 3, payment.revenue_stream.name)
            worksheet.write(row, 4, float(payment.amount), money_format)
            worksheet.write(row, 5, payment.payment_method.name)
            worksheet.write(row, 6, payment.get_status_display())
    
    workbook.close()
    output.seek(0)
    
    response = HttpResponse(
        output.read(),
        content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )
    response['Content-Disposition'] = f'attachment; filename="wajir_{report_type}_{start_date}_{end_date}.xlsx"'
    
    return response

# Optional API View for dynamic ward loading
from django.http import JsonResponse
from .models import Ward

def get_wards_api(request):
    """
    API endpoint to get wards by sub-county
    """
    sub_county_id = request.GET.get('sub_county')
    
    if sub_county_id:
        wards = Ward.objects.filter(
            sub_county_id=sub_county_id,
            is_active=True
        ).values('id', 'name').order_by('name')
        return JsonResponse(list(wards), safe=False)
    
    return JsonResponse([], safe=False)

"""
Revenue Management Views
"""
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db.models import Q, Sum, Count, Avg
from django.http import HttpResponse
from django.utils import timezone
from datetime import datetime, timedelta
from decimal import Decimal
import openpyxl
from openpyxl.styles import Font, Alignment, PatternFill, Border, Side
from openpyxl.utils import get_column_letter

from .models import (
    RevenueStream, ChargeRate, RevenueBudget, Department,
    SubCounty, Ward, Payment, Bill, User
)


# ============================================================================
# REVENUE STREAMS
# ============================================================================

@login_required
def revenue_stream_list(request):
    """Revenue streams list with filtering and search"""
    streams = RevenueStream.objects.all().select_related('department', 'parent_stream')
    
    # Search
    search_query = request.GET.get('search', '')
    if search_query:
        streams = streams.filter(
            Q(name__icontains=search_query) |
            Q(code__icontains=search_query) |
            Q(description__icontains=search_query) |
            Q(department__name__icontains=search_query)
        )
    
    # Filters
    department_id = request.GET.get('department')
    if department_id:
        streams = streams.filter(department_id=department_id)
    
    is_recurring = request.GET.get('is_recurring')
    if is_recurring:
        streams = streams.filter(is_recurring=is_recurring == 'true')
    
    status = request.GET.get('status')
    if status:
        streams = streams.filter(is_active=status == 'active')
    
    # Statistics
    stats = {
        'total': RevenueStream.objects.count(),
        'active': RevenueStream.objects.filter(is_active=True).count(),
        'recurring': RevenueStream.objects.filter(is_recurring=True).count(),
        'non_recurring': RevenueStream.objects.filter(is_recurring=False).count(),
    }
    
    # Get departments for filter
    departments = Department.objects.filter(is_active=True).order_by('name')
    
    context = {
        'streams': streams,
        'stats': stats,
        'departments': departments,
        'search_query': search_query,
        'current_department': department_id,
        'current_recurring': is_recurring,
        'current_status': status,
    }
    
    return render(request, 'revenue/stream_list.html', context)


@login_required
def revenue_stream_detail(request, stream_id):
    """Revenue stream detail view"""
    stream = get_object_or_404(RevenueStream, id=stream_id)
    
    # Get related data
    charge_rates = stream.charge_rates.all().order_by('-effective_from')
    penalty_rules = stream.penalty_rules.all().order_by('-effective_from')
    budgets = stream.budgets.all().order_by('-period_start')
    
    # Collection statistics (last 12 months)
    twelve_months_ago = timezone.now().date() - timedelta(days=365)
    collections = Payment.objects.filter(
        revenue_stream=stream,
        payment_date__gte=twelve_months_ago,
        status='completed'
    ).aggregate(
        total_collected=Sum('amount'),
        transaction_count=Count('id'),
        avg_transaction=Avg('amount')
    )
    
    # Bills statistics
    bills_stats = Bill.objects.filter(revenue_stream=stream).aggregate(
        total_bills=Count('id'),
        total_billed=Sum('bill_amount'),
        total_paid=Sum('amount_paid'),
        outstanding=Sum('balance')
    )
    
    context = {
        'stream': stream,
        'charge_rates': charge_rates,
        'penalty_rules': penalty_rules,
        'budgets': budgets,
        'collections': collections,
        'bills_stats': bills_stats,
    }
    
    return render(request, 'revenue/stream_detail.html', context)


@login_required
def revenue_stream_export(request):
    """Export revenue streams to Excel"""
    streams = RevenueStream.objects.all().select_related('department', 'parent_stream')
    
    # Apply same filters as list view
    search_query = request.GET.get('search', '')
    if search_query:
        streams = streams.filter(
            Q(name__icontains=search_query) |
            Q(code__icontains=search_query)
        )
    
    department_id = request.GET.get('department')
    if department_id:
        streams = streams.filter(department_id=department_id)
    
    # Create workbook
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Revenue Streams"
    
    # Styling
    header_fill = PatternFill(start_color="3498db", end_color="3498db", fill_type="solid")
    header_font = Font(bold=True, color="FFFFFF", size=12)
    border = Border(
        left=Side(style='thin'),
        right=Side(style='thin'),
        top=Side(style='thin'),
        bottom=Side(style='thin')
    )
    
    # Headers
    headers = ['Code', 'Name', 'Department', 'Description', 'Is Recurring', 
               'Billing Frequency', 'Status', 'Created At']
    ws.append(headers)
    
    # Style headers
    for cell in ws[1]:
        cell.fill = header_fill
        cell.font = header_font
        cell.alignment = Alignment(horizontal='center', vertical='center')
        cell.border = border
    
    # Data rows
    for stream in streams:
        ws.append([
            stream.code,
            stream.name,
            stream.department.name,
            stream.description,
            'Yes' if stream.is_recurring else 'No',
            stream.billing_frequency or 'N/A',
            'Active' if stream.is_active else 'Inactive',
            stream.created_at.strftime('%Y-%m-%d %H:%M')
        ])
    
    # Style data rows
    for row in ws.iter_rows(min_row=2, max_row=ws.max_row):
        for cell in row:
            cell.border = border
            cell.alignment = Alignment(vertical='center', wrap_text=True)
    
    # Adjust column widths
    for idx, col in enumerate(ws.columns, 1):
        ws.column_dimensions[get_column_letter(idx)].width = 20
    
    # Create response
    response = HttpResponse(
        content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )
    response['Content-Disposition'] = f'attachment; filename=revenue_streams_{timezone.now().strftime("%Y%m%d_%H%M%S")}.xlsx'
    wb.save(response)
    
    return response


# ============================================================================
# CHARGE RATES
# ============================================================================

@login_required
def charge_rate_list(request):
    """Charge rates list with filtering"""
    rates = ChargeRate.objects.all().select_related('revenue_stream')
    
    # Search
    search_query = request.GET.get('search', '')
    if search_query:
        rates = rates.filter(
            Q(name__icontains=search_query) |
            Q(revenue_stream__name__icontains=search_query) |
            Q(revenue_stream__code__icontains=search_query)
        )
    
    # Filters
    stream_id = request.GET.get('revenue_stream')
    if stream_id:
        rates = rates.filter(revenue_stream_id=stream_id)
    
    rate_type = request.GET.get('rate_type')
    if rate_type:
        rates = rates.filter(rate_type=rate_type)
    
    status = request.GET.get('status')
    if status == 'active':
        today = timezone.now().date()
        rates = rates.filter(
            is_active=True,
            effective_from__lte=today
        ).filter(
            Q(effective_to__isnull=True) | Q(effective_to__gte=today)
        )
    elif status == 'expired':
        today = timezone.now().date()
        rates = rates.filter(effective_to__lt=today)
    elif status == 'future':
        today = timezone.now().date()
        rates = rates.filter(effective_from__gt=today)
    
    # Statistics
    today = timezone.now().date()
    stats = {
        'total': ChargeRate.objects.count(),
        'active': ChargeRate.objects.filter(
            is_active=True,
            effective_from__lte=today
        ).filter(
            Q(effective_to__isnull=True) | Q(effective_to__gte=today)
        ).count(),
        'expired': ChargeRate.objects.filter(effective_to__lt=today).count(),
        'future': ChargeRate.objects.filter(effective_from__gt=today).count(),
    }
    
    # Get revenue streams for filter
    revenue_streams = RevenueStream.objects.filter(is_active=True).order_by('name')
    
    # Get unique rate types
    rate_types = ChargeRate.objects.values_list('rate_type', flat=True).distinct()
    
    context = {
        'rates': rates,
        'stats': stats,
        'revenue_streams': revenue_streams,
        'rate_types': rate_types,
        'search_query': search_query,
        'current_stream': stream_id,
        'current_rate_type': rate_type,
        'current_status': status,
    }
    
    return render(request, 'revenue/charge_rate_list.html', context)


@login_required
def charge_rate_export(request):
    """Export charge rates to Excel"""
    rates = ChargeRate.objects.all().select_related('revenue_stream')
    
    # Apply filters
    stream_id = request.GET.get('revenue_stream')
    if stream_id:
        rates = rates.filter(revenue_stream_id=stream_id)
    
    # Create workbook
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Charge Rates"
    
    # Styling
    header_fill = PatternFill(start_color="3498db", end_color="3498db", fill_type="solid")
    header_font = Font(bold=True, color="FFFFFF", size=12)
    border = Border(
        left=Side(style='thin'),
        right=Side(style='thin'),
        top=Side(style='thin'),
        bottom=Side(style='thin')
    )
    
    # Headers
    headers = ['Revenue Stream', 'Rate Name', 'Rate Type', 'Amount', 
               'Min Amount', 'Max Amount', 'Effective From', 'Effective To', 'Status']
    ws.append(headers)
    
    # Style headers
    for cell in ws[1]:
        cell.fill = header_fill
        cell.font = header_font
        cell.alignment = Alignment(horizontal='center', vertical='center')
        cell.border = border
    
    # Data rows
    today = timezone.now().date()
    for rate in rates:
        is_active = (
            rate.is_active and 
            rate.effective_from <= today and 
            (rate.effective_to is None or rate.effective_to >= today)
        )
        
        ws.append([
            f"{rate.revenue_stream.code} - {rate.revenue_stream.name}",
            rate.name,
            rate.rate_type,
            float(rate.amount),
            float(rate.min_amount) if rate.min_amount else 'N/A',
            float(rate.max_amount) if rate.max_amount else 'N/A',
            rate.effective_from.strftime('%Y-%m-%d'),
            rate.effective_to.strftime('%Y-%m-%d') if rate.effective_to else 'N/A',
            'Active' if is_active else 'Inactive'
        ])
    
    # Style data rows
    for row in ws.iter_rows(min_row=2, max_row=ws.max_row):
        for cell in row:
            cell.border = border
            cell.alignment = Alignment(vertical='center')
    
    # Adjust column widths
    for idx, col in enumerate(ws.columns, 1):
        ws.column_dimensions[get_column_letter(idx)].width = 18
    
    # Create response
    response = HttpResponse(
        content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )
    response['Content-Disposition'] = f'attachment; filename=charge_rates_{timezone.now().strftime("%Y%m%d_%H%M%S")}.xlsx'
    wb.save(response)
    
    return response


# ============================================================================
# REVENUE BUDGETS
# ============================================================================

@login_required
def revenue_budget_list(request):
    """Revenue budgets list with filtering"""
    budgets = RevenueBudget.objects.all().select_related(
        'revenue_stream', 'sub_county', 'ward', 'created_by'
    )
    
    # Search
    search_query = request.GET.get('search', '')
    if search_query:
        budgets = budgets.filter(
            Q(revenue_stream__name__icontains=search_query) |
            Q(revenue_stream__code__icontains=search_query) |
            Q(financial_year__icontains=search_query)
        )
    
    # Filters
    stream_id = request.GET.get('revenue_stream')
    if stream_id:
        budgets = budgets.filter(revenue_stream_id=stream_id)
    
    financial_year = request.GET.get('financial_year')
    if financial_year:
        budgets = budgets.filter(financial_year=financial_year)
    
    period_type = request.GET.get('period_type')
    if period_type:
        budgets = budgets.filter(period_type=period_type)
    
    sub_county_id = request.GET.get('sub_county')
    if sub_county_id:
        budgets = budgets.filter(sub_county_id=sub_county_id)
    
    # Calculate actual collections for each budget
    budgets_with_actual = []
    for budget in budgets:
        actual = Payment.objects.filter(
            revenue_stream=budget.revenue_stream,
            payment_date__gte=budget.period_start,
            payment_date__lte=budget.period_end,
            status='completed'
        )
        
        if budget.sub_county:
            actual = actual.filter(sub_county=budget.sub_county)
        if budget.ward:
            actual = actual.filter(ward=budget.ward)
        
        actual_amount = actual.aggregate(total=Sum('amount'))['total'] or Decimal('0')
        
        budget.actual_amount = actual_amount
        budget.variance = actual_amount - budget.target_amount
        budget.achievement_percentage = (
            (actual_amount / budget.target_amount * 100) 
            if budget.target_amount > 0 else 0
        )
        budgets_with_actual.append(budget)
    
    # Statistics
    total_target = budgets.aggregate(Sum('target_amount'))['target_amount__sum'] or Decimal('0')
    total_actual = sum(b.actual_amount for b in budgets_with_actual)
    
    stats = {
        'total_budgets': budgets.count(),
        'total_target': total_target,
        'total_actual': total_actual,
        'total_variance': total_actual - total_target,
        'achievement_rate': (total_actual / total_target * 100) if total_target > 0 else 0,
    }
    
    # Get filter options
    revenue_streams = RevenueStream.objects.filter(is_active=True).order_by('name')
    financial_years = RevenueBudget.objects.values_list(
        'financial_year', flat=True
    ).distinct().order_by('-financial_year')
    period_types = RevenueBudget.objects.values_list(
        'period_type', flat=True
    ).distinct()
    sub_counties = SubCounty.objects.filter(is_active=True).order_by('name')
    
    context = {
        'budgets': budgets_with_actual,
        'stats': stats,
        'revenue_streams': revenue_streams,
        'financial_years': financial_years,
        'period_types': period_types,
        'sub_counties': sub_counties,
        'search_query': search_query,
        'current_stream': stream_id,
        'current_year': financial_year,
        'current_period': period_type,
        'current_sub_county': sub_county_id,
    }
    
    return render(request, 'revenue/budget_list.html', context)


@login_required
def revenue_budget_export(request):
    """Export revenue budgets to Excel"""
    budgets = RevenueBudget.objects.all().select_related(
        'revenue_stream', 'sub_county', 'ward'
    )
    
    # Apply filters
    stream_id = request.GET.get('revenue_stream')
    if stream_id:
        budgets = budgets.filter(revenue_stream_id=stream_id)
    
    financial_year = request.GET.get('financial_year')
    if financial_year:
        budgets = budgets.filter(financial_year=financial_year)
    
    # Create workbook
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Revenue Budgets"
    
    # Styling
    header_fill = PatternFill(start_color="3498db", end_color="3498db", fill_type="solid")
    header_font = Font(bold=True, color="FFFFFF", size=12)
    border = Border(
        left=Side(style='thin'),
        right=Side(style='thin'),
        top=Side(style='thin'),
        bottom=Side(style='thin')
    )
    
    # Headers
    headers = ['Revenue Stream', 'Financial Year', 'Period Type', 'Period Start', 
               'Period End', 'Target Amount', 'Actual Amount', 'Variance', 
               'Achievement %', 'Sub-County', 'Ward']
    ws.append(headers)
    
    # Style headers
    for cell in ws[1]:
        cell.fill = header_fill
        cell.font = header_font
        cell.alignment = Alignment(horizontal='center', vertical='center')
        cell.border = border
    
    # Data rows
    for budget in budgets:
        # Calculate actual
        actual = Payment.objects.filter(
            revenue_stream=budget.revenue_stream,
            payment_date__gte=budget.period_start,
            payment_date__lte=budget.period_end,
            status='completed'
        )
        
        if budget.sub_county:
            actual = actual.filter(sub_county=budget.sub_county)
        if budget.ward:
            actual = actual.filter(ward=budget.ward)
        
        actual_amount = actual.aggregate(total=Sum('amount'))['total'] or Decimal('0')
        variance = actual_amount - budget.target_amount
        achievement = (actual_amount / budget.target_amount * 100) if budget.target_amount > 0 else 0
        
        ws.append([
            f"{budget.revenue_stream.code} - {budget.revenue_stream.name}",
            budget.financial_year,
            budget.period_type,
            budget.period_start.strftime('%Y-%m-%d'),
            budget.period_end.strftime('%Y-%m-%d'),
            float(budget.target_amount),
            float(actual_amount),
            float(variance),
            f"{achievement:.2f}%",
            budget.sub_county.name if budget.sub_county else 'County-wide',
            budget.ward.name if budget.ward else 'N/A'
        ])
    
    # Style data rows
    for row in ws.iter_rows(min_row=2, max_row=ws.max_row):
        for cell in row:
            cell.border = border
            cell.alignment = Alignment(vertical='center')
    
    # Adjust column widths
    for idx, col in enumerate(ws.columns, 1):
        ws.column_dimensions[get_column_letter(idx)].width = 18
    
    # Create response
    response = HttpResponse(
        content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )
    response['Content-Disposition'] = f'attachment; filename=revenue_budgets_{timezone.now().strftime("%Y%m%d_%H%M%S")}.xlsx'
    wb.save(response)
    
    return response


# ============================================================================
# COLLECTION REPORTS
# ============================================================================

@login_required
def collection_report(request):
    """Comprehensive revenue collection reports"""
    # Date filters
    date_from = request.GET.get('date_from')
    date_to = request.GET.get('date_to')
    
    # Default to current month if no dates provided
    if not date_from or not date_to:
        today = timezone.now().date()
        date_from = today.replace(day=1).strftime('%Y-%m-%d')
        date_to = today.strftime('%Y-%m-%d')
    
    # Parse dates
    start_date = datetime.strptime(date_from, '%Y-%m-%d').date()
    end_date = datetime.strptime(date_to, '%Y-%m-%d').date()
    
    # Base queryset
    payments = Payment.objects.filter(
        payment_date__gte=start_date,
        payment_date__lte=end_date,
        status='completed'
    ).select_related('revenue_stream', 'sub_county', 'ward', 'payment_method')
    
    # Filters
    stream_id = request.GET.get('revenue_stream')
    if stream_id:
        payments = payments.filter(revenue_stream_id=stream_id)
    
    sub_county_id = request.GET.get('sub_county')
    if sub_county_id:
        payments = payments.filter(sub_county_id=sub_county_id)
    
    ward_id = request.GET.get('ward')
    if ward_id:
        payments = payments.filter(ward_id=ward_id)
    
    payment_method_id = request.GET.get('payment_method')
    if payment_method_id:
        payments = payments.filter(payment_method_id=payment_method_id)
    
    # Overall statistics
    overall_stats = payments.aggregate(
        total_amount=Sum('amount'),
        transaction_count=Count('id'),
        average_transaction=Avg('amount')
    )
    
    # By revenue stream
    by_stream = payments.values(
        'revenue_stream__code',
        'revenue_stream__name'
    ).annotate(
        total=Sum('amount'),
        count=Count('id')
    ).order_by('-total')
    
    # By sub-county
    by_sub_county = payments.values(
        'sub_county__name'
    ).annotate(
        total=Sum('amount'),
        count=Count('id')
    ).order_by('-total')
    
    # By payment method
    by_payment_method = payments.values(
        'payment_method__name'
    ).annotate(
        total=Sum('amount'),
        count=Count('id')
    ).order_by('-total')
    
    # Daily collections (for chart)
    daily_collections = payments.extra(
        select={'day': 'DATE(payment_date)'}
    ).values('day').annotate(
        total=Sum('amount'),
        count=Count('id')
    ).order_by('day')
    
    # Get filter options
    revenue_streams = RevenueStream.objects.filter(is_active=True).order_by('name')
    sub_counties = SubCounty.objects.filter(is_active=True).order_by('name')
    wards = Ward.objects.filter(is_active=True).order_by('name')
    from .models import PaymentMethod
    payment_methods = PaymentMethod.objects.filter(is_active=True).order_by('name')
    
    context = {
        'overall_stats': overall_stats,
        'by_stream': by_stream,
        'by_sub_county': by_sub_county,
        'by_payment_method': by_payment_method,
        'daily_collections': daily_collections,
        'revenue_streams': revenue_streams,
        'sub_counties': sub_counties,
        'wards': wards,
        'payment_methods': payment_methods,
        'date_from': date_from,
        'date_to': date_to,
        'current_stream': stream_id,
        'current_sub_county': sub_county_id,
        'current_ward': ward_id,
        'current_payment_method': payment_method_id,
    }
    
    return render(request, 'revenue/collection_report.html', context)


@login_required
def collection_report_export(request):
    """Export collection report to Excel"""
    # Get date filters
    date_from = request.GET.get('date_from')
    date_to = request.GET.get('date_to')
    
    if not date_from or not date_to:
        today = timezone.now().date()
        date_from = today.replace(day=1).strftime('%Y-%m-%d')
        date_to = today.strftime('%Y-%m-%d')
    
    start_date = datetime.strptime(date_from, '%Y-%m-%d').date()
    end_date = datetime.strptime(date_to, '%Y-%m-%d').date()
    
    # Get payments
    payments = Payment.objects.filter(
        payment_date__gte=start_date,
        payment_date__lte=end_date,
        status='completed'
    ).select_related('revenue_stream', 'sub_county', 'payment_method', 'citizen')
    
    # Apply filters
    stream_id = request.GET.get('revenue_stream')
    if stream_id:
        payments = payments.filter(revenue_stream_id=stream_id)
    
    # Create workbook
    wb = openpyxl.Workbook()
    
    # Summary sheet
    ws_summary = wb.active
    ws_summary.title = "Summary"
    
    # Styling
    header_fill = PatternFill(start_color="3498db", end_color="3498db", fill_type="solid")
    header_font = Font(bold=True, color="FFFFFF", size=12)
    title_font = Font(bold=True, size=14)
    
    # Title
    ws_summary['A1'] = 'REVENUE COLLECTION REPORT'
    ws_summary['A1'].font = title_font
    ws_summary['A2'] = f'Period: {date_from} to {date_to}'
    
    # Overall stats
    ws_summary['A4'] = 'Overall Statistics'
    ws_summary['A4'].font = Font(bold=True, size=12)
    
    overall = payments.aggregate(
        total=Sum('amount'),
        count=Count('id'),
        avg=Avg('amount')
    )
    
    ws_summary['A5'] = 'Total Collections:'
    ws_summary['B5'] = float(overall['total'] or 0)
    ws_summary['A6'] = 'Total Transactions:'
    ws_summary['B6'] = overall['count'] or 0
    ws_summary['A7'] = 'Average Transaction:'
    ws_summary['B7'] = float(overall['avg'] or 0)
    
    # Detailed transactions sheet
    ws_detail = wb.create_sheet("Transactions")
    
    headers = ['Receipt No.', 'Date', 'Citizen', 'Revenue Stream', 'Amount', 
               'Payment Method', 'Sub-County', 'Status']
    ws_detail.append(headers)
    
    # Style headers
    for cell in ws_detail[1]:
        cell.fill = header_fill
        cell.font = header_font
        cell.alignment = Alignment(horizontal='center', vertical='center')
    
    # Data rows
    for payment in payments:
        ws_detail.append([
            payment.receipt_number,
            payment.payment_date.strftime('%Y-%m-%d %H:%M'),
            str(payment.citizen),
            f"{payment.revenue_stream.code} - {payment.revenue_stream.name}",
            float(payment.amount),
            payment.payment_method.name,
            payment.sub_county.name if payment.sub_county else 'N/A',
            payment.status
        ])
    
    # Adjust column widths
    for ws in [ws_summary, ws_detail]:
        for idx, col in enumerate(ws.columns, 1):
            ws.column_dimensions[get_column_letter(idx)].width = 20
    
    # Create response
    response = HttpResponse(
        content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )
    response['Content-Disposition'] = f'attachment; filename=collection_report_{timezone.now().strftime("%Y%m%d_%H%M%S")}.xlsx'
    wb.save(response)
    
    return response


"""
Billing Management Views
Handles all billing operations including listing, generation, and reporting
"""

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db.models import Q, Sum, Count, Avg
from django.http import HttpResponse
from django.utils import timezone
from datetime import datetime, timedelta
from decimal import Decimal
import openpyxl
from openpyxl.styles import Font, Alignment, PatternFill, Border, Side
from openpyxl.utils import get_column_letter

# Import models (adjust based on your app structure)
from .models import (
    Bill, BillLineItem, Citizen, RevenueStream, 
    SubCounty, Ward, Payment, ChargeRate
)


@login_required
def bill_list(request):
    """
    Display all bills with filtering and search functionality
    """
    bills = Bill.objects.select_related(
        'citizen', 'revenue_stream', 'sub_county', 'ward', 'created_by'
    ).prefetch_related('line_items', 'payments')
    
    # Search functionality
    search_query = request.GET.get('search', '').strip()
    if search_query:
        bills = bills.filter(
            Q(bill_number__icontains=search_query) |
            Q(citizen__first_name__icontains=search_query) |
            Q(citizen__last_name__icontains=search_query) |
            Q(citizen__business_name__icontains=search_query) |
            Q(revenue_stream__name__icontains=search_query)
        )
    
    # Filters
    status_filter = request.GET.get('status', '')
    if status_filter:
        bills = bills.filter(status=status_filter)
    
    revenue_stream_filter = request.GET.get('revenue_stream', '')
    if revenue_stream_filter:
        bills = bills.filter(revenue_stream_id=revenue_stream_filter)
    
    sub_county_filter = request.GET.get('sub_county', '')
    if sub_county_filter:
        bills = bills.filter(sub_county_id=sub_county_filter)
    
    date_from = request.GET.get('date_from', '')
    date_to = request.GET.get('date_to', '')
    if date_from:
        bills = bills.filter(bill_date__gte=date_from)
    if date_to:
        bills = bills.filter(bill_date__lte=date_to)
    
    # Order by most recent
    bills = bills.order_by('-bill_date', '-created_at')
    
    # Statistics
    stats = {
        'total': bills.count(),
        'draft': bills.filter(status='draft').count(),
        'issued': bills.filter(status='issued').count(),
        'partially_paid': bills.filter(status='partially_paid').count(),
        'paid': bills.filter(status='paid').count(),
        'overdue': bills.filter(status='overdue').count(),
        'cancelled': bills.filter(status='cancelled').count(),
        'total_amount': bills.aggregate(Sum('total_amount'))['total_amount__sum'] or 0,
        'total_paid': bills.aggregate(Sum('amount_paid'))['amount_paid__sum'] or 0,
        'total_balance': bills.aggregate(Sum('balance'))['balance__sum'] or 0,
    }
    
    # Get filter options
    revenue_streams = RevenueStream.objects.filter(is_active=True).order_by('name')
    sub_counties = SubCounty.objects.filter(is_active=True).order_by('name')
    
    context = {
        'bills': bills,
        'stats': stats,
        'search_query': search_query,
        'current_status': status_filter,
        'current_revenue_stream': revenue_stream_filter,
        'current_sub_county': sub_county_filter,
        'date_from': date_from,
        'date_to': date_to,
        'revenue_streams': revenue_streams,
        'sub_counties': sub_counties,
        'bill_statuses': Bill.BILL_STATUS_CHOICES,
    }
    
    return render(request, 'billing/bill_list.html', context)


@login_required
def bill_detail(request, bill_id):
    """
    Display detailed information about a specific bill
    """
    bill = get_object_or_404(
        Bill.objects.select_related(
            'citizen', 'revenue_stream', 'sub_county', 
            'ward', 'created_by'
        ).prefetch_related('line_items', 'payments'),
        id=bill_id
    )
    
    # Get payment history
    payments = bill.payments.select_related('payment_method', 'collected_by').order_by('-payment_date')
    
    context = {
        'bill': bill,
        'payments': payments,
        'line_items': bill.line_items.all(),
    }
    
    return render(request, 'billing/bill_detail.html', context)


@login_required
def generate_bills(request):
    """
    Generate new bills - form and processing
    """
    if request.method == 'POST':
        try:
            # Get form data
            citizen_id = request.POST.get('citizen_id')
            revenue_stream_id = request.POST.get('revenue_stream_id')
            bill_date = request.POST.get('bill_date')
            due_date = request.POST.get('due_date')
            description = request.POST.get('description', '')
            
            citizen = get_object_or_404(Citizen, id=citizen_id)
            revenue_stream = get_object_or_404(RevenueStream, id=revenue_stream_id)
            
            # Generate bill number
            today = timezone.now()
            bill_count = Bill.objects.filter(
                bill_date__year=today.year,
                bill_date__month=today.month
            ).count()
            bill_number = f"BL{today.strftime('%Y%m')}{str(bill_count + 1).zfill(5)}"
            
            # Calculate totals
            bill_amount = Decimal(request.POST.get('bill_amount', '0'))
            penalty_amount = Decimal(request.POST.get('penalty_amount', '0'))
            total_amount = bill_amount + penalty_amount
            
            # Create bill
            bill = Bill.objects.create(
                bill_number=bill_number,
                citizen=citizen,
                revenue_stream=revenue_stream,
                bill_date=bill_date,
                due_date=due_date,
                bill_amount=bill_amount,
                penalty_amount=penalty_amount,
                total_amount=total_amount,
                balance=total_amount,
                status='issued',
                sub_county=citizen.sub_county,
                ward=citizen.ward,
                description=description,
                created_by=request.user
            )
            
            # Create line items
            line_item_descriptions = request.POST.getlist('line_item_description[]')
            line_item_quantities = request.POST.getlist('line_item_quantity[]')
            line_item_unit_prices = request.POST.getlist('line_item_unit_price[]')
            
            for i, desc in enumerate(line_item_descriptions):
                if desc.strip():
                    quantity = Decimal(line_item_quantities[i])
                    unit_price = Decimal(line_item_unit_prices[i])
                    amount = quantity * unit_price
                    
                    BillLineItem.objects.create(
                        bill=bill,
                        description=desc,
                        quantity=quantity,
                        unit_price=unit_price,
                        amount=amount
                    )
            
            messages.success(request, f'Bill {bill_number} generated successfully!')
            return redirect('bill_detail', bill_id=bill.id)
            
        except Exception as e:
            messages.error(request, f'Error generating bill: {str(e)}')
    
    # GET request - show form
    citizens = Citizen.objects.filter(is_active=True).order_by('first_name', 'business_name')
    revenue_streams = RevenueStream.objects.filter(is_active=True).order_by('name')
    charge_rates = ChargeRate.objects.filter(is_active=True).select_related('revenue_stream')
    
    context = {
        'citizens': citizens,
        'revenue_streams': revenue_streams,
        'charge_rates': charge_rates,
    }
    
    return render(request, 'billing/generate_bills.html', context)


@login_required
def overdue_bills(request):
    """
    Display all overdue bills
    """
    today = timezone.now().date()
    
    bills = Bill.objects.select_related(
        'citizen', 'revenue_stream', 'sub_county', 'ward'
    ).filter(
        Q(status='issued') | Q(status='partially_paid'),
        due_date__lt=today
    ).prefetch_related('payments')
    
    # Search functionality
    search_query = request.GET.get('search', '').strip()
    if search_query:
        bills = bills.filter(
            Q(bill_number__icontains=search_query) |
            Q(citizen__first_name__icontains=search_query) |
            Q(citizen__last_name__icontains=search_query) |
            Q(citizen__business_name__icontains=search_query)
        )
    
    # Filters
    revenue_stream_filter = request.GET.get('revenue_stream', '')
    if revenue_stream_filter:
        bills = bills.filter(revenue_stream_id=revenue_stream_filter)
    
    sub_county_filter = request.GET.get('sub_county', '')
    if sub_county_filter:
        bills = bills.filter(sub_county_id=sub_county_filter)
    
    # Calculate days overdue and categorize
    bills_with_overdue = []
    for bill in bills:
        days_overdue = (today - bill.due_date).days
        bill.days_overdue = days_overdue
        
        # Categorize by overdue period
        if days_overdue <= 30:
            bill.overdue_category = '1-30 days'
        elif days_overdue <= 60:
            bill.overdue_category = '31-60 days'
        elif days_overdue <= 90:
            bill.overdue_category = '61-90 days'
        else:
            bill.overdue_category = '90+ days'
        
        bills_with_overdue.append(bill)
    
    # Order by days overdue (most overdue first)
    bills_with_overdue.sort(key=lambda x: x.days_overdue, reverse=True)
    
    # Statistics
    stats = {
        'total': len(bills_with_overdue),
        'total_balance': sum(bill.balance for bill in bills_with_overdue),
        'avg_days_overdue': sum(bill.days_overdue for bill in bills_with_overdue) / len(bills_with_overdue) if bills_with_overdue else 0,
        'overdue_1_30': sum(1 for bill in bills_with_overdue if bill.days_overdue <= 30),
        'overdue_31_60': sum(1 for bill in bills_with_overdue if 31 <= bill.days_overdue <= 60),
        'overdue_61_90': sum(1 for bill in bills_with_overdue if 61 <= bill.days_overdue <= 90),
        'overdue_90_plus': sum(1 for bill in bills_with_overdue if bill.days_overdue > 90),
    }
    
    # Get filter options
    revenue_streams = RevenueStream.objects.filter(is_active=True).order_by('name')
    sub_counties = SubCounty.objects.filter(is_active=True).order_by('name')
    
    context = {
        'bills': bills_with_overdue,
        'stats': stats,
        'search_query': search_query,
        'current_revenue_stream': revenue_stream_filter,
        'current_sub_county': sub_county_filter,
        'revenue_streams': revenue_streams,
        'sub_counties': sub_counties,
    }
    
    return render(request, 'billing/overdue_bills.html', context)


@login_required
def bill_reports(request):
    """
    Display billing reports and analytics
    """
    # Date range filter
    date_from = request.GET.get('date_from', '')
    date_to = request.GET.get('date_to', '')
    
    if not date_from:
        date_from = (timezone.now() - timedelta(days=30)).strftime('%Y-%m-%d')
    if not date_to:
        date_to = timezone.now().strftime('%Y-%m-%d')
    
    bills = Bill.objects.filter(
        bill_date__gte=date_from,
        bill_date__lte=date_to
    ).select_related('revenue_stream', 'sub_county')
    
    # Overall statistics
    overall_stats = {
        'total_bills': bills.count(),
        'total_billed': bills.aggregate(Sum('total_amount'))['total_amount__sum'] or 0,
        'total_collected': bills.aggregate(Sum('amount_paid'))['amount_paid__sum'] or 0,
        'total_outstanding': bills.aggregate(Sum('balance'))['balance__sum'] or 0,
        'collection_rate': 0,
    }
    
    if overall_stats['total_billed'] > 0:
        overall_stats['collection_rate'] = (
            overall_stats['total_collected'] / overall_stats['total_billed'] * 100
        )
    
    # Status breakdown
    status_breakdown = []
    for status_code, status_name in Bill.BILL_STATUS_CHOICES:
        count = bills.filter(status=status_code).count()
        amount = bills.filter(status=status_code).aggregate(
            Sum('total_amount')
        )['total_amount__sum'] or 0
        
        status_breakdown.append({
            'status': status_name,
            'count': count,
            'amount': amount,
        })
    
    # Revenue stream breakdown
    stream_breakdown = bills.values(
        'revenue_stream__code',
        'revenue_stream__name'
    ).annotate(
        bill_count=Count('id'),
        total_billed=Sum('total_amount'),
        total_collected=Sum('amount_paid'),
        outstanding=Sum('balance')
    ).order_by('-total_billed')[:10]
    
    # Sub-county breakdown
    subcounty_breakdown = bills.values(
        'sub_county__name'
    ).annotate(
        bill_count=Count('id'),
        total_billed=Sum('total_amount'),
        total_collected=Sum('amount_paid'),
        outstanding=Sum('balance')
    ).order_by('-total_billed')[:10]
    
    # Monthly trend (last 6 months)
    monthly_trend = []
    for i in range(5, -1, -1):
        date = timezone.now() - timedelta(days=30*i)
        month_start = date.replace(day=1)
        if i == 0:
            month_end = timezone.now()
        else:
            next_month = month_start + timedelta(days=32)
            month_end = next_month.replace(day=1) - timedelta(days=1)
        
        month_bills = Bill.objects.filter(
            bill_date__gte=month_start,
            bill_date__lte=month_end
        )
        
        monthly_trend.append({
            'month': month_start.strftime('%b %Y'),
            'bills': month_bills.count(),
            'billed': month_bills.aggregate(Sum('total_amount'))['total_amount__sum'] or 0,
            'collected': month_bills.aggregate(Sum('amount_paid'))['amount_paid__sum'] or 0,
        })
    
    context = {
        'date_from': date_from,
        'date_to': date_to,
        'overall_stats': overall_stats,
        'status_breakdown': status_breakdown,
        'stream_breakdown': stream_breakdown,
        'subcounty_breakdown': subcounty_breakdown,
        'monthly_trend': monthly_trend,
    }
    
    return render(request, 'billing/bill_reports.html', context)


@login_required
def export_bills_excel(request):
    """
    Export bills to Excel with all filters applied
    """
    # Get filtered bills (same logic as bill_list)
    bills = Bill.objects.select_related(
        'citizen', 'revenue_stream', 'sub_county', 'ward', 'created_by'
    )
    
    # Apply filters
    search_query = request.GET.get('search', '')
    if search_query:
        bills = bills.filter(
            Q(bill_number__icontains=search_query) |
            Q(citizen__first_name__icontains=search_query) |
            Q(citizen__last_name__icontains=search_query) |
            Q(citizen__business_name__icontains=search_query)
        )
    
    status_filter = request.GET.get('status', '')
    if status_filter:
        bills = bills.filter(status=status_filter)
    
    revenue_stream_filter = request.GET.get('revenue_stream', '')
    if revenue_stream_filter:
        bills = bills.filter(revenue_stream_id=revenue_stream_filter)
    
    sub_county_filter = request.GET.get('sub_county', '')
    if sub_county_filter:
        bills = bills.filter(sub_county_id=sub_county_filter)
    
    date_from = request.GET.get('date_from', '')
    date_to = request.GET.get('date_to', '')
    if date_from:
        bills = bills.filter(bill_date__gte=date_from)
    if date_to:
        bills = bills.filter(bill_date__lte=date_to)
    
    bills = bills.order_by('-bill_date')
    
    # Create workbook
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Bills Report"
    
    # Styling
    header_fill = PatternFill(start_color="3498db", end_color="3498db", fill_type="solid")
    header_font = Font(bold=True, color="FFFFFF", size=12)
    border = Border(
        left=Side(style='thin'),
        right=Side(style='thin'),
        top=Side(style='thin'),
        bottom=Side(style='thin')
    )
    
    # Headers
    headers = [
        'Bill Number', 'Bill Date', 'Due Date', 'Citizen/Business', 
        'Revenue Stream', 'Sub County', 'Ward', 'Bill Amount', 
        'Penalty', 'Total Amount', 'Amount Paid', 'Balance', 
        'Status', 'Created By', 'Created At'
    ]
    
    for col_num, header in enumerate(headers, 1):
        cell = ws.cell(row=1, column=col_num)
        cell.value = header
        cell.fill = header_fill
        cell.font = header_font
        cell.alignment = Alignment(horizontal='center', vertical='center')
        cell.border = border
    
    # Data rows
    for row_num, bill in enumerate(bills, 2):
        citizen_name = bill.citizen.business_name if bill.citizen.entity_type == 'business' else f"{bill.citizen.first_name} {bill.citizen.last_name}"
        
        data = [
            bill.bill_number,
            bill.bill_date.strftime('%Y-%m-%d'),
            bill.due_date.strftime('%Y-%m-%d'),
            citizen_name,
            bill.revenue_stream.name,
            bill.sub_county.name if bill.sub_county else '',
            bill.ward.name if bill.ward else '',
            float(bill.bill_amount),
            float(bill.penalty_amount),
            float(bill.total_amount),
            float(bill.amount_paid),
            float(bill.balance),
            bill.get_status_display(),
            bill.created_by.get_full_name() if bill.created_by else '',
            bill.created_at.strftime('%Y-%m-%d %H:%M'),
        ]
        
        for col_num, value in enumerate(data, 1):
            cell = ws.cell(row=row_num, column=col_num)
            cell.value = value
            cell.border = border
            
            # Format currency columns
            if col_num in [8, 9, 10, 11, 12]:
                cell.number_format = '#,##0.00'
    
    # Auto-adjust column widths
    for col in ws.columns:
        max_length = 0
        column = col[0].column_letter
        for cell in col:
            try:
                if len(str(cell.value)) > max_length:
                    max_length = len(cell.value)
            except:
                pass
        adjusted_width = min(max_length + 2, 50)
        ws.column_dimensions[column].width = adjusted_width
    
    # Add summary row
    summary_row = bills.count() + 3
    ws.cell(row=summary_row, column=1, value="TOTALS:").font = Font(bold=True)
    ws.cell(row=summary_row, column=8, value=float(sum(b.bill_amount for b in bills))).number_format = '#,##0.00'
    ws.cell(row=summary_row, column=9, value=float(sum(b.penalty_amount for b in bills))).number_format = '#,##0.00'
    ws.cell(row=summary_row, column=10, value=float(sum(b.total_amount for b in bills))).number_format = '#,##0.00'
    ws.cell(row=summary_row, column=11, value=float(sum(b.amount_paid for b in bills))).number_format = '#,##0.00'
    ws.cell(row=summary_row, column=12, value=float(sum(b.balance for b in bills))).number_format = '#,##0.00'
    
    # Prepare response
    response = HttpResponse(
        content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )
    response['Content-Disposition'] = f'attachment; filename=Bills_Report_{timezone.now().strftime("%Y%m%d_%H%M%S")}.xlsx'
    
    wb.save(response)
    return response


@login_required
def export_overdue_bills_excel(request):
    """
    Export overdue bills to Excel
    """
    today = timezone.now().date()
    
    bills = Bill.objects.select_related(
        'citizen', 'revenue_stream', 'sub_county', 'ward'
    ).filter(
        Q(status='issued') | Q(status='partially_paid'),
        due_date__lt=today
    )
    
    # Apply filters
    search_query = request.GET.get('search', '')
    if search_query:
        bills = bills.filter(
            Q(bill_number__icontains=search_query) |
            Q(citizen__first_name__icontains=search_query) |
            Q(citizen__last_name__icontains=search_query) |
            Q(citizen__business_name__icontains=search_query)
        )
    
    revenue_stream_filter = request.GET.get('revenue_stream', '')
    if revenue_stream_filter:
        bills = bills.filter(revenue_stream_id=revenue_stream_filter)
    
    sub_county_filter = request.GET.get('sub_county', '')
    if sub_county_filter:
        bills = bills.filter(sub_county_id=sub_county_filter)
    
    # Create workbook
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Overdue Bills"
    
    # Styling
    header_fill = PatternFill(start_color="e74c3c", end_color="e74c3c", fill_type="solid")
    header_font = Font(bold=True, color="FFFFFF", size=12)
    border = Border(
        left=Side(style='thin'),
        right=Side(style='thin'),
        top=Side(style='thin'),
        bottom=Side(style='thin')
    )
    
    # Headers
    headers = [
        'Bill Number', 'Citizen/Business', 'Revenue Stream', 
        'Bill Date', 'Due Date', 'Days Overdue', 'Total Amount', 
        'Amount Paid', 'Balance', 'Sub County', 'Contact Phone', 'Status'
    ]
    
    for col_num, header in enumerate(headers, 1):
        cell = ws.cell(row=1, column=col_num)
        cell.value = header
        cell.fill = header_fill
        cell.font = header_font
        cell.alignment = Alignment(horizontal='center', vertical='center')
        cell.border = border
    
    # Data rows
    for row_num, bill in enumerate(bills, 2):
        citizen_name = bill.citizen.business_name if bill.citizen.entity_type == 'business' else f"{bill.citizen.first_name} {bill.citizen.last_name}"
        days_overdue = (today - bill.due_date).days
        
        data = [
            bill.bill_number,
            citizen_name,
            bill.revenue_stream.name,
            bill.bill_date.strftime('%Y-%m-%d'),
            bill.due_date.strftime('%Y-%m-%d'),
            days_overdue,
            float(bill.total_amount),
            float(bill.amount_paid),
            float(bill.balance),
            bill.sub_county.name if bill.sub_county else '',
            bill.citizen.phone_primary,
            bill.get_status_display(),
        ]
        
        for col_num, value in enumerate(data, 1):
            cell = ws.cell(row=row_num, column=col_num)
            cell.value = value
            cell.border = border
            
            # Format currency columns
            if col_num in [7, 8, 9]:
                cell.number_format = '#,##0.00'
            
            # Highlight severely overdue bills
            if col_num == 6 and days_overdue > 90:
                cell.fill = PatternFill(start_color="ffcccc", end_color="ffcccc", fill_type="solid")
    
    # Auto-adjust column widths
    for col in ws.columns:
        max_length = 0
        column = col[0].column_letter
        for cell in col:
            try:
                if len(str(cell.value)) > max_length:
                    max_length = len(cell.value)
            except:
                pass
        adjusted_width = min(max_length + 2, 50)
        ws.column_dimensions[column].width = adjusted_width
    
    # Prepare response
    response = HttpResponse(
        content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )
    response['Content-Disposition'] = f'attachment; filename=Overdue_Bills_{timezone.now().strftime("%Y%m%d_%H%M%S")}.xlsx'
    
    wb.save(response)
    return response


# payments/views.py

from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db.models import Q, Sum, Count, Avg
from django.http import HttpResponse, JsonResponse
from django.utils import timezone
from django.core.paginator import Paginator
from datetime import datetime, timedelta
import openpyxl
from openpyxl.styles import Font, Alignment, PatternFill, Border, Side
from openpyxl.utils import get_column_letter
from decimal import Decimal

from .models import (
    Payment, PaymentMethod, PaymentReversal, BankReconciliation,
    RevenueStream, SubCounty, Ward, Bill, Citizen, User
)


# ============================================================================
# PAYMENT LIST VIEW
# ============================================================================

@login_required
def payment_list(request):
    """Display list of all payments with search, filter, and export"""
    
    # Get all payments
    payments = Payment.objects.select_related(
        'citizen', 'payment_method', 'revenue_stream', 
        'sub_county', 'ward', 'collected_by', 'bill'
    ).order_by('-payment_date')
    
    # Search functionality
    search_query = request.GET.get('search', '').strip()
    if search_query:
        payments = payments.filter(
            Q(receipt_number__icontains=search_query) |
            Q(transaction_reference__icontains=search_query) |
            Q(payer_name__icontains=search_query) |
            Q(payer_phone__icontains=search_query) |
            Q(citizen__first_name__icontains=search_query) |
            Q(citizen__last_name__icontains=search_query) |
            Q(citizen__business_name__icontains=search_query)
        )
    
    # Filters
    status_filter = request.GET.get('status', '')
    if status_filter:
        payments = payments.filter(status=status_filter)
    
    method_filter = request.GET.get('payment_method', '')
    if method_filter:
        payments = payments.filter(payment_method_id=method_filter)
    
    revenue_stream_filter = request.GET.get('revenue_stream', '')
    if revenue_stream_filter:
        payments = payments.filter(revenue_stream_id=revenue_stream_filter)
    
    sub_county_filter = request.GET.get('sub_county', '')
    if sub_county_filter:
        payments = payments.filter(sub_county_id=sub_county_filter)
    
    date_from = request.GET.get('date_from', '')
    if date_from:
        payments = payments.filter(payment_date__gte=date_from)
    
    date_to = request.GET.get('date_to', '')
    if date_to:
        payments = payments.filter(payment_date__lte=date_to)
    
    amount_min = request.GET.get('amount_min', '')
    if amount_min:
        try:
            payments = payments.filter(amount__gte=Decimal(amount_min))
        except:
            pass
    
    amount_max = request.GET.get('amount_max', '')
    if amount_max:
        try:
            payments = payments.filter(amount__lte=Decimal(amount_max))
        except:
            pass
    
    # Calculate statistics
    stats = payments.aggregate(
        total_count=Count('id'),
        total_amount=Sum('amount'),
        avg_amount=Avg('amount'),
        completed_count=Count('id', filter=Q(status='completed')),
        pending_count=Count('id', filter=Q(status='pending')),
        failed_count=Count('id', filter=Q(status='failed')),
        completed_amount=Sum('amount', filter=Q(status='completed'))
    )
    
    # Status breakdown
    status_stats = {
        'completed': payments.filter(status='completed').count(),
        'pending': payments.filter(status='pending').count(),
        'processing': payments.filter(status='processing').count(),
        'failed': payments.filter(status='failed').count(),
        'reversed': payments.filter(status='reversed').count(),
        'cancelled': payments.filter(status='cancelled').count(),
    }
    
    # Export to Excel
    if request.GET.get('export') == 'excel':
        return export_payments_excel(payments, request.GET)
    
    # Pagination
    paginator = Paginator(payments, 50)
    page_number = request.GET.get('page', 1)
    payments_page = paginator.get_page(page_number)
    
    # Get filter options
    payment_methods = PaymentMethod.objects.filter(is_active=True)
    revenue_streams = RevenueStream.objects.filter(is_active=True).select_related('department')
    sub_counties = SubCounty.objects.filter(is_active=True)
    
    context = {
        'payments': payments_page,
        'stats': stats,
        'status_stats': status_stats,
        'search_query': search_query,
        'payment_methods': payment_methods,
        'revenue_streams': revenue_streams,
        'sub_counties': sub_counties,
        'current_status': status_filter,
        'current_method': method_filter,
        'current_stream': revenue_stream_filter,
        'current_sub_county': sub_county_filter,
        'date_from': date_from,
        'date_to': date_to,
        'amount_min': amount_min,
        'amount_max': amount_max,
        'total_records': paginator.count,
    }
    
    return render(request, 'payments/payment_list.html', context)


# ============================================================================
# PAYMENT DETAIL VIEW
# ============================================================================

@login_required
def payment_detail(request, payment_id):
    """Display detailed information about a payment"""
    
    payment = get_object_or_404(
        Payment.objects.select_related(
            'citizen', 'payment_method', 'revenue_stream', 
            'sub_county', 'ward', 'collected_by', 'bill'
        ),
        id=payment_id
    )
    
    # Get payment history/audit trail
    from .models import AuditLog
    audit_logs = AuditLog.objects.filter(
        model_name='Payment',
        object_id=str(payment.id)
    ).select_related('user').order_by('-timestamp')[:20]
    
    # Get reversal if exists
    reversal = PaymentReversal.objects.filter(
        payment=payment
    ).select_related('reversed_by', 'approved_by').first()
    
    # Get related payments (same citizen)
    related_payments = Payment.objects.filter(
        citizen=payment.citizen
    ).exclude(id=payment.id).order_by('-payment_date')[:10]
    
    context = {
        'payment': payment,
        'audit_logs': audit_logs,
        'reversal': reversal,
        'related_payments': related_payments,
    }
    
    return render(request, 'payments/payment_detail.html', context)


# ============================================================================
# PAYMENT UPDATE/EDIT VIEW
# ============================================================================

@login_required
def payment_update(request, payment_id):
    """Update payment information"""
    
    payment = get_object_or_404(Payment, id=payment_id)
    
    # Only allow editing of pending/processing payments
    if payment.status not in ['pending', 'processing']:
        messages.error(request, 'Cannot edit completed or cancelled payments.')
        return redirect('payment_detail', payment_id=payment.id)
    
    if request.method == 'POST':
        # Update payment details
        payment.payer_name = request.POST.get('payer_name', payment.payer_name)
        payment.payer_phone = request.POST.get('payer_phone', payment.payer_phone)
        payment.payer_reference = request.POST.get('payer_reference', payment.payer_reference)
        payment.notes = request.POST.get('notes', payment.notes)
        
        # Update status if changed
        new_status = request.POST.get('status')
        if new_status and new_status != payment.status:
            old_status = payment.status
            payment.status = new_status
            
            # Create audit log
            from .models import AuditLog
            AuditLog.objects.create(
                user=request.user,
                action='update',
                model_name='Payment',
                object_id=str(payment.id),
                object_repr=payment.receipt_number,
                changes={
                    'status': {'old': old_status, 'new': new_status}
                },
                ip_address=request.META.get('REMOTE_ADDR')
            )
        
        payment.save()
        
        messages.success(request, 'Payment updated successfully.')
        return redirect('payment_detail', payment_id=payment.id)
    
    payment_methods = PaymentMethod.objects.filter(is_active=True)
    
    context = {
        'payment': payment,
        'payment_methods': payment_methods,
    }
    
    return render(request, 'payments/payment_update.html', context)


# ============================================================================
# PAYMENT DELETE/CANCEL VIEW
# ============================================================================

@login_required
def payment_delete(request, payment_id):
    """Cancel a payment (soft delete)"""
    
    payment = get_object_or_404(Payment, id=payment_id)
    
    # Only allow cancellation of pending payments
    if payment.status != 'pending':
        messages.error(request, 'Only pending payments can be cancelled.')
        return redirect('payment_detail', payment_id=payment.id)
    
    if request.method == 'POST':
        reason = request.POST.get('cancellation_reason', '')
        
        # Update payment status
        payment.status = 'cancelled'
        payment.notes = f"Cancelled: {reason}\n{payment.notes}"
        payment.save()
        
        # Create audit log
        from .models import AuditLog
        AuditLog.objects.create(
            user=request.user,
            action='delete',
            model_name='Payment',
            object_id=str(payment.id),
            object_repr=payment.receipt_number,
            changes={'reason': reason},
            ip_address=request.META.get('REMOTE_ADDR')
        )
        
        messages.success(request, f'Payment {payment.receipt_number} has been cancelled.')
        return redirect('payment_list')
    
    context = {
        'payment': payment,
    }
    
    return render(request, 'payments/payment_delete.html', context)


# ============================================================================
# PAYMENT METHODS MANAGEMENT
# ============================================================================

@login_required
def payment_method_list(request):
    """List all payment methods"""
    
    payment_methods = PaymentMethod.objects.all().order_by('-is_active', 'name')
    
    # Search
    search_query = request.GET.get('search', '').strip()
    if search_query:
        payment_methods = payment_methods.filter(
            Q(name__icontains=search_query) |
            Q(code__icontains=search_query) |
            Q(provider__icontains=search_query)
        )
    
    # Filter by status
    status_filter = request.GET.get('status', '')
    if status_filter:
        is_active = status_filter == 'active'
        payment_methods = payment_methods.filter(is_active=is_active)
    
    # Get statistics for each method
    for method in payment_methods:
        method.total_transactions = Payment.objects.filter(
            payment_method=method,
            status='completed'
        ).count()
        
        method.total_amount = Payment.objects.filter(
            payment_method=method,
            status='completed'
        ).aggregate(total=Sum('amount'))['total'] or 0
    
    context = {
        'payment_methods': payment_methods,
        'search_query': search_query,
        'current_status': status_filter,
    }
    
    return render(request, 'payments/payment_method_list.html', context)


# ============================================================================
# PAYMENT RECONCILIATION
# ============================================================================

@login_required
def reconciliation_list(request):
    """List bank reconciliation records"""
    
    reconciliations = BankReconciliation.objects.select_related(
        'reconciled_by'
    ).order_by('-reconciliation_date')
    
    # Filter by date range
    date_from = request.GET.get('date_from', '')
    if date_from:
        reconciliations = reconciliations.filter(reconciliation_date__gte=date_from)
    
    date_to = request.GET.get('date_to', '')
    if date_to:
        reconciliations = reconciliations.filter(reconciliation_date__lte=date_to)
    
    # Filter by bank account
    bank_account = request.GET.get('bank_account', '')
    if bank_account:
        reconciliations = reconciliations.filter(bank_account=bank_account)
    
    # Filter by status
    status_filter = request.GET.get('status', '')
    if status_filter:
        is_reconciled = status_filter == 'reconciled'
        reconciliations = reconciliations.filter(is_reconciled=is_reconciled)
    
    # Statistics
    stats = reconciliations.aggregate(
        total_count=Count('id'),
        reconciled_count=Count('id', filter=Q(is_reconciled=True)),
        pending_count=Count('id', filter=Q(is_reconciled=False)),
        total_variance=Sum('variance')
    )
    
    # Get unique bank accounts
    bank_accounts = BankReconciliation.objects.values_list(
        'bank_account', flat=True
    ).distinct()
    
    # Pagination
    paginator = Paginator(reconciliations, 20)
    page_number = request.GET.get('page', 1)
    reconciliations_page = paginator.get_page(page_number)
    
    context = {
        'reconciliations': reconciliations_page,
        'stats': stats,
        'bank_accounts': bank_accounts,
        'date_from': date_from,
        'date_to': date_to,
        'current_bank': bank_account,
        'current_status': status_filter,
    }
    
    return render(request, 'payments/reconciliation_list.html', context)


# ============================================================================
# PAYMENT REVERSALS
# ============================================================================

@login_required
def reversal_list(request):
    """List all payment reversals"""
    
    reversals = PaymentReversal.objects.select_related(
        'payment', 'payment__citizen', 'reversed_by', 'approved_by'
    ).order_by('-created_at')
    
    # Search
    search_query = request.GET.get('search', '').strip()
    if search_query:
        reversals = reversals.filter(
            Q(payment__receipt_number__icontains=search_query) |
            Q(reversal_reason__icontains=search_query)
        )
    
    # Filter by date range
    date_from = request.GET.get('date_from', '')
    if date_from:
        reversals = reversals.filter(created_at__gte=date_from)
    
    date_to = request.GET.get('date_to', '')
    if date_to:
        reversals = reversals.filter(created_at__lte=date_to)
    
    # Statistics
    stats = reversals.aggregate(
        total_count=Count('id'),
        total_amount=Sum('payment__amount')
    )
    
    # Pagination
    paginator = Paginator(reversals, 30)
    page_number = request.GET.get('page', 1)
    reversals_page = paginator.get_page(page_number)
    
    context = {
        'reversals': reversals_page,
        'stats': stats,
        'search_query': search_query,
        'date_from': date_from,
        'date_to': date_to,
    }
    
    return render(request, 'payments/reversal_list.html', context)


@login_required
def payment_reverse(request, payment_id):
    """Reverse a payment"""
    
    payment = get_object_or_404(Payment, id=payment_id)
    
    # Check if payment can be reversed
    if payment.status != 'completed':
        messages.error(request, 'Only completed payments can be reversed.')
        return redirect('payment_detail', payment_id=payment.id)
    
    # Check if already reversed
    if PaymentReversal.objects.filter(payment=payment).exists():
        messages.error(request, 'This payment has already been reversed.')
        return redirect('payment_detail', payment_id=payment.id)
    
    if request.method == 'POST':
        reason = request.POST.get('reversal_reason', '')
        
        if not reason:
            messages.error(request, 'Please provide a reason for reversal.')
            return render(request, 'payments/payment_reverse.html', {'payment': payment})
        
        # Create reversal record
        reversal = PaymentReversal.objects.create(
            payment=payment,
            reversal_reason=reason,
            reversed_by=request.user,
            reversal_amount=payment.amount
        )
        
        # Update payment status
        payment.status = 'reversed'
        payment.save()
        
        # If payment was linked to a bill, update bill
        if payment.bill:
            bill = payment.bill
            bill.amount_paid -= payment.amount
            bill.balance += payment.amount
            
            if bill.balance > 0:
                if bill.status == 'paid':
                    bill.status = 'partially_paid'
            bill.save()
        
        # Create audit log
        from .models import AuditLog
        AuditLog.objects.create(
            user=request.user,
            action='reverse',
            model_name='Payment',
            object_id=str(payment.id),
            object_repr=payment.receipt_number,
            changes={'reason': reason, 'amount': str(payment.amount)},
            ip_address=request.META.get('REMOTE_ADDR')
        )
        
        messages.success(request, f'Payment {payment.receipt_number} has been reversed successfully.')
        return redirect('payment_detail', payment_id=payment.id)
    
    context = {
        'payment': payment,
    }
    
    return render(request, 'payments/payment_reverse.html', context)


from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.views.decorators.http import require_http_methods
from .models import PaymentMethod

@login_required
#@permission_required('your_app.add_paymentmethod', raise_exception=True)
def payment_method_create(request):
    """
    View for creating new payment methods
    """
    if request.method == 'POST':
        try:
            # Extract form data
            name = request.POST.get('name')
            code = request.POST.get('code')
            provider = request.POST.get('provider')
            is_online = request.POST.get('is_online') == 'on'
            is_active = request.POST.get('is_active') == 'on'
            api_endpoint = request.POST.get('api_endpoint', '')
            
            # Basic validation
            if not name or not code or not provider:
                messages.error(request, "Name, Code, and Provider are required fields.")
                return render(request, 'payments/payment_method_create.html', {
                    'form_data': request.POST
                })
            
            # Check for duplicate code
            if PaymentMethod.objects.filter(code=code).exists():
                messages.error(request, f"A payment method with code '{code}' already exists.")
                return render(request, 'payments/payment_method_create.html', {
                    'form_data': request.POST
                })
            
            # Check for duplicate name
            if PaymentMethod.objects.filter(name=name).exists():
                messages.error(request, f"A payment method with name '{name}' already exists.")
                return render(request, 'payments/payment_method_create.html', {
                    'form_data': request.POST
                })
            
            # Create payment method
            payment_method = PaymentMethod.objects.create(
                name=name,
                code=code,
                provider=provider,
                is_online=is_online,
                is_active=is_active,
                api_endpoint=api_endpoint,
                configuration={}  # Empty configuration by default
            )
            
            messages.success(request, f"Payment method '{payment_method.name}' created successfully!")
            return redirect('payment_method_list')  # Redirect to payment method list view
            
        except Exception as e:
            messages.error(request, f"Error creating payment method: {str(e)}")
            return render(request, 'payments/payment_method_create.html', {
                'form_data': request.POST
            })
    
    # GET request - show empty form
    return render(request, 'payments/payment_method_create.html')


@login_required
@permission_required('your_app.view_paymentmethod', raise_exception=True)
def payment_method_detail(request, pk):
    """
    View for displaying payment method details
    """
    try:
        payment_method = get_object_or_404(PaymentMethod, pk=pk)
        
        # Get payment statistics for this method
        payment_stats = Payment.objects.filter(payment_method=payment_method).aggregate(
            total_payments=models.Count('id'),
            total_amount=models.Sum('amount'),
            successful_payments=models.Count('id', filter=models.Q(status='completed')),
            failed_payments=models.Count('id', filter=models.Q(status='failed'))
        )
        
        # Recent payments using this method
        recent_payments = Payment.objects.filter(
            payment_method=payment_method
        ).select_related('citizen', 'bill').order_by('-payment_date')[:10]
        
        context = {
            'method': payment_method,
            'payment_stats': payment_stats,
            'recent_payments': recent_payments,
        }
        
        return render(request, 'payments/payment_method_detail.html', context)
        
    except Exception as e:
        messages.error(request, f"Error loading payment method details: {str(e)}")
        return redirect('payment_method_list')

@login_required
@permission_required('your_app.change_paymentmethod', raise_exception=True)
def payment_method_update(request, pk):
    """
    View for updating payment methods
    """
    payment_method = get_object_or_404(PaymentMethod, pk=pk)
    
    if request.method == 'POST':
        try:
            # Extract form data
            name = request.POST.get('name')
            code = request.POST.get('code')
            provider = request.POST.get('provider')
            is_online = request.POST.get('is_online') == 'on'
            is_active = request.POST.get('is_active') == 'on'
            api_endpoint = request.POST.get('api_endpoint', '')
            
            # Basic validation
            if not name or not code or not provider:
                messages.error(request, "Name, Code, and Provider are required fields.")
                return render(request, 'payments/payment_method_update.html', {
                    'method': payment_method
                })
            
            # Check for duplicate code (excluding current instance)
            if PaymentMethod.objects.filter(code=code).exclude(pk=pk).exists():
                messages.error(request, f"A payment method with code '{code}' already exists.")
                return render(request, 'payments/payment_method_update.html', {
                    'method': payment_method
                })
            
            # Check for duplicate name (excluding current instance)
            if PaymentMethod.objects.filter(name=name).exclude(pk=pk).exists():
                messages.error(request, f"A payment method with name '{name}' already exists.")
                return render(request, 'payments/payment_method_update.html', {
                    'method': payment_method
                })
            
            # Update payment method
            payment_method.name = name
            payment_method.code = code
            payment_method.provider = provider
            payment_method.is_online = is_online
            payment_method.is_active = is_active
            payment_method.api_endpoint = api_endpoint
            payment_method.save()
            
            messages.success(request, f"Payment method '{payment_method.name}' updated successfully!")
            return redirect('payment_method_detail', pk=payment_method.pk)
            
        except Exception as e:
            messages.error(request, f"Error updating payment method: {str(e)}")
            return render(request, 'payments/payment_method_update.html', {
                'method': payment_method
            })
    
    # GET request - show form with current data
    return render(request, 'payments/payment_method_update.html', {
        'method': payment_method
    })

@login_required
@permission_required('your_app.delete_paymentmethod', raise_exception=True)
@require_http_methods(["POST"])
def payment_method_delete(request, pk):
    """
    View for deleting payment methods
    """
    payment_method = get_object_or_404(PaymentMethod, pk=pk)
    
    try:
        # Check if payment method is being used
        payment_count = Payment.objects.filter(payment_method=payment_method).count()
        
        if payment_count > 0:
            messages.error(
                request, 
                f"Cannot delete '{payment_method.name}'. It is being used by {payment_count} payment(s). "
                "Consider deactivating it instead."
            )
            return redirect('payment_method_detail', pk=pk)
        
        method_name = payment_method.name
        payment_method.delete()
        
        messages.success(request, f"Payment method '{method_name}' deleted successfully!")
        return redirect('payment_method_list')
        
    except Exception as e:
        messages.error(request, f"Error deleting payment method: {str(e)}")
        return redirect('payment_method_detail', pk=pk)

@login_required
@permission_required('your_app.change_paymentmethod', raise_exception=True)
@require_http_methods(["POST"])
def payment_method_toggle_active(request, pk):
    """
    View for toggling payment method active status
    """
    payment_method = get_object_or_404(PaymentMethod, pk=pk)
    
    try:
        payment_method.is_active = not payment_method.is_active
        payment_method.save()
        
        status = "activated" if payment_method.is_active else "deactivated"
        messages.success(request, f"Payment method '{payment_method.name}' {status} successfully!")
        
    except Exception as e:
        messages.error(request, f"Error updating payment method status: {str(e)}")
    
    return redirect('payment_method_detail', pk=pk)

# ============================================================================
# EXPORT FUNCTIONS
# ============================================================================

def export_payments_excel(payments, filters):
    """Export payments to Excel"""
    
    # Create workbook
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Payments Report"
    
    # Define styles
    header_font = Font(bold=True, color="FFFFFF", size=12)
    header_fill = PatternFill(start_color="3498db", end_color="3498db", fill_type="solid")
    header_alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
    
    border = Border(
        left=Side(style='thin'),
        right=Side(style='thin'),
        top=Side(style='thin'),
        bottom=Side(style='thin')
    )
    
    # Report header
    ws.merge_cells('A1:N1')
    title_cell = ws['A1']
    title_cell.value = "WAJIR COUNTY GOVERNMENT - PAYMENTS REPORT"
    title_cell.font = Font(bold=True, size=14)
    title_cell.alignment = Alignment(horizontal="center", vertical="center")
    
    # Report info
    ws.merge_cells('A2:N2')
    info_cell = ws['A2']
    info_cell.value = f"Generated on: {timezone.now().strftime('%d/%m/%Y %H:%M')}"
    info_cell.alignment = Alignment(horizontal="center")
    
    # Filter info
    filter_info = []
    if filters.get('date_from'):
        filter_info.append(f"From: {filters['date_from']}")
    if filters.get('date_to'):
        filter_info.append(f"To: {filters['date_to']}")
    if filters.get('status'):
        filter_info.append(f"Status: {filters['status']}")
    
    if filter_info:
        ws.merge_cells('A3:N3')
        filter_cell = ws['A3']
        filter_cell.value = f"Filters: {' | '.join(filter_info)}"
        filter_cell.alignment = Alignment(horizontal="center")
        header_row = 5
    else:
        header_row = 4
    
    # Column headers
    headers = [
        'Receipt No',
        'Transaction Ref',
        'Payment Date',
        'Payer Name',
        'Phone',
        'Payment Method',
        'Revenue Stream',
        'Amount (KES)',
        'Status',
        'Sub County',
        'Ward',
        'Collected By',
        'Bill Number',
        'Notes'
    ]
    
    for col, header in enumerate(headers, start=1):
        cell = ws.cell(row=header_row, column=col)
        cell.value = header
        cell.font = header_font
        cell.fill = header_fill
        cell.alignment = header_alignment
        cell.border = border
    
    # Data rows
    row_num = header_row + 1
    total_amount = 0
    
    for payment in payments:
        ws.cell(row=row_num, column=1, value=payment.receipt_number).border = border
        ws.cell(row=row_num, column=2, value=payment.transaction_reference).border = border
        ws.cell(row=row_num, column=3, value=payment.payment_date.strftime('%d/%m/%Y %H:%M')).border = border
        ws.cell(row=row_num, column=4, value=payment.payer_name).border = border
        ws.cell(row=row_num, column=5, value=payment.payer_phone).border = border
        ws.cell(row=row_num, column=6, value=payment.payment_method.name).border = border
        ws.cell(row=row_num, column=7, value=payment.revenue_stream.name).border = border
        
        amount_cell = ws.cell(row=row_num, column=8, value=float(payment.amount))
        amount_cell.number_format = '#,##0.00'
        amount_cell.border = border
        
        ws.cell(row=row_num, column=9, value=payment.get_status_display()).border = border
        ws.cell(row=row_num, column=10, value=payment.sub_county.name if payment.sub_county else '').border = border
        ws.cell(row=row_num, column=11, value=payment.ward.name if payment.ward else '').border = border
        ws.cell(row=row_num, column=12, value=payment.collected_by.get_full_name() if payment.collected_by else '').border = border
        ws.cell(row=row_num, column=13, value=payment.bill.bill_number if payment.bill else '').border = border
        ws.cell(row=row_num, column=14, value=payment.notes).border = border
        
        total_amount += payment.amount
        row_num += 1
    
    # Total row
    ws.cell(row=row_num, column=7, value="TOTAL:").font = Font(bold=True)
    total_cell = ws.cell(row=row_num, column=8, value=float(total_amount))
    total_cell.font = Font(bold=True)
    total_cell.number_format = '#,##0.00'
    
    # Adjust column widths
    column_widths = [15, 20, 18, 25, 15, 18, 30, 15, 12, 15, 15, 20, 15, 30]
    for i, width in enumerate(column_widths, start=1):
        ws.column_dimensions[get_column_letter(i)].width = width
    
    # Create response
    response = HttpResponse(
        content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )
    response['Content-Disposition'] = f'attachment; filename=payments_report_{timezone.now().strftime("%Y%m%d_%H%M%S")}.xlsx'
    
    wb.save(response)
    return response

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.views.decorators.http import require_http_methods
from django.db import models
from django.utils import timezone
from datetime import timedelta
from .models import Payment, PaymentMethod, RevenueStream, Reconciliation

@login_required
#@permission_required('your_app.add_reconciliation', raise_exception=True)
def reconciliation_create(request):
    """
    View for creating new payment reconciliations
    """
    # Calculate default dates
    today = timezone.now().date()
    default_end_date = today
    default_start_date = today - timedelta(days=7)
    default_reconciliation_date = today
    
    # Get available payment methods and revenue streams
    payment_methods = PaymentMethod.objects.filter(is_active=True)
    revenue_streams = RevenueStream.objects.filter(is_active=True)
    
    if request.method == 'POST':
        try:
            # Extract form data
            reconciliation_date = request.POST.get('reconciliation_date')
            payment_method_id = request.POST.get('payment_method')
            revenue_stream_id = request.POST.get('revenue_stream')
            start_date = request.POST.get('start_date')
            end_date = request.POST.get('end_date')
            notes = request.POST.get('notes', '')
            
            # Basic validation
            if not reconciliation_date or not payment_method_id or not start_date or not end_date:
                messages.error(request, "Please fill in all required fields.")
                return render(request, 'payments/reconciliation_create.html', {
                    'form_data': request.POST,
                    'payment_methods': payment_methods,
                    'revenue_streams': revenue_streams,
                    'default_start_date': default_start_date,
                    'default_end_date': default_end_date,
                    'default_reconciliation_date': default_reconciliation_date,
                })
            
            # Convert dates
            reconciliation_date = timezone.datetime.strptime(reconciliation_date, '%Y-%m-%d').date()
            start_date = timezone.datetime.strptime(start_date, '%Y-%m-%d').date()
            end_date = timezone.datetime.strptime(end_date, '%Y-%m-%d').date()
            
            if start_date > end_date:
                messages.error(request, "Start date cannot be after end date.")
                return render(request, 'payments/reconciliation_create.html', {
                    'form_data': request.POST,
                    'payment_methods': payment_methods,
                    'revenue_streams': revenue_streams,
                    'default_start_date': default_start_date,
                    'default_end_date': default_end_date,
                    'default_reconciliation_date': default_reconciliation_date,
                })
            
            if reconciliation_date < start_date or reconciliation_date > end_date:
                messages.error(request, "Reconciliation date must be within the reconciliation period.")
                return render(request, 'payments/reconciliation_create.html', {
                    'form_data': request.POST,
                    'payment_methods': payment_methods,
                    'revenue_streams': revenue_streams,
                    'default_start_date': default_start_date,
                    'default_end_date': default_end_date,
                    'default_reconciliation_date': default_reconciliation_date,
                })
            
            # Get payment method and revenue stream
            payment_method = get_object_or_404(PaymentMethod, id=payment_method_id, is_active=True)
            revenue_stream = None
            if revenue_stream_id:
                revenue_stream = get_object_or_404(RevenueStream, id=revenue_stream_id, is_active=True)
            
            # Get payments for reconciliation period
            payments = Payment.objects.filter(
                payment_method=payment_method,
                payment_date__date__range=[start_date, end_date],
                status='completed'
            )
            
            if revenue_stream:
                payments = payments.filter(revenue_stream=revenue_stream)
            
            # Calculate totals
            total_payments = payments.count()
            total_amount = payments.aggregate(total=models.Sum('amount'))['total'] or 0
            
            if total_payments == 0:
                messages.warning(request, f"No completed payments found for the selected period and criteria. Do you want to continue?")
                # You might want to add a confirmation step here
            
            # Generate reconciliation number
            last_reconciliation = Reconciliation.objects.order_by('-id').first()
            next_id = last_reconciliation.id + 1 if last_reconciliation else 1
            reconciliation_number = f"REC-{timezone.now().strftime('%Y%m%d')}-{next_id:04d}"
            
            # Create reconciliation
            reconciliation = Reconciliation.objects.create(
                reconciliation_number=reconciliation_number,
                reconciliation_date=reconciliation_date,
                payment_method=payment_method,
                revenue_stream=revenue_stream,
                start_date=start_date,
                end_date=end_date,
                total_payments=total_payments,
                total_amount=total_amount,
                reconciled_amount=0,  # Will be updated during reconciliation process
                discrepancy_amount=0,
                status='draft',
                notes=notes,
                created_by=request.user
            )
            
            # Associate payments with this reconciliation
            payments.update(reconciliation=reconciliation)
            
            messages.success(request, f"Reconciliation {reconciliation_number} created successfully!")
            return redirect('reconciliation_detail', pk=reconciliation.id)
            
        except Exception as e:
            messages.error(request, f"Error creating reconciliation: {str(e)}")
            return render(request, 'payments/reconciliation_create.html', {
                'form_data': request.POST,
                'payment_methods': payment_methods,
                'revenue_streams': revenue_streams,
                'default_start_date': default_start_date,
                'default_end_date': default_end_date,
                'default_reconciliation_date': default_reconciliation_date,
            })
    
    # GET request - show empty form
    context = {
        'payment_methods': payment_methods,
        'revenue_streams': revenue_streams,
        'default_start_date': default_start_date,
        'default_end_date': default_end_date,
        'default_reconciliation_date': default_reconciliation_date,
    }
    
    return render(request, 'payments/reconciliation_create.html', context)


"""
Fleet Management Views - Wajir County ERP
Handles vehicles, fuel, maintenance, and trips management
"""

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.paginator import Paginator
from django.db.models import Q, Sum, Count, Avg
from django.http import HttpResponse
from django.utils import timezone
from datetime import timedelta
from decimal import Decimal
import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side

from .models import (
    FleetVehicle, FuelStation, FuelCard, FuelTransaction,
    VehicleMaintenance, VehicleTrip, Department, SubCounty, User
)


# ============================================================================
# VEHICLES MANAGEMENT
# ============================================================================

@login_required
def vehicle_list(request):
    """List all fleet vehicles with filtering and search"""
    vehicles = FleetVehicle.objects.select_related(
        'department', 'current_driver'
    ).all()
    
    # Search
    search_query = request.GET.get('search', '')
    if search_query:
        vehicles = vehicles.filter(
            Q(fleet_number__icontains=search_query) |
            Q(registration_number__icontains=search_query) |
            Q(make__icontains=search_query) |
            Q(model__icontains=search_query)
        )
    
    # Filters
    vehicle_type = request.GET.get('vehicle_type', '')
    department_id = request.GET.get('department', '')
    status = request.GET.get('status', '')
    fuel_type = request.GET.get('fuel_type', '')
    
    if vehicle_type:
        vehicles = vehicles.filter(vehicle_type=vehicle_type)
    if department_id:
        vehicles = vehicles.filter(department_id=department_id)
    if status:
        vehicles = vehicles.filter(status=status)
    if fuel_type:
        vehicles = vehicles.filter(fuel_type=fuel_type)
    
    # Statistics
    stats = {
        'total': FleetVehicle.objects.count(),
        'active': FleetVehicle.objects.filter(status='active').count(),
        'maintenance': FleetVehicle.objects.filter(status='maintenance').count(),
        'inactive': FleetVehicle.objects.filter(status='inactive').count(),
        'cars': FleetVehicle.objects.filter(vehicle_type='car').count(),
        'trucks': FleetVehicle.objects.filter(vehicle_type='truck').count(),
    }
    
    # Pagination
    paginator = Paginator(vehicles, 25)
    page = request.GET.get('page')
    page_obj = paginator.get_page(page)
    
    # Get departments for filter
    departments = Department.objects.filter(is_active=True)
    
    context = {
        'page_obj': page_obj,
        'stats': stats,
        'search_query': search_query,
        'departments': departments,
        'current_vehicle_type': vehicle_type,
        'current_department': department_id,
        'current_status': status,
        'current_fuel_type': fuel_type,
    }
    
    return render(request, 'fleet/vehicle_list.html', context)


@login_required
def vehicle_detail(request, fleet_number):
    """View vehicle details"""
    vehicle = get_object_or_404(FleetVehicle, fleet_number=fleet_number)
    
    # Get related data
    fuel_transactions = FuelTransaction.objects.filter(
        vehicle=vehicle
    ).select_related('fuel_station', 'driver').order_by('-transaction_date')[:10]
    
    maintenance_records = VehicleMaintenance.objects.filter(
        vehicle=vehicle
    ).select_related('requested_by').order_by('-scheduled_date')[:10]
    
    trips = VehicleTrip.objects.filter(
        vehicle=vehicle
    ).select_related('driver', 'approved_by').order_by('-scheduled_departure')[:10]
    
    # Calculate statistics
    thirty_days_ago = timezone.now() - timedelta(days=30)
    
    fuel_stats = FuelTransaction.objects.filter(
        vehicle=vehicle,
        transaction_date__gte=thirty_days_ago
    ).aggregate(
        total_fuel=Sum('quantity_liters'),
        total_cost=Sum('total_amount'),
        avg_price=Avg('unit_price')
    )
    
    maintenance_stats = VehicleMaintenance.objects.filter(
        vehicle=vehicle,
        completed_date__gte=thirty_days_ago
    ).aggregate(
        total_cost=Sum('cost'),
        count=Count('id')
    )
    
    trip_stats = VehicleTrip.objects.filter(
        vehicle=vehicle,
        actual_departure__gte=thirty_days_ago
    ).count()
    
    context = {
        'vehicle': vehicle,
        'fuel_transactions': fuel_transactions,
        'maintenance_records': maintenance_records,
        'trips': trips,
        'fuel_stats': fuel_stats,
        'maintenance_stats': maintenance_stats,
        'trip_stats': trip_stats,
    }
    
    return render(request, 'fleet/vehicle_detail.html', context)


@login_required
def vehicle_create(request):
    """Create new vehicle"""
    if request.method == 'POST':
        try:
            vehicle = FleetVehicle.objects.create(
                fleet_number=request.POST.get('fleet_number'),
                registration_number=request.POST.get('registration_number'),
                vehicle_type=request.POST.get('vehicle_type'),
                make=request.POST.get('make'),
                model=request.POST.get('model'),
                year=request.POST.get('year'),
                department_id=request.POST.get('department'),
                fuel_type=request.POST.get('fuel_type'),
                engine_capacity=request.POST.get('engine_capacity', ''),
                purchase_date=request.POST.get('purchase_date'),
                purchase_cost=request.POST.get('purchase_cost'),
                insurance_expiry=request.POST.get('insurance_expiry'),
                inspection_due=request.POST.get('inspection_due'),
                current_mileage=request.POST.get('current_mileage', 0),
                has_gps=request.POST.get('has_gps') == 'on',
                gps_device_id=request.POST.get('gps_device_id', ''),
            )
            
            # Assign driver if provided
            driver_id = request.POST.get('current_driver')
            if driver_id:
                vehicle.current_driver_id = driver_id
                vehicle.save()
            
            messages.success(request, f'Vehicle {vehicle.fleet_number} registered successfully!')
            return redirect('vehicle_detail', fleet_number=vehicle.fleet_number)
            
        except Exception as e:
            messages.error(request, f'Error creating vehicle: {str(e)}')
    
    departments = Department.objects.filter(is_active=True)
    drivers = User.objects.filter(is_active=True, is_active_staff=True)
    
    context = {
        'departments': departments,
        'drivers': drivers,
    }
    
    return render(request, 'fleet/vehicle_form.html', context)


@login_required
def vehicle_update(request, fleet_number):
    """Update vehicle details"""
    vehicle = get_object_or_404(FleetVehicle, fleet_number=fleet_number)
    
    if request.method == 'POST':
        try:
            vehicle.registration_number = request.POST.get('registration_number')
            vehicle.vehicle_type = request.POST.get('vehicle_type')
            vehicle.make = request.POST.get('make')
            vehicle.model = request.POST.get('model')
            vehicle.year = request.POST.get('year')
            vehicle.department_id = request.POST.get('department')
            vehicle.fuel_type = request.POST.get('fuel_type')
            vehicle.engine_capacity = request.POST.get('engine_capacity', '')
            vehicle.purchase_date = request.POST.get('purchase_date')
            vehicle.purchase_cost = request.POST.get('purchase_cost')
            vehicle.insurance_expiry = request.POST.get('insurance_expiry')
            vehicle.inspection_due = request.POST.get('inspection_due')
            vehicle.current_mileage = request.POST.get('current_mileage')
            vehicle.status = request.POST.get('status')
            vehicle.has_gps = request.POST.get('has_gps') == 'on'
            vehicle.gps_device_id = request.POST.get('gps_device_id', '')
            
            driver_id = request.POST.get('current_driver')
            vehicle.current_driver_id = driver_id if driver_id else None
            
            vehicle.save()
            
            messages.success(request, 'Vehicle updated successfully!')
            return redirect('vehicle_detail', fleet_number=vehicle.fleet_number)
            
        except Exception as e:
            messages.error(request, f'Error updating vehicle: {str(e)}')
    
    departments = Department.objects.filter(is_active=True)
    drivers = User.objects.filter(is_active=True, is_active_staff=True)
    
    context = {
        'vehicle': vehicle,
        'departments': departments,
        'drivers': drivers,
    }
    
    return render(request, 'fleet/vehicle_form.html', context)


@login_required
def vehicle_delete(request, fleet_number):
    """Delete vehicle"""
    vehicle = get_object_or_404(FleetVehicle, fleet_number=fleet_number)
    
    if request.method == 'POST':
        try:
            vehicle.delete()
            messages.success(request, f'Vehicle {fleet_number} deleted successfully!')
            return redirect('vehicle_list')
        except Exception as e:
            messages.error(request, f'Error deleting vehicle: {str(e)}')
            return redirect('vehicle_detail', fleet_number=fleet_number)
    
    return redirect('vehicle_detail', fleet_number=fleet_number)


@login_required
def vehicle_export_excel(request):
    """Export vehicles to Excel"""
    # Get filtered vehicles
    vehicles = FleetVehicle.objects.select_related('department', 'current_driver').all()
    
    # Apply filters
    vehicle_type = request.GET.get('vehicle_type', '')
    department_id = request.GET.get('department', '')
    status = request.GET.get('status', '')
    
    if vehicle_type:
        vehicles = vehicles.filter(vehicle_type=vehicle_type)
    if department_id:
        vehicles = vehicles.filter(department_id=department_id)
    if status:
        vehicles = vehicles.filter(status=status)
    
    # Create workbook
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = 'Fleet Vehicles'
    
    # Styles
    header_fill = PatternFill(start_color='3498db', end_color='3498db', fill_type='solid')
    header_font = Font(color='FFFFFF', bold=True, size=12)
    border = Border(
        left=Side(style='thin'),
        right=Side(style='thin'),
        top=Side(style='thin'),
        bottom=Side(style='thin')
    )
    
    # Headers
    headers = [
        'Fleet Number', 'Registration Number', 'Vehicle Type', 'Make', 'Model',
        'Year', 'Department', 'Current Driver', 'Fuel Type', 'Status',
        'Current Mileage', 'Insurance Expiry', 'Inspection Due', 'Purchase Cost'
    ]
    
    for col, header in enumerate(headers, 1):
        cell = ws.cell(row=1, column=col, value=header)
        cell.fill = header_fill
        cell.font = header_font
        cell.alignment = Alignment(horizontal='center', vertical='center')
        cell.border = border
    
    # Data
    for row, vehicle in enumerate(vehicles, 2):
        data = [
            vehicle.fleet_number,
            vehicle.registration_number,
            vehicle.get_vehicle_type_display(),
            vehicle.make,
            vehicle.model,
            vehicle.year,
            vehicle.department.name if vehicle.department else '',
            vehicle.current_driver.get_full_name() if vehicle.current_driver else '',
            vehicle.fuel_type,
            vehicle.get_status_display(),
            vehicle.current_mileage,
            vehicle.insurance_expiry.strftime('%Y-%m-%d') if vehicle.insurance_expiry else '',
            vehicle.inspection_due.strftime('%Y-%m-%d') if vehicle.inspection_due else '',
            float(vehicle.purchase_cost),
        ]
        
        for col, value in enumerate(data, 1):
            cell = ws.cell(row=row, column=col, value=value)
            cell.border = border
            if col == 14:  # Purchase cost
                cell.number_format = '#,##0.00'
    
    # Adjust column widths
    for col in ws.columns:
        max_length = 0
        col_letter = col[0].column_letter
        for cell in col:
            if cell.value:
                max_length = max(max_length, len(str(cell.value)))
        ws.column_dimensions[col_letter].width = min(max_length + 2, 50)
    
    # Create response
    response = HttpResponse(
        content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )
    response['Content-Disposition'] = f'attachment; filename=fleet_vehicles_{timezone.now().strftime("%Y%m%d")}.xlsx'
    wb.save(response)
    
    return response


# ============================================================================
# FUEL MANAGEMENT
# ============================================================================

@login_required
def fuel_transaction_list(request):
    """List fuel transactions"""
    transactions = FuelTransaction.objects.select_related(
        'vehicle', 'fuel_station', 'driver', 'fuel_card'
    ).all()
    
    # Search
    search_query = request.GET.get('search', '')
    if search_query:
        transactions = transactions.filter(
            Q(transaction_number__icontains=search_query) |
            Q(vehicle__registration_number__icontains=search_query) |
            Q(vehicle__fleet_number__icontains=search_query)
        )
    
    # Filters
    vehicle_id = request.GET.get('vehicle', '')
    fuel_station_id = request.GET.get('fuel_station', '')
    transaction_type = request.GET.get('transaction_type', '')
    date_from = request.GET.get('date_from', '')
    date_to = request.GET.get('date_to', '')
    
    if vehicle_id:
        transactions = transactions.filter(vehicle_id=vehicle_id)
    if fuel_station_id:
        transactions = transactions.filter(fuel_station_id=fuel_station_id)
    if transaction_type:
        transactions = transactions.filter(transaction_type=transaction_type)
    if date_from:
        transactions = transactions.filter(transaction_date__gte=date_from)
    if date_to:
        transactions = transactions.filter(transaction_date__lte=date_to)
    
    # Statistics
    thirty_days_ago = timezone.now() - timedelta(days=30)
    stats = FuelTransaction.objects.filter(
        transaction_date__gte=thirty_days_ago
    ).aggregate(
        total_transactions=Count('id'),
        total_liters=Sum('quantity_liters'),
        total_amount=Sum('total_amount'),
        avg_price=Avg('unit_price')
    )
    
    # Pagination
    paginator = Paginator(transactions, 25)
    page = request.GET.get('page')
    page_obj = paginator.get_page(page)
    
    vehicles = FleetVehicle.objects.filter(status='active')
    fuel_stations = FuelStation.objects.filter(is_active=True)
    
    context = {
        'page_obj': page_obj,
        'stats': stats,
        'search_query': search_query,
        'vehicles': vehicles,
        'fuel_stations': fuel_stations,
        'current_vehicle': vehicle_id,
        'current_fuel_station': fuel_station_id,
        'current_transaction_type': transaction_type,
        'date_from': date_from,
        'date_to': date_to,
    }
    
    return render(request, 'fleet/fuel_transaction_list.html', context)


@login_required
def fuel_transaction_create(request):
    """Create fuel transaction"""
    if request.method == 'POST':
        try:
            # Generate transaction number
            last_transaction = FuelTransaction.objects.order_by('-id').first()
            if last_transaction:
                last_num = int(last_transaction.transaction_number.split('-')[-1])
                transaction_number = f'FT-{timezone.now().year}-{last_num + 1:06d}'
            else:
                transaction_number = f'FT-{timezone.now().year}-000001'
            
            quantity = Decimal(request.POST.get('quantity_liters'))
            unit_price = Decimal(request.POST.get('unit_price'))
            total_amount = quantity * unit_price
            
            transaction = FuelTransaction.objects.create(
                transaction_number=transaction_number,
                vehicle_id=request.POST.get('vehicle'),
                fuel_station_id=request.POST.get('fuel_station'),
                transaction_type=request.POST.get('transaction_type'),
                transaction_date=request.POST.get('transaction_date'),
                quantity_liters=quantity,
                unit_price=unit_price,
                total_amount=total_amount,
                mileage=request.POST.get('mileage'),
                driver_id=request.POST.get('driver'),
                receipt_number=request.POST.get('receipt_number', ''),
                notes=request.POST.get('notes', ''),
            )
            
            # Update vehicle mileage
            vehicle = transaction.vehicle
            vehicle.current_mileage = transaction.mileage
            vehicle.save()
            
            messages.success(request, f'Fuel transaction {transaction_number} recorded successfully!')
            return redirect('fuel_transaction_list')
            
        except Exception as e:
            messages.error(request, f'Error creating transaction: {str(e)}')
    
    vehicles = FleetVehicle.objects.filter(status='active')
    fuel_stations = FuelStation.objects.filter(is_active=True)
    drivers = User.objects.filter(is_active=True, is_active_staff=True)
    
    context = {
        'vehicles': vehicles,
        'fuel_stations': fuel_stations,
        'drivers': drivers,
    }
    
    return render(request, 'fleet/fuel_transaction_form.html', context)


@login_required
def fuel_export_excel(request):
    """Export fuel transactions to Excel"""
    transactions = FuelTransaction.objects.select_related(
        'vehicle', 'fuel_station', 'driver'
    ).all()
    
    # Apply filters
    date_from = request.GET.get('date_from', '')
    date_to = request.GET.get('date_to', '')
    
    if date_from:
        transactions = transactions.filter(transaction_date__gte=date_from)
    if date_to:
        transactions = transactions.filter(transaction_date__lte=date_to)
    
    # Create workbook
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = 'Fuel Transactions'
    
    # Styles
    header_fill = PatternFill(start_color='3498db', end_color='3498db', fill_type='solid')
    header_font = Font(color='FFFFFF', bold=True, size=12)
    border = Border(
        left=Side(style='thin'),
        right=Side(style='thin'),
        top=Side(style='thin'),
        bottom=Side(style='thin')
    )
    
    # Headers
    headers = [
        'Transaction Number', 'Date', 'Vehicle', 'Registration', 'Fuel Station',
        'Type', 'Quantity (L)', 'Unit Price', 'Total Amount', 'Mileage',
        'Driver', 'Receipt Number'
    ]
    
    for col, header in enumerate(headers, 1):
        cell = ws.cell(row=1, column=col, value=header)
        cell.fill = header_fill
        cell.font = header_font
        cell.alignment = Alignment(horizontal='center', vertical='center')
        cell.border = border
    
    # Data
    for row, trans in enumerate(transactions, 2):
        data = [
            trans.transaction_number,
            trans.transaction_date.strftime('%Y-%m-%d %H:%M'),
            trans.vehicle.fleet_number,
            trans.vehicle.registration_number,
            trans.fuel_station.name,
            trans.get_transaction_type_display(),
            float(trans.quantity_liters),
            float(trans.unit_price),
            float(trans.total_amount),
            trans.mileage,
            trans.driver.get_full_name() if trans.driver else '',
            trans.receipt_number,
        ]
        
        for col, value in enumerate(data, 1):
            cell = ws.cell(row=row, column=col, value=value)
            cell.border = border
            if col in [7, 8, 9]:  # Numeric columns
                cell.number_format = '#,##0.00'
    
    # Adjust column widths
    for col in ws.columns:
        max_length = 0
        col_letter = col[0].column_letter
        for cell in col:
            if cell.value:
                max_length = max(max_length, len(str(cell.value)))
        ws.column_dimensions[col_letter].width = min(max_length + 2, 50)
    
    # Create response
    response = HttpResponse(
        content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )
    response['Content-Disposition'] = f'attachment; filename=fuel_transactions_{timezone.now().strftime("%Y%m%d")}.xlsx'
    wb.save(response)
    
    return response


# ============================================================================
# MAINTENANCE MANAGEMENT
# ============================================================================

@login_required
def maintenance_list(request):
    """List maintenance records"""
    maintenance = VehicleMaintenance.objects.select_related(
        'vehicle', 'requested_by'
    ).all()
    
    # Search
    search_query = request.GET.get('search', '')
    if search_query:
        maintenance = maintenance.filter(
            Q(maintenance_number__icontains=search_query) |
            Q(vehicle__registration_number__icontains=search_query) |
            Q(vehicle__fleet_number__icontains=search_query)
        )
    
    # Filters
    vehicle_id = request.GET.get('vehicle', '')
    maintenance_type = request.GET.get('maintenance_type', '')
    status = request.GET.get('status', '')
    
    if vehicle_id:
        maintenance = maintenance.filter(vehicle_id=vehicle_id)
    if maintenance_type:
        maintenance = maintenance.filter(maintenance_type=maintenance_type)
    if status:
        maintenance = maintenance.filter(status=status)
    
    # Statistics
    stats = {
        'total': VehicleMaintenance.objects.count(),
        'scheduled': VehicleMaintenance.objects.filter(status='scheduled').count(),
        'in_progress': VehicleMaintenance.objects.filter(status='in_progress').count(),
        'completed': VehicleMaintenance.objects.filter(status='completed').count(),
        'total_cost': VehicleMaintenance.objects.filter(
            status='completed'
        ).aggregate(Sum('cost'))['cost__sum'] or 0,
    }
    
    # Pagination
    paginator = Paginator(maintenance, 25)
    page = request.GET.get('page')
    page_obj = paginator.get_page(page)
    
    vehicles = FleetVehicle.objects.all()
    
    context = {
        'page_obj': page_obj,
        'stats': stats,
        'search_query': search_query,
        'vehicles': vehicles,
        'current_vehicle': vehicle_id,
        'current_maintenance_type': maintenance_type,
        'current_status': status,
    }
    
    return render(request, 'fleet/maintenance_list.html', context)


@login_required
def maintenance_create(request):
    """Create maintenance record"""
    if request.method == 'POST':
        try:
            # Generate maintenance number
            last_maintenance = VehicleMaintenance.objects.order_by('-id').first()
            if last_maintenance:
                last_num = int(last_maintenance.maintenance_number.split('-')[-1])
                maintenance_number = f'MT-{timezone.now().year}-{last_num + 1:06d}'
            else:
                maintenance_number = f'MT-{timezone.now().year}-000001'
            
            maintenance = VehicleMaintenance.objects.create(
                maintenance_number=maintenance_number,
                vehicle_id=request.POST.get('vehicle'),
                maintenance_type=request.POST.get('maintenance_type'),
                description=request.POST.get('description'),
                scheduled_date=request.POST.get('scheduled_date'),
                service_provider=request.POST.get('service_provider'),
                cost=request.POST.get('cost'),
                mileage=request.POST.get('mileage'),
                requested_by=request.user,
            )
            
            messages.success(request, f'Maintenance {maintenance_number} scheduled successfully!')
            return redirect('maintenance_list')
            
        except Exception as e:
            messages.error(request, f'Error creating maintenance record: {str(e)}')
    
    vehicles = FleetVehicle.objects.all()
    
    context = {
        'vehicles': vehicles,
    }
    
    return render(request, 'fleet/maintenance_form.html', context)


@login_required
def maintenance_update(request, maintenance_number):
    """Update maintenance record"""
    maintenance = get_object_or_404(VehicleMaintenance, maintenance_number=maintenance_number)
    
    if request.method == 'POST':
        try:
            maintenance.vehicle_id = request.POST.get('vehicle')
            maintenance.maintenance_type = request.POST.get('maintenance_type')
            maintenance.description = request.POST.get('description')
            maintenance.scheduled_date = request.POST.get('scheduled_date')
            maintenance.service_provider = request.POST.get('service_provider')
            maintenance.cost = request.POST.get('cost')
            maintenance.mileage = request.POST.get('mileage')
            maintenance.status = request.POST.get('status')
            
            if request.POST.get('completed_date'):
                maintenance.completed_date = request.POST.get('completed_date')
            
            maintenance.save()
            
            messages.success(request, 'Maintenance record updated successfully!')
            return redirect('maintenance_list')
            
        except Exception as e:
            messages.error(request, f'Error updating maintenance record: {str(e)}')
    
    vehicles = FleetVehicle.objects.all()
    
    context = {
        'maintenance': maintenance,
        'vehicles': vehicles,
    }
    
    return render(request, 'fleet/maintenance_form.html', context)


@login_required
def maintenance_delete(request, maintenance_number):
    """Delete maintenance record"""
    maintenance = get_object_or_404(VehicleMaintenance, maintenance_number=maintenance_number)
    
    if request.method == 'POST':
        try:
            maintenance.delete()
            messages.success(request, f'Maintenance record {maintenance_number} deleted successfully!')
            return redirect('maintenance_list')
        except Exception as e:
            messages.error(request, f'Error deleting maintenance record: {str(e)}')
    
    return redirect('maintenance_list')


# ============================================================================
# TRIPS & WORK TICKETS
# ============================================================================

@login_required
def trip_list(request):
    """List vehicle trips"""
    trips = VehicleTrip.objects.select_related(
        'vehicle', 'driver', 'approved_by'
    ).all()
    
    # Search
    search_query = request.GET.get('search', '')
    if search_query:
        trips = trips.filter(
            Q(trip_number__icontains=search_query) |
            Q(vehicle__registration_number__icontains=search_query) |
            Q(destination__icontains=search_query)
        )
    
    # Filters
    vehicle_id = request.GET.get('vehicle', '')
    status = request.GET.get('status', '')
    
    if vehicle_id:
        trips = trips.filter(vehicle_id=vehicle_id)
    if status:
        trips = trips.filter(status=status)
    
    # Statistics
    stats = {
        'total': VehicleTrip.objects.count(),
        'scheduled': VehicleTrip.objects.filter(status='scheduled').count(),
        'in_progress': VehicleTrip.objects.filter(status='in_progress').count(),
        'completed': VehicleTrip.objects.filter(status='completed').count(),
    }
    
    # Pagination
    paginator = Paginator(trips, 25)
    page = request.GET.get('page')
    page_obj = paginator.get_page(page)
    
    vehicles = FleetVehicle.objects.filter(status='active')
    
    context = {
        'page_obj': page_obj,
        'stats': stats,
        'search_query': search_query,
        'vehicles': vehicles,
        'current_vehicle': vehicle_id,
        'current_status': status,
    }
    
    return render(request, 'fleet/trip_list.html', context)


@login_required
def trip_create(request):
    """Create trip/work ticket"""
    if request.method == 'POST':
        try:
            # Generate trip number
            last_trip = VehicleTrip.objects.order_by('-id').first()
            if last_trip:
                last_num = int(last_trip.trip_number.split('-')[-1])
                trip_number = f'WT-{timezone.now().year}-{last_num + 1:06d}'
            else:
                trip_number = f'WT-{timezone.now().year}-000001'
            
            trip = VehicleTrip.objects.create(
                trip_number=trip_number,
                vehicle_id=request.POST.get('vehicle'),
                driver_id=request.POST.get('driver'),
                purpose=request.POST.get('purpose'),
                destination=request.POST.get('destination'),
                scheduled_departure=request.POST.get('scheduled_departure'),
                scheduled_return=request.POST.get('scheduled_return'),
                start_mileage=request.POST.get('start_mileage'),
                notes=request.POST.get('notes', ''),
            )
            
            messages.success(request, f'Work ticket {trip_number} created successfully!')
            return redirect('trip_list')
            
        except Exception as e:
            messages.error(request, f'Error creating work ticket: {str(e)}')
    
    vehicles = FleetVehicle.objects.filter(status='active')
    drivers = User.objects.filter(is_active=True, is_active_staff=True)
    
    context = {
        'vehicles': vehicles,
        'drivers': drivers,
    }
    
    return render(request, 'fleet/trip_form.html', context)


@login_required
def trip_update(request, trip_number):
    """Update trip/work ticket"""
    trip = get_object_or_404(VehicleTrip, trip_number=trip_number)
    
    if request.method == 'POST':
        try:
            trip.vehicle_id = request.POST.get('vehicle')
            trip.driver_id = request.POST.get('driver')
            trip.purpose = request.POST.get('purpose')
            trip.destination = request.POST.get('destination')
            trip.scheduled_departure = request.POST.get('scheduled_departure')
            trip.scheduled_return = request.POST.get('scheduled_return')
            trip.start_mileage = request.POST.get('start_mileage')
            trip.status = request.POST.get('status')
            trip.notes = request.POST.get('notes', '')
            
            if request.POST.get('actual_departure'):
                trip.actual_departure = request.POST.get('actual_departure')
            if request.POST.get('actual_return'):
                trip.actual_return = request.POST.get('actual_return')
            if request.POST.get('end_mileage'):
                trip.end_mileage = request.POST.get('end_mileage')
            
            trip.save()
            
            # Update vehicle mileage if trip completed
            if trip.status == 'completed' and trip.end_mileage:
                vehicle = trip.vehicle
                vehicle.current_mileage = trip.end_mileage
                vehicle.save()
            
            messages.success(request, 'Work ticket updated successfully!')
            return redirect('trip_list')
            
        except Exception as e:
            messages.error(request, f'Error updating work ticket: {str(e)}')
    
    vehicles = FleetVehicle.objects.filter(status='active')
    drivers = User.objects.filter(is_active=True, is_active_staff=True)
    
    context = {
        'trip': trip,
        'vehicles': vehicles,
        'drivers': drivers,
    }
    
    return render(request, 'fleet/trip_form.html', context)


@login_required
def trip_delete(request, trip_number):
    """Delete trip/work ticket"""
    trip = get_object_or_404(VehicleTrip, trip_number=trip_number)
    
    if request.method == 'POST':
        try:
            trip.delete()
            messages.success(request, f'Work ticket {trip_number} deleted successfully!')
            return redirect('trip_list')
        except Exception as e:
            messages.error(request, f'Error deleting work ticket: {str(e)}')
    
    return redirect('trip_list')