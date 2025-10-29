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