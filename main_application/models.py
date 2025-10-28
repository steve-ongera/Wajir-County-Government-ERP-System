"""
Wajir County Government ERP System - Django Models
Complete model structure for all modules with __str__ methods
"""

from django.db import models
from django.contrib.auth.models import AbstractUser
from django.contrib.gis.db import models as gis_models
from django.core.validators import MinValueValidator, MaxValueValidator
from decimal import Decimal


from django.core.validators import MinValueValidator, MaxValueValidator, RegexValidator
from django.utils import timezone
from datetime import timedelta
import uuid
import random
import string


# ============================================================================
# CORE MODELS - User Management & Authentication
# ============================================================================

class User(AbstractUser):
    """Extended user model with county-specific fields"""
    employee_number = models.CharField(max_length=50, unique=True, null=True, blank=True)
    phone_number = models.CharField(max_length=15, unique=True)
    id_number = models.CharField(max_length=20, unique=True, null=True, blank=True)
    department = models.ForeignKey('Department', on_delete=models.SET_NULL, null=True, blank=True)
    sub_county = models.ForeignKey('SubCounty', on_delete=models.SET_NULL, null=True, blank=True)
    is_active_staff = models.BooleanField(default=True)
    biometric_id = models.CharField(max_length=100, unique=True, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'users'

    def __str__(self):
        return f"{self.get_full_name()} ({self.username})"


class Role(models.Model):
    """Role-based access control"""
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField()
    permissions = models.ManyToManyField('Permission', related_name='roles')
    parent_role = models.ForeignKey('self', on_delete=models.CASCADE, null=True, blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'roles'

    def __str__(self):
        return self.name


class Permission(models.Model):
    """System permissions"""
    name = models.CharField(max_length=100, unique=True)
    codename = models.CharField(max_length=100, unique=True)
    module = models.CharField(max_length=100)
    description = models.TextField()

    class Meta:
        db_table = 'permissions'

    def __str__(self):
        return f"{self.name} ({self.module})"


class UserRole(models.Model):
    """User role assignment with time tracking"""
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    role = models.ForeignKey(Role, on_delete=models.CASCADE)
    assigned_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='role_assignments')
    assigned_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        db_table = 'user_roles'
        unique_together = ['user', 'role']

    def __str__(self):
        return f"{self.user.username} - {self.role.name}"

class LoginAttempt(models.Model):
    """
    Track login attempts for security purposes
    """
    username = models.CharField(max_length=150)
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField(auto_now_add=True)
    success = models.BooleanField(default=False)
    user_agent = models.TextField(blank=True, null=True)
    
    class Meta:
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"Login attempt for {self.username} at {self.timestamp}"


class AccountLock(models.Model):
    """
    Track locked accounts
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='account_lock')
    locked_at = models.DateTimeField(auto_now_add=True)
    failed_attempts = models.PositiveIntegerField(default=0)
    last_attempt_ip = models.GenericIPAddressField(null=True, blank=True)
    unlock_time = models.DateTimeField(null=True, blank=True)
    is_locked = models.BooleanField(default=True)
    
    def is_account_locked(self):
        if not self.is_locked:
            return False
        if self.unlock_time and timezone.now() > self.unlock_time:
            self.is_locked = False
            self.save()
            return False
        return True
    
    def __str__(self):
        return f"Account lock for {self.user.username}"


class TwoFactorCode(models.Model):
    """
    Store 2FA verification codes
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='tfa_codes')
    code = models.CharField(max_length=7)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used = models.BooleanField(default=False)
    used_at = models.DateTimeField(null=True, blank=True)
    ip_address = models.GenericIPAddressField()
    session_key = models.CharField(max_length=40)
    
    def save(self, *args, **kwargs):
        if not self.code:
            digits = ''.join(random.choices(string.digits, k=6))
            self.code = f"{digits[:3]}-{digits[3:]}"
        
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(minutes=2)
        
        super().save(*args, **kwargs)
    
    def is_expired(self):
        return timezone.now() > self.expires_at
    
    def is_valid(self):
        return not self.used and not self.is_expired()
    
    def mark_as_used(self):
        self.used = True
        self.used_at = timezone.now()
        self.save()
    
    def time_remaining(self):
        if self.is_expired():
            return 0
        return int((self.expires_at - timezone.now()).total_seconds())
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"2FA Code for {self.user.username} - {self.code}"


class SecurityNotification(models.Model):
    """
    Security-related notifications sent to users
    """
    NOTIFICATION_TYPES = (
        ('failed_login', 'Failed Login Attempt'),
        ('account_locked', 'Account Locked'),
        ('tfa_code', '2FA Code'),
        ('successful_login', 'Successful Login'),
        ('account_unlocked', 'Account Unlocked'),
    )
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='security_notifications')
    notification_type = models.CharField(max_length=20, choices=NOTIFICATION_TYPES)
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField(auto_now_add=True)
    message = models.TextField()
    email_sent = models.BooleanField(default=False)
    email_sent_at = models.DateTimeField(null=True, blank=True)
    
    def __str__(self):
        return f"{self.get_notification_type_display()} for {self.user.username}"

# ============================================================================
# ADMINISTRATIVE STRUCTURE
# ============================================================================

class County(models.Model):
    """County information"""
    name = models.CharField(max_length=100, unique=True)
    code = models.CharField(max_length=10, unique=True)
    county_number = models.IntegerField(unique=True)
    headquarters = models.CharField(max_length=100)
    area_sq_km = models.DecimalField(max_digits=10, decimal_places=2)
    boundary = gis_models.MultiPolygonField(null=True, blank=True)
    logo = models.ImageField(upload_to='county/logos/', null=True, blank=True)
    
    class Meta:
        db_table = 'counties'
        verbose_name_plural = 'counties'

    def __str__(self):
        return self.name


class SubCounty(models.Model):
    """Sub-county administrative divisions"""
    county = models.ForeignKey(County, on_delete=models.CASCADE, related_name='sub_counties')
    name = models.CharField(max_length=100)
    code = models.CharField(max_length=20, unique=True)
    headquarters = models.CharField(max_length=100)
    boundary = gis_models.MultiPolygonField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'sub_counties'
        unique_together = ['county', 'name']

    def __str__(self):
        return f"{self.name} - {self.county.name}"


class Ward(models.Model):
    """Ward administrative divisions"""
    sub_county = models.ForeignKey(SubCounty, on_delete=models.CASCADE, related_name='wards')
    name = models.CharField(max_length=100)
    code = models.CharField(max_length=20, unique=True)
    boundary = gis_models.MultiPolygonField(null=True, blank=True)
    population = models.IntegerField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'wards'
        unique_together = ['sub_county', 'name']

    def __str__(self):
        return f"{self.name} - {self.sub_county.name}"


class Department(models.Model):
    """County departments"""
    name = models.CharField(max_length=200, unique=True)
    code = models.CharField(max_length=20, unique=True)
    description = models.TextField()
    parent_department = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True)
    head_of_department = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='headed_departments')
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'departments'

    def __str__(self):
        return self.name


# ============================================================================
# CITIZEN MANAGEMENT
# ============================================================================

class Citizen(models.Model):
    """Citizen/Business entity master record"""
    ENTITY_TYPE_CHOICES = [
        ('individual', 'Individual'),
        ('business', 'Business'),
        ('organization', 'Organization'),
        ('government', 'Government Entity'),
    ]
    
    entity_type = models.CharField(max_length=20, choices=ENTITY_TYPE_CHOICES)
    unique_identifier = models.CharField(max_length=100, unique=True)
    
    # Individual fields
    first_name = models.CharField(max_length=100, blank=True)
    middle_name = models.CharField(max_length=100, blank=True)
    last_name = models.CharField(max_length=100, blank=True)
    date_of_birth = models.DateField(null=True, blank=True)
    gender = models.CharField(max_length=10, blank=True)
    
    # Business/Organization fields
    business_name = models.CharField(max_length=200, blank=True)
    registration_number = models.CharField(max_length=100, blank=True)
    
    # Contact information
    email = models.EmailField(unique=True, null=True, blank=True)
    phone_primary = models.CharField(max_length=15)
    phone_secondary = models.CharField(max_length=15, blank=True)
    postal_address = models.CharField(max_length=100, blank=True)
    physical_address = models.TextField(blank=True)
    
    # Location
    sub_county = models.ForeignKey(SubCounty, on_delete=models.SET_NULL, null=True)
    ward = models.ForeignKey(Ward, on_delete=models.SET_NULL, null=True)
    location = gis_models.PointField(null=True, blank=True)
    
    # Portal access
    has_portal_access = models.BooleanField(default=False)
    portal_user = models.OneToOneField(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='citizen_profile')
    
    # Metadata
    is_active = models.BooleanField(default=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='citizens_created')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'citizens'
        indexes = [
            models.Index(fields=['unique_identifier']),
            models.Index(fields=['email']),
            models.Index(fields=['phone_primary']),
        ]

    def __str__(self):
        if self.entity_type == 'individual':
            return f"{self.first_name} {self.last_name}"
        return self.business_name or self.unique_identifier


class CitizenDocument(models.Model):
    """Documents attached to citizen records"""
    citizen = models.ForeignKey(Citizen, on_delete=models.CASCADE, related_name='documents')
    document_type = models.CharField(max_length=100)
    document_number = models.CharField(max_length=100, blank=True)
    file = models.FileField(upload_to='citizen/documents/')
    description = models.TextField(blank=True)
    uploaded_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'citizen_documents'

    def __str__(self):
        return f"{self.citizen} - {self.document_type}"


# ============================================================================
# REVENUE MANAGEMENT - CORE
# ============================================================================

class RevenueStream(models.Model):
    """Master revenue stream configuration"""
    name = models.CharField(max_length=200, unique=True)
    code = models.CharField(max_length=50, unique=True)
    description = models.TextField()
    department = models.ForeignKey(Department, on_delete=models.CASCADE, related_name='revenue_streams')
    parent_stream = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True)
    is_recurring = models.BooleanField(default=False)
    billing_frequency = models.CharField(max_length=20, blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'revenue_streams'

    def __str__(self):
        return f"{self.code} - {self.name}"


class ChargeRate(models.Model):
    """Configurable charge rates for revenue streams"""
    revenue_stream = models.ForeignKey(RevenueStream, on_delete=models.CASCADE, related_name='charge_rates')
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    rate_type = models.CharField(max_length=50)
    amount = models.DecimalField(max_digits=15, decimal_places=2)
    min_amount = models.DecimalField(max_digits=15, decimal_places=2, null=True, blank=True)
    max_amount = models.DecimalField(max_digits=15, decimal_places=2, null=True, blank=True)
    effective_from = models.DateField()
    effective_to = models.DateField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'charge_rates'

    def __str__(self):
        return f"{self.revenue_stream.code} - {self.name}"


class PenaltyRule(models.Model):
    """Penalty configurations for late payments"""
    revenue_stream = models.ForeignKey(RevenueStream, on_delete=models.CASCADE, related_name='penalty_rules')
    name = models.CharField(max_length=200)
    grace_period_days = models.IntegerField(default=0)
    penalty_type = models.CharField(max_length=20)
    penalty_amount = models.DecimalField(max_digits=15, decimal_places=2)
    max_penalty_amount = models.DecimalField(max_digits=15, decimal_places=2, null=True, blank=True)
    effective_from = models.DateField()
    effective_to = models.DateField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'penalty_rules'

    def __str__(self):
        return f"{self.revenue_stream.code} - {self.name}"


class RevenueBudget(models.Model):
    """Revenue budgets and targets"""
    revenue_stream = models.ForeignKey(RevenueStream, on_delete=models.CASCADE, related_name='budgets')
    financial_year = models.CharField(max_length=20)
    period_type = models.CharField(max_length=20)
    period_start = models.DateField()
    period_end = models.DateField()
    target_amount = models.DecimalField(max_digits=15, decimal_places=2)
    sub_county = models.ForeignKey(SubCounty, on_delete=models.CASCADE, null=True, blank=True)
    ward = models.ForeignKey(Ward, on_delete=models.CASCADE, null=True, blank=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'revenue_budgets'
        unique_together = ['revenue_stream', 'financial_year', 'period_start', 'sub_county', 'ward']

    def __str__(self):
        return f"{self.revenue_stream.code} - {self.financial_year}"


# ============================================================================
# BILLING & INVOICING
# ============================================================================

class Bill(models.Model):
    """Bills/Invoices/Demand Notes"""
    BILL_STATUS_CHOICES = [
        ('draft', 'Draft'),
        ('issued', 'Issued'),
        ('partially_paid', 'Partially Paid'),
        ('paid', 'Paid'),
        ('overdue', 'Overdue'),
        ('cancelled', 'Cancelled'),
        ('waived', 'Waived'),
    ]
    
    bill_number = models.CharField(max_length=50, unique=True)
    citizen = models.ForeignKey(Citizen, on_delete=models.CASCADE, related_name='bills')
    revenue_stream = models.ForeignKey(RevenueStream, on_delete=models.CASCADE)
    
    bill_date = models.DateField()
    due_date = models.DateField()
    bill_amount = models.DecimalField(max_digits=15, decimal_places=2)
    penalty_amount = models.DecimalField(max_digits=15, decimal_places=2, default=0)
    total_amount = models.DecimalField(max_digits=15, decimal_places=2)
    amount_paid = models.DecimalField(max_digits=15, decimal_places=2, default=0)
    balance = models.DecimalField(max_digits=15, decimal_places=2)
    
    status = models.CharField(max_length=20, choices=BILL_STATUS_CHOICES, default='draft')
    
    sub_county = models.ForeignKey(SubCounty, on_delete=models.SET_NULL, null=True)
    ward = models.ForeignKey(Ward, on_delete=models.SET_NULL, null=True)
    
    property_id = models.IntegerField(null=True, blank=True)
    license_id = models.IntegerField(null=True, blank=True)
    permit_id = models.IntegerField(null=True, blank=True)
    
    description = models.TextField(blank=True)
    notes = models.TextField(blank=True)
    is_recurring = models.BooleanField(default=False)
    parent_bill = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True)
    
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'bills'
        indexes = [
            models.Index(fields=['bill_number']),
            models.Index(fields=['citizen', 'status']),
            models.Index(fields=['due_date']),
        ]

    def __str__(self):
        return f"{self.bill_number} - {self.citizen}"


class BillLineItem(models.Model):
    """Line items for bills"""
    bill = models.ForeignKey(Bill, on_delete=models.CASCADE, related_name='line_items')
    description = models.CharField(max_length=500)
    quantity = models.DecimalField(max_digits=10, decimal_places=2, default=1)
    unit_price = models.DecimalField(max_digits=15, decimal_places=2)
    amount = models.DecimalField(max_digits=15, decimal_places=2)
    charge_rate = models.ForeignKey(ChargeRate, on_delete=models.SET_NULL, null=True)
    
    class Meta:
        db_table = 'bill_line_items'

    def __str__(self):
        return f"{self.bill.bill_number} - {self.description}"


# ============================================================================
# PAYMENT MANAGEMENT
# ============================================================================

class PaymentMethod(models.Model):
    """Payment methods configuration"""
    name = models.CharField(max_length=100, unique=True)
    code = models.CharField(max_length=20, unique=True)
    provider = models.CharField(max_length=100)
    is_online = models.BooleanField(default=True)
    is_active = models.BooleanField(default=True)
    api_endpoint = models.URLField(blank=True)
    configuration = models.JSONField(default=dict)
    
    class Meta:
        db_table = 'payment_methods'

    def __str__(self):
        return f"{self.name} ({self.provider})"


class Payment(models.Model):
    """Payment transactions"""
    PAYMENT_STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('processing', 'Processing'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('reversed', 'Reversed'),
        ('cancelled', 'Cancelled'),
    ]
    
    receipt_number = models.CharField(max_length=50, unique=True)
    transaction_reference = models.CharField(max_length=100, unique=True)
    
    citizen = models.ForeignKey(Citizen, on_delete=models.CASCADE, related_name='payments')
    bill = models.ForeignKey(Bill, on_delete=models.SET_NULL, null=True, blank=True, related_name='payments')
    
    payment_method = models.ForeignKey(PaymentMethod, on_delete=models.CASCADE)
    payment_date = models.DateTimeField()
    amount = models.DecimalField(max_digits=15, decimal_places=2)
    
    status = models.CharField(max_length=20, choices=PAYMENT_STATUS_CHOICES, default='pending')
    
    payer_name = models.CharField(max_length=200)
    payer_phone = models.CharField(max_length=15)
    payer_reference = models.CharField(max_length=100, blank=True)
    
    provider_reference = models.CharField(max_length=100, blank=True)
    provider_response = models.JSONField(null=True, blank=True)
    
    revenue_stream = models.ForeignKey(RevenueStream, on_delete=models.CASCADE)
    sub_county = models.ForeignKey(SubCounty, on_delete=models.SET_NULL, null=True)
    ward = models.ForeignKey(Ward, on_delete=models.SET_NULL, null=True)
    
    notes = models.TextField(blank=True)
    collected_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    is_auto_receipted = models.BooleanField(default=False)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'payments'
        indexes = [
            models.Index(fields=['receipt_number']),
            models.Index(fields=['transaction_reference']),
            models.Index(fields=['payment_date']),
        ]

    def __str__(self):
        return f"{self.receipt_number} - KES {self.amount}"


class PaymentReversal(models.Model):
    """Payment reversal audit trail"""
    payment = models.ForeignKey(Payment, on_delete=models.SET_NULL, null=True, blank=True)
    
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    
    def __str__(self):
        return f"{self.fine_number} - {self.offender}"


# ============================================================================
# HOSPITAL MANAGEMENT INFORMATION SYSTEM
# ============================================================================

class Patient(models.Model):
    """Patient registration"""
    GENDER_CHOICES = [
        ('M', 'Male'),
        ('F', 'Female'),
        ('O', 'Other'),
    ]
    
    patient_number = models.CharField(max_length=50, unique=True)
    citizen = models.OneToOneField(Citizen, on_delete=models.CASCADE, related_name='patient_profile', null=True, blank=True)
    
    first_name = models.CharField(max_length=100)
    middle_name = models.CharField(max_length=100, blank=True)
    last_name = models.CharField(max_length=100)
    
    date_of_birth = models.DateField()
    gender = models.CharField(max_length=1, choices=GENDER_CHOICES)
    id_number = models.CharField(max_length=20, blank=True)
    
    phone = models.CharField(max_length=15)
    email = models.EmailField(blank=True)
    address = models.TextField()
    
    next_of_kin_name = models.CharField(max_length=200)
    next_of_kin_phone = models.CharField(max_length=15)
    next_of_kin_relationship = models.CharField(max_length=50)
    
    blood_group = models.CharField(max_length=10, blank=True)
    allergies = models.TextField(blank=True)
    
    is_active = models.BooleanField(default=True)
    registered_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'patients'

    def __str__(self):
        return f"{self.patient_number} - {self.first_name} {self.last_name}"


class HealthFacility(models.Model):
    """Health facilities"""
    FACILITY_LEVEL_CHOICES = [
        ('level_1', 'Community Health Unit'),
        ('level_2', 'Dispensary'),
        ('level_3', 'Health Centre'),
        ('level_4', 'Sub-County Hospital'),
        ('level_5', 'County Referral Hospital'),
    ]
    
    name = models.CharField(max_length=200)
    code = models.CharField(max_length=50, unique=True)
    facility_level = models.CharField(max_length=20, choices=FACILITY_LEVEL_CHOICES)
    
    location = gis_models.PointField()
    sub_county = models.ForeignKey(SubCounty, on_delete=models.CASCADE)
    ward = models.ForeignKey(Ward, on_delete=models.CASCADE)
    
    phone = models.CharField(max_length=15)
    email = models.EmailField(blank=True)
    
    bed_capacity = models.IntegerField(default=0)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'health_facilities'
        verbose_name_plural = 'health facilities'

    def __str__(self):
        return self.name


class Triage(models.Model):
    """Triage records"""
    PRIORITY_CHOICES = [
        ('emergency', 'Emergency'),
        ('urgent', 'Urgent'),
        ('normal', 'Normal'),
    ]
    
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE, related_name='triages')
    facility = models.ForeignKey(HealthFacility, on_delete=models.CASCADE)
    
    visit_date = models.DateTimeField()
    priority = models.CharField(max_length=20, choices=PRIORITY_CHOICES)
    
    temperature = models.DecimalField(max_digits=4, decimal_places=1, null=True, blank=True)
    blood_pressure = models.CharField(max_length=20, blank=True)
    pulse_rate = models.IntegerField(null=True, blank=True)
    weight = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    height = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    
    chief_complaint = models.TextField()
    notes = models.TextField(blank=True)
    
    triaged_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'triages'

    def __str__(self):
        return f"{self.patient.patient_number} - {self.visit_date}"


class Visit(models.Model):
    """Patient visits/encounters"""
    VISIT_TYPE_CHOICES = [
        ('outpatient', 'Outpatient'),
        ('inpatient', 'Inpatient'),
        ('emergency', 'Emergency'),
    ]
    
    visit_number = models.CharField(max_length=50, unique=True)
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE, related_name='visits')
    facility = models.ForeignKey(HealthFacility, on_delete=models.CASCADE)
    triage = models.OneToOneField(Triage, on_delete=models.SET_NULL, null=True, blank=True)
    
    visit_type = models.CharField(max_length=20, choices=VISIT_TYPE_CHOICES)
    visit_date = models.DateTimeField()
    
    diagnosis = models.TextField(blank=True)
    treatment = models.TextField(blank=True)
    notes = models.TextField(blank=True)
    
    attended_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    
    is_complete = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'visits'

    def __str__(self):
        return f"{self.visit_number} - {self.patient.patient_number}"


class HospitalWard(models.Model):
    """Hospital wards"""
    facility = models.ForeignKey(HealthFacility, on_delete=models.CASCADE, related_name='hospital_wards')
    name = models.CharField(max_length=200)
    ward_type = models.CharField(max_length=100)
    bed_capacity = models.IntegerField()
    is_active = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'hospital_wards'

    def __str__(self):
        return f"{self.facility.name} - {self.name}"


class Admission(models.Model):
    """Patient admissions"""
    STATUS_CHOICES = [
        ('admitted', 'Admitted'),
        ('discharged', 'Discharged'),
        ('transferred', 'Transferred'),
        ('deceased', 'Deceased'),
    ]
    
    admission_number = models.CharField(max_length=50, unique=True)
    visit = models.OneToOneField(Visit, on_delete=models.CASCADE, related_name='admission')
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE, related_name='admissions')
    
    ward = models.ForeignKey(HospitalWard, on_delete=models.CASCADE, related_name='admissions')
    bed_number = models.CharField(max_length=20)
    
    admission_date = models.DateTimeField()
    discharge_date = models.DateTimeField(null=True, blank=True)
    
    admission_reason = models.TextField()
    discharge_notes = models.TextField(blank=True)
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='admitted')
    
    admitted_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='patient_admissions')
    discharged_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='patient_discharges')
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'admissions'

    def __str__(self):
        return f"{self.admission_number} - {self.patient.patient_number}"


class LabTest(models.Model):
    """Laboratory tests"""
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('cancelled', 'Cancelled'),
    ]
    
    test_number = models.CharField(max_length=50, unique=True)
    visit = models.ForeignKey(Visit, on_delete=models.CASCADE, related_name='lab_tests')
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE, related_name='lab_tests')
    
    test_name = models.CharField(max_length=200)
    test_category = models.CharField(max_length=100)
    
    requested_date = models.DateTimeField()
    completed_date = models.DateTimeField(null=True, blank=True)
    
    results = models.TextField(blank=True)
    remarks = models.TextField(blank=True)
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    
    requested_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='requested_tests')
    processed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='processed_tests')
    
    test_cost = models.DecimalField(max_digits=10, decimal_places=2)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'lab_tests'

    def __str__(self):
        return f"{self.test_number} - {self.test_name}"


class Imaging(models.Model):
    """Imaging/Radiology records"""
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('cancelled', 'Cancelled'),
    ]
    
    imaging_number = models.CharField(max_length=50, unique=True)
    visit = models.ForeignKey(Visit, on_delete=models.CASCADE, related_name='imaging_tests')
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE, related_name='imaging_tests')
    
    imaging_type = models.CharField(max_length=100)
    body_part = models.CharField(max_length=100)
    
    requested_date = models.DateTimeField()
    completed_date = models.DateTimeField(null=True, blank=True)
    
    findings = models.TextField(blank=True)
    report = models.TextField(blank=True)
    images = models.FileField(upload_to='imaging/', null=True, blank=True)
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    
    requested_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='requested_imaging')
    processed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='processed_imaging')
    
    imaging_cost = models.DecimalField(max_digits=10, decimal_places=2)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'imaging'

    def __str__(self):
        return f"{self.imaging_number} - {self.imaging_type}"


class Prescription(models.Model):
    """Medical prescriptions"""
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('dispensed', 'Dispensed'),
        ('cancelled', 'Cancelled'),
    ]
    
    prescription_number = models.CharField(max_length=50, unique=True)
    visit = models.ForeignKey(Visit, on_delete=models.CASCADE, related_name='prescriptions')
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE, related_name='prescriptions')
    
    medication_name = models.CharField(max_length=200)
    dosage = models.CharField(max_length=100)
    frequency = models.CharField(max_length=100)
    duration = models.CharField(max_length=100)
    quantity = models.IntegerField()
    
    instructions = models.TextField(blank=True)
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    
    prescribed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='prescriptions')
    dispensed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='dispensed_prescriptions')
    dispensed_date = models.DateTimeField(null=True, blank=True)
    
    medication_cost = models.DecimalField(max_digits=10, decimal_places=2)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'prescriptions'

    def __str__(self):
        return f"{self.prescription_number} - {self.medication_name}"


class MorgueRecord(models.Model):
    """Morgue management records"""
    STATUS_CHOICES = [
        ('admitted', 'Admitted'),
        ('released', 'Released'),
        ('buried', 'Buried'),
    ]
    
    morgue_number = models.CharField(max_length=50, unique=True)
    deceased_name = models.CharField(max_length=200)
    age = models.IntegerField(null=True, blank=True)
    gender = models.CharField(max_length=10)
    
    date_of_death = models.DateField()
    admission_date = models.DateTimeField()
    release_date = models.DateTimeField(null=True, blank=True)
    
    cause_of_death = models.TextField()
    
    next_of_kin_name = models.CharField(max_length=200)
    next_of_kin_phone = models.CharField(max_length=15)
    next_of_kin_relationship = models.CharField(max_length=50)
    
    compartment_number = models.CharField(max_length=20)
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='admitted')
    
    facility = models.ForeignKey(HealthFacility, on_delete=models.CASCADE, related_name='morgue_records')
    
    admitted_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'morgue_records'

    def __str__(self):
        return f"{self.morgue_number} - {self.deceased_name}"


# ============================================================================
# FLEET MANAGEMENT
# ============================================================================

class FleetVehicle(models.Model):
    """County fleet vehicles and machinery"""
    VEHICLE_TYPE_CHOICES = [
        ('car', 'Car'),
        ('truck', 'Truck'),
        ('bus', 'Bus'),
        ('motorcycle', 'Motorcycle'),
        ('machinery', 'Machinery/Plant'),
    ]
    
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('maintenance', 'Under Maintenance'),
        ('inactive', 'Inactive'),
        ('disposed', 'Disposed'),
    ]
    
    fleet_number = models.CharField(max_length=50, unique=True)
    registration_number = models.CharField(max_length=20, unique=True)
    
    vehicle_type = models.CharField(max_length=50, choices=VEHICLE_TYPE_CHOICES)
    make = models.CharField(max_length=100)
    model = models.CharField(max_length=100)
    year = models.IntegerField()
    
    department = models.ForeignKey(Department, on_delete=models.CASCADE, related_name='fleet_vehicles')
    current_driver = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='assigned_vehicles')
    
    fuel_type = models.CharField(max_length=50)
    engine_capacity = models.CharField(max_length=50, blank=True)
    
    purchase_date = models.DateField()
    purchase_cost = models.DecimalField(max_digits=15, decimal_places=2)
    
    insurance_expiry = models.DateField()
    inspection_due = models.DateField()
    
    current_mileage = models.IntegerField(default=0)
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')
    
    has_gps = models.BooleanField(default=False)
    gps_device_id = models.CharField(max_length=100, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'fleet_vehicles'

    def __str__(self):
        return f"{self.fleet_number} - {self.registration_number}"


class FuelStation(models.Model):
    """Fuel stations"""
    name = models.CharField(max_length=200)
    code = models.CharField(max_length=50, unique=True)
    location = gis_models.PointField()
    address = models.TextField()
    is_active = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'fuel_stations'

    def __str__(self):
        return self.name


class FuelCard(models.Model):
    """Fuel cards"""
    card_number = models.CharField(max_length=50, unique=True)
    vehicle = models.ForeignKey(FleetVehicle, on_delete=models.CASCADE, related_name='fuel_cards')
    daily_limit = models.DecimalField(max_digits=10, decimal_places=2)
    monthly_limit = models.DecimalField(max_digits=10, decimal_places=2)
    is_active = models.BooleanField(default=True)
    
    issued_date = models.DateField()
    expiry_date = models.DateField()
    
    class Meta:
        db_table = 'fuel_cards'

    def __str__(self):
        return f"{self.card_number} - {self.vehicle.registration_number}"


class FuelTransaction(models.Model):
    """Fuel, oil, and lubricants transactions"""
    TRANSACTION_TYPE_CHOICES = [
        ('fuel', 'Fuel'),
        ('oil', 'Oil'),
        ('lubricant', 'Lubricant'),
    ]
    
    transaction_number = models.CharField(max_length=50, unique=True)
    vehicle = models.ForeignKey(FleetVehicle, on_delete=models.CASCADE, related_name='fuel_transactions')
    fuel_card = models.ForeignKey(FuelCard, on_delete=models.SET_NULL, null=True, blank=True)
    
    transaction_type = models.CharField(max_length=20, choices=TRANSACTION_TYPE_CHOICES)
    fuel_station = models.ForeignKey(FuelStation, on_delete=models.CASCADE)
    
    transaction_date = models.DateTimeField()
    quantity_liters = models.DecimalField(max_digits=10, decimal_places=2)
    unit_price = models.DecimalField(max_digits=10, decimal_places=2)
    total_amount = models.DecimalField(max_digits=10, decimal_places=2)
    
    mileage = models.IntegerField()
    driver = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    
    receipt_number = models.CharField(max_length=100, blank=True)
    notes = models.TextField(blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'fuel_transactions'

    def __str__(self):
        return f"{self.transaction_number} - {self.vehicle.registration_number}"


class VehicleMaintenance(models.Model):
    """Vehicle maintenance records"""
    MAINTENANCE_TYPE_CHOICES = [
        ('routine', 'Routine Service'),
        ('repair', 'Repair'),
        ('inspection', 'Inspection'),
        ('emergency', 'Emergency'),
    ]
    
    STATUS_CHOICES = [
        ('scheduled', 'Scheduled'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('cancelled', 'Cancelled'),
    ]
    
    maintenance_number = models.CharField(max_length=50, unique=True)
    vehicle = models.ForeignKey(FleetVehicle, on_delete=models.CASCADE, related_name='maintenance_records')
    
    maintenance_type = models.CharField(max_length=20, choices=MAINTENANCE_TYPE_CHOICES)
    description = models.TextField()
    
    scheduled_date = models.DateField()
    completed_date = models.DateField(null=True, blank=True)
    
    service_provider = models.CharField(max_length=200)
    cost = models.DecimalField(max_digits=10, decimal_places=2)
    
    mileage = models.IntegerField()
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='scheduled')
    
    requested_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'vehicle_maintenance'

    def __str__(self):
        return f"{self.maintenance_number} - {self.vehicle.registration_number}"


class VehicleTrip(models.Model):
    """Vehicle trip/work ticket records"""
    STATUS_CHOICES = [
        ('scheduled', 'Scheduled'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('cancelled', 'Cancelled'),
    ]
    
    trip_number = models.CharField(max_length=50, unique=True)
    vehicle = models.ForeignKey(FleetVehicle, on_delete=models.CASCADE, related_name='trips')
    driver = models.ForeignKey(User, on_delete=models.CASCADE, related_name='trips')
    
    purpose = models.TextField()
    destination = models.CharField(max_length=200)
    
    scheduled_departure = models.DateTimeField()
    scheduled_return = models.DateTimeField()
    
    actual_departure = models.DateTimeField(null=True, blank=True)
    actual_return = models.DateTimeField(null=True, blank=True)
    
    start_mileage = models.IntegerField()
    end_mileage = models.IntegerField(null=True, blank=True)
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='scheduled')
    
    approved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='approved_trips')
    
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'vehicle_trips'

    def __str__(self):
        return f"{self.trip_number} - {self.vehicle.registration_number}"


# ============================================================================
# COUNTY FACILITIES - MARKETS, STALLS, HOUSING
# ============================================================================

class FacilityCategory(models.Model):
    """Categories of county facilities"""
    name = models.CharField(max_length=100, unique=True)
    code = models.CharField(max_length=20, unique=True)
    description = models.TextField()
    is_active = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'facility_categories'
        verbose_name_plural = 'facility categories'

    def __str__(self):
        return self.name


class Facility(models.Model):
    """County facilities - markets, stadia, toilets, etc."""
    FACILITY_TYPE_CHOICES = [
        ('market', 'Market'),
        ('stadium', 'Stadium'),
        ('toilet', 'Public Toilet'),
        ('housing', 'County Housing'),
        ('office', 'Office'),
        ('other', 'Other'),
    ]
    
    name = models.CharField(max_length=200)
    code = models.CharField(max_length=50, unique=True)
    facility_type = models.CharField(max_length=50, choices=FACILITY_TYPE_CHOICES)
    category = models.ForeignKey(FacilityCategory, on_delete=models.CASCADE)
    
    location = gis_models.PointField()
    sub_county = models.ForeignKey(SubCounty, on_delete=models.CASCADE)
    ward = models.ForeignKey(Ward, on_delete=models.CASCADE)
    physical_address = models.TextField()
    
    description = models.TextField(blank=True)
    capacity = models.IntegerField(default=0)
    
    is_active = models.BooleanField(default=True)
    managed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'facilities'
        verbose_name_plural = 'facilities'

    def __str__(self):
        return f"{self.code} - {self.name}"


class FacilityUnit(models.Model):
    """Units within facilities (stalls, houses, kiosks, etc.)"""
    UNIT_TYPE_CHOICES = [
        ('stall', 'Market Stall'),
        ('shop', 'Shop'),
        ('kiosk', 'Kiosk'),
        ('house', 'Rental House'),
        ('toilet', 'Toilet Unit'),
        ('office', 'Office Space'),
    ]
    
    STATUS_CHOICES = [
        ('vacant', 'Vacant'),
        ('occupied', 'Occupied'),
        ('reserved', 'Reserved'),
        ('maintenance', 'Under Maintenance'),
        ('closed', 'Closed'),
    ]
    
    facility = models.ForeignKey(Facility, on_delete=models.CASCADE, related_name='units')
    unit_number = models.CharField(max_length=50)
    unit_type = models.CharField(max_length=50, choices=UNIT_TYPE_CHOICES)
    
    description = models.TextField(blank=True)
    size_sqm = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    
    rental_rate_daily = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    rental_rate_monthly = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    rental_rate_yearly = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='vacant')
    current_tenant = models.ForeignKey(Citizen, on_delete=models.SET_NULL, null=True, blank=True, related_name='rented_units')
    
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'facility_units'
        unique_together = ['facility', 'unit_number']

    def __str__(self):
        return f"{self.facility.name} - {self.unit_number}"


class FacilityTenancy(models.Model):
    """Tenancy/rental records for facility units"""
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('expired', 'Expired'),
        ('terminated', 'Terminated'),
        ('transferred', 'Transferred'),
    ]
    
    tenancy_number = models.CharField(max_length=50, unique=True)
    unit = models.ForeignKey(FacilityUnit, on_delete=models.CASCADE, related_name='tenancies')
    tenant = models.ForeignKey(Citizen, on_delete=models.CASCADE, related_name='tenancies')
    
    start_date = models.DateField()
    end_date = models.DateField(null=True, blank=True)
    
    rental_amount = models.DecimalField(max_digits=10, decimal_places=2)
    payment_frequency = models.CharField(max_length=20)  # daily, monthly, yearly
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')
    
    deposit_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    deposit_paid = models.BooleanField(default=False)
    
    notes = models.TextField(blank=True)
    termination_reason = models.TextField(blank=True)
    termination_date = models.DateField(null=True, blank=True)
    
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'facility_tenancies'
        verbose_name_plural = 'facility tenancies'

    def __str__(self):
        return f"{self.tenancy_number} - {self.tenant}"


class FacilityBooking(models.Model):
    """Bookings for facilities (stadiums, halls, etc.)"""
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('confirmed', 'Confirmed'),
        ('cancelled', 'Cancelled'),
        ('completed', 'Completed'),
    ]
    
    booking_number = models.CharField(max_length=50, unique=True)
    facility = models.ForeignKey(Facility, on_delete=models.CASCADE, related_name='bookings')
    customer = models.ForeignKey(Citizen, on_delete=models.CASCADE, related_name='facility_bookings')
    
    booking_date = models.DateField()
    start_time = models.DateTimeField()
    end_time = models.DateTimeField()
    
    purpose = models.TextField()
    expected_attendance = models.IntegerField(default=0)
    
    booking_fee = models.DecimalField(max_digits=10, decimal_places=2)
    payment = models.ForeignKey(Payment, on_delete=models.SET_NULL, null=True, blank=True)
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    
    approved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='approved_bookings')
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'facility_bookings'

    def __str__(self):
        return f"{self.booking_number} - {self.facility.name}"




# ============================================================================
# HUMAN RESOURCE MANAGEMENT
# ============================================================================

class BiometricDevice(models.Model):
    """Biometric attendance devices"""
    device_id = models.CharField(max_length=50, unique=True)
    device_name = models.CharField(max_length=200)
    location = models.CharField(max_length=200)
    facility = models.ForeignKey(Facility, on_delete=models.SET_NULL, null=True, blank=True)
    ip_address = models.GenericIPAddressField()
    is_active = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'biometric_devices'

    def __str__(self):
        return f"{self.device_id} - {self.device_name}"


class Attendance(models.Model):
    """Staff attendance records"""
    ATTENDANCE_TYPE_CHOICES = [
        ('check_in', 'Check In'),
        ('check_out', 'Check Out'),
    ]
    
    employee = models.ForeignKey(User, on_delete=models.CASCADE, related_name='attendance_records')
    attendance_date = models.DateField()
    attendance_time = models.DateTimeField()
    attendance_type = models.CharField(max_length=20, choices=ATTENDANCE_TYPE_CHOICES)
    
    device = models.ForeignKey(BiometricDevice, on_delete=models.SET_NULL, null=True)
    biometric_verified = models.BooleanField(default=False)
    
    location = gis_models.PointField(null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'attendance'
        indexes = [
            models.Index(fields=['employee', 'attendance_date']),
        ]

    def __str__(self):
        return f"{self.employee.username} - {self.attendance_date} - {self.attendance_type}"


class LeaveType(models.Model):
    """Types of leave"""
    name = models.CharField(max_length=100, unique=True)
    code = models.CharField(max_length=20, unique=True)
    description = models.TextField()
    days_per_year = models.IntegerField()
    requires_approval = models.BooleanField(default=True)
    is_paid = models.BooleanField(default=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'leave_types'

    def __str__(self):
        return self.name


class LeaveApplication(models.Model):
    """Leave applications"""
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
        ('cancelled', 'Cancelled'),
    ]
    
    application_number = models.CharField(max_length=50, unique=True)
    employee = models.ForeignKey(User, on_delete=models.CASCADE, related_name='leave_applications')
    leave_type = models.ForeignKey(LeaveType, on_delete=models.CASCADE)
    
    start_date = models.DateField()
    end_date = models.DateField()
    days_requested = models.IntegerField()
    
    reason = models.TextField()
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    
    approved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='approved_leaves')
    approval_date = models.DateField(null=True, blank=True)
    rejection_reason = models.TextField(blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'leave_applications'

    def __str__(self):
        return f"{self.application_number} - {self.employee.username}"


class Transfer(models.Model):
    """Staff transfers"""
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
        ('completed', 'Completed'),
    ]
    
    transfer_number = models.CharField(max_length=50, unique=True)
    employee = models.ForeignKey(User, on_delete=models.CASCADE, related_name='transfers')
    
    from_department = models.ForeignKey(Department, on_delete=models.CASCADE, related_name='transfers_from')
    to_department = models.ForeignKey(Department, on_delete=models.CASCADE, related_name='transfers_to')
    
    from_sub_county = models.ForeignKey(SubCounty, on_delete=models.CASCADE, related_name='transfers_from', null=True, blank=True)
    to_sub_county = models.ForeignKey(SubCounty, on_delete=models.CASCADE, related_name='transfers_to', null=True, blank=True)
    
    reason = models.TextField()
    effective_date = models.DateField()
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    
    requested_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='requested_transfers')
    approved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='approved_transfers')
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'transfers'

    def __str__(self):
        return f"{self.transfer_number} - {self.employee.username}"


class PerformanceReview(models.Model):
    """Performance management"""
    STATUS_CHOICES = [
        ('draft', 'Draft'),
        ('submitted', 'Submitted'),
        ('reviewed', 'Reviewed'),
        ('approved', 'Approved'),
    ]
    
    review_number = models.CharField(max_length=50, unique=True)
    employee = models.ForeignKey(User, on_delete=models.CASCADE, related_name='performance_reviews')
    
    review_period_start = models.DateField()
    review_period_end = models.DateField()
    
    objectives = models.TextField()
    achievements = models.TextField(blank=True)
    
    rating = models.IntegerField(validators=[MinValueValidator(1), MaxValueValidator(5)], null=True, blank=True)
    
    supervisor_comments = models.TextField(blank=True)
    employee_comments = models.TextField(blank=True)
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='draft')
    
    reviewer = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='conducted_reviews')
    approved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='approved_reviews')
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'performance_reviews'

    def __str__(self):
        return f"{self.review_number} - {self.employee.username}"


class TrainingProgram(models.Model):
    """Training and development programs"""
    program_name = models.CharField(max_length=200)
    program_code = models.CharField(max_length=50, unique=True)
    description = models.TextField()
    
    provider = models.CharField(max_length=200)
    duration_days = models.IntegerField()
    cost_per_participant = models.DecimalField(max_digits=10, decimal_places=2)
    
    start_date = models.DateField()
    end_date = models.DateField()
    
    venue = models.CharField(max_length=200)
    max_participants = models.IntegerField()
    
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'training_programs'

    def __str__(self):
        return self.program_name


class TrainingParticipant(models.Model):
    """Training participants"""
    STATUS_CHOICES = [
        ('nominated', 'Nominated'),
        ('confirmed', 'Confirmed'),
        ('completed', 'Completed'),
        ('withdrawn', 'Withdrawn'),
    ]
    
    program = models.ForeignKey(TrainingProgram, on_delete=models.CASCADE, related_name='participants')
    employee = models.ForeignKey(User, on_delete=models.CASCADE, related_name='training_programs')
    
    nomination_date = models.DateField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='nominated')
    
    attendance_percentage = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    certificate_issued = models.BooleanField(default=False)
    certificate_number = models.CharField(max_length=100, blank=True)
    
    feedback = models.TextField(blank=True)
    
    nominated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='nominated_trainees')
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'training_participants'
        unique_together = ['program', 'employee']

    def __str__(self):
        return f"{self.employee.username} - {self.program.program_name}"


class DisciplinaryCase(models.Model):
    """Staff discipline management"""
    STATUS_CHOICES = [
        ('reported', 'Reported'),
        ('under_investigation', 'Under Investigation'),
        ('hearing_scheduled', 'Hearing Scheduled'),
        ('resolved', 'Resolved'),
        ('closed', 'Closed'),
    ]
    
    case_number = models.CharField(max_length=50, unique=True)
    employee = models.ForeignKey(User, on_delete=models.CASCADE, related_name='disciplinary_cases')
    
    offense = models.TextField()
    offense_date = models.DateField()
    report_date = models.DateField()
    
    investigation_findings = models.TextField(blank=True)
    action_taken = models.TextField(blank=True)
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='reported')
    
    reported_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='reported_cases')
    investigating_officer = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='investigated_cases')
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'disciplinary_cases'

    def __str__(self):
        return f"{self.case_number} - {self.employee.username}"


class StaffDocument(models.Model):
    """Staff records and documents"""
    employee = models.ForeignKey(User, on_delete=models.CASCADE, related_name='documents')
    document_type = models.CharField(max_length=100)
    document_number = models.CharField(max_length=100, blank=True)
    file = models.FileField(upload_to='staff/documents/')
    description = models.TextField(blank=True)
    
    expiry_date = models.DateField(null=True, blank=True)
    
    uploaded_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='uploaded_staff_docs')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'staff_documents'

    def __str__(self):
        return f"{self.employee.username} - {self.document_type}"


# ============================================================================
# STORES & INVENTORY MANAGEMENT
# ============================================================================

class Store(models.Model):
    """Stores/Warehouses"""
    name = models.CharField(max_length=200)
    code = models.CharField(max_length=50, unique=True)
    
    location = gis_models.PointField(null=True, blank=True)
    sub_county = models.ForeignKey(SubCounty, on_delete=models.CASCADE)
    
    store_keeper = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='managed_stores')
    
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'stores'

    def __str__(self):
        return self.name


class ItemCategory(models.Model):
    """Inventory item categories"""
    name = models.CharField(max_length=200, unique=True)
    code = models.CharField(max_length=50, unique=True)
    description = models.TextField()
    parent_category = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'item_categories'
        verbose_name_plural = 'item categories'

    def __str__(self):
        return self.name


class InventoryItem(models.Model):
    """Inventory items/consumables"""
    ITEM_TYPE_CHOICES = [
        ('consumable', 'Consumable'),
        ('non_consumable', 'Non-Consumable'),
    ]
    
    item_code = models.CharField(max_length=50, unique=True)
    name = models.CharField(max_length=200)
    description = models.TextField()
    
    category = models.ForeignKey(ItemCategory, on_delete=models.CASCADE, related_name='items')
    item_type = models.CharField(max_length=20, choices=ITEM_TYPE_CHOICES)
    
    unit_of_measure = models.CharField(max_length=50)
    reorder_level = models.IntegerField(default=0)
    
    unit_cost = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'inventory_items'

    def __str__(self):
        return f"{self.item_code} - {self.name}"


class StoreStock(models.Model):
    """Stock levels in stores"""
    store = models.ForeignKey(Store, on_delete=models.CASCADE, related_name='stock')
    item = models.ForeignKey(InventoryItem, on_delete=models.CASCADE, related_name='stock_levels')
    
    quantity = models.IntegerField(default=0)
    reserved_quantity = models.IntegerField(default=0)
    available_quantity = models.IntegerField(default=0)
    
    last_updated = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'store_stock'
        unique_together = ['store', 'item']

    def __str__(self):
        return f"{self.store.name} - {self.item.name} - {self.quantity}"


class GoodsReceiptNote(models.Model):
    """Goods receipt notes"""
    STATUS_CHOICES = [
        ('draft', 'Draft'),
        ('received', 'Received'),
        ('inspected', 'Inspected'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
    ]
    
    grn_number = models.CharField(max_length=50, unique=True)
    store = models.ForeignKey(Store, on_delete=models.CASCADE, related_name='receipts')
    
    supplier = models.CharField(max_length=200)
    delivery_note_number = models.CharField(max_length=100, blank=True)
    lpo_number = models.CharField(max_length=100, blank=True)
    
    receipt_date = models.DateField()
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='draft')
    
    received_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='received_goods')
    inspected_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='inspected_goods')
    
    notes = models.TextField(blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'goods_receipt_notes'

    def __str__(self):
        return self.grn_number


class GoodsReceiptItem(models.Model):
    """Items in goods receipt notes"""
    grn = models.ForeignKey(GoodsReceiptNote, on_delete=models.CASCADE, related_name='items')
    item = models.ForeignKey(InventoryItem, on_delete=models.CASCADE)
    
    quantity_ordered = models.IntegerField()
    quantity_received = models.IntegerField()
    unit_price = models.DecimalField(max_digits=10, decimal_places=2)
    total_price = models.DecimalField(max_digits=15, decimal_places=2)
    
    remarks = models.TextField(blank=True)
    
    class Meta:
        db_table = 'goods_receipt_items'

    def __str__(self):
        return f"{self.grn.grn_number} - {self.item.name}"


class StoreRequisition(models.Model):
    """Store requisitions/issues"""
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('issued', 'Issued'),
        ('rejected', 'Rejected'),
        ('cancelled', 'Cancelled'),
    ]
    
    requisition_number = models.CharField(max_length=50, unique=True)
    store = models.ForeignKey(Store, on_delete=models.CASCADE, related_name='requisitions')
    
    department = models.ForeignKey(Department, on_delete=models.CASCADE)
    requisition_date = models.DateField()
    required_date = models.DateField()
    
    purpose = models.TextField()
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    
    requested_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='store_requests')
    approved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='approved_requisitions')
    issued_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='issued_items')
    issue_date = models.DateField(null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'store_requisitions'

    def __str__(self):
        return self.requisition_number


class RequisitionItem(models.Model):
    """Items in store requisitions"""
    requisition = models.ForeignKey(StoreRequisition, on_delete=models.CASCADE, related_name='items')
    item = models.ForeignKey(InventoryItem, on_delete=models.CASCADE)
    
    quantity_requested = models.IntegerField()
    quantity_approved = models.IntegerField(null=True, blank=True)
    quantity_issued = models.IntegerField(null=True, blank=True)
    
    remarks = models.TextField(blank=True)
    
    class Meta:
        db_table = 'requisition_items'

    def __str__(self):
        return f"{self.requisition.requisition_number} - {self.item.name}"


# ============================================================================
# ASSET MANAGEMENT
# ============================================================================

class AssetCategory(models.Model):
    """Asset categories"""
    name = models.CharField(max_length=200, unique=True)
    code = models.CharField(max_length=50, unique=True)
    description = models.TextField()
    depreciation_rate = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    useful_life_years = models.IntegerField(default=0)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'asset_categories'
        verbose_name_plural = 'asset categories'

    def __str__(self):
        return self.name


class Asset(models.Model):
    """Fixed assets - movable and immovable"""
    ASSET_TYPE_CHOICES = [
        ('movable', 'Movable'),
        ('immovable', 'Immovable'),
    ]
    
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('inactive', 'Inactive'),
        ('disposed', 'Disposed'),
        ('written_off', 'Written Off'),
    ]
    
    asset_number = models.CharField(max_length=50, unique=True)
    name = models.CharField(max_length=200)
    description = models.TextField()
    
    category = models.ForeignKey(AssetCategory, on_delete=models.CASCADE, related_name='assets')
    asset_type = models.CharField(max_length=20, choices=ASSET_TYPE_CHOICES)
    
    acquisition_date = models.DateField()
    acquisition_cost = models.DecimalField(max_digits=15, decimal_places=2)
    current_value = models.DecimalField(max_digits=15, decimal_places=2)
    
    location = gis_models.PointField(null=True, blank=True)
    sub_county = models.ForeignKey(SubCounty, on_delete=models.CASCADE)
    department = models.ForeignKey(Department, on_delete=models.CASCADE)
    
    custodian = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='custodian_assets')
    
    serial_number = models.CharField(max_length=100, blank=True)
    barcode = models.CharField(max_length=100, blank=True, unique=True)
    
    warranty_expiry = models.DateField(null=True, blank=True)
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'assets'

    def __str__(self):
        return f"{self.asset_number} - {self.name}"


class AssetTransfer(models.Model):
    """Asset transfer records"""
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('completed', 'Completed'),
        ('rejected', 'Rejected'),
    ]
    
    transfer_number = models.CharField(max_length=50, unique=True)
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name='transfers')
    
    from_department = models.ForeignKey(Department, on_delete=models.CASCADE, related_name='asset_transfers_from')
    to_department = models.ForeignKey(Department, on_delete=models.CASCADE, related_name='asset_transfers_to')
    
    from_custodian = models.ForeignKey(User, on_delete=models.CASCADE, related_name='assets_transferred_from')
    to_custodian = models.ForeignKey(User, on_delete=models.CASCADE, related_name='assets_transferred_to')
    
    transfer_date = models.DateField()
    reason = models.TextField()
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    
    requested_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='requested_asset_transfers')
    approved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='approved_asset_transfers')
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'asset_transfers'

    def __str__(self):
        return f"{self.transfer_number} - {self.asset.asset_number}"


class AssetMaintenance(models.Model):
    """Asset maintenance records"""
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name='maintenance_records')
    maintenance_date = models.DateField()
    maintenance_type = models.CharField(max_length=100)
    description = models.TextField()
    cost = models.DecimalField(max_digits=10, decimal_places=2)
    service_provider = models.CharField(max_length=200, blank=True)
    
    performed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'asset_maintenance'

    def __str__(self):
        return f"{self.asset.asset_number} - {self.maintenance_date}"


class AssetDisposal(models.Model):
    """Asset disposal records"""
    DISPOSAL_METHOD_CHOICES = [
        ('sale', 'Sale'),
        ('auction', 'Auction'),
        ('donation', 'Donation'),
        ('write_off', 'Write Off'),
        ('destruction', 'Destruction'),
    ]
    
    disposal_number = models.CharField(max_length=50, unique=True)
    asset = models.OneToOneField(Asset, on_delete=models.CASCADE, related_name='disposal')
    
    disposal_date = models.DateField()
    disposal_method = models.CharField(max_length=20, choices=DISPOSAL_METHOD_CHOICES)
    disposal_value = models.DecimalField(max_digits=15, decimal_places=2, default=0)
    
    reason = models.TextField()
    buyer_details = models.TextField(blank=True)
    
    approved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'asset_disposals'

    def __str__(self):
        return f"{self.disposal_number} - {self.asset.asset_number}"


# ============================================================================
# CASE MANAGEMENT
# ============================================================================

class CaseCategory(models.Model):
    """Case categories"""
    name = models.CharField(max_length=200, unique=True)
    code = models.CharField(max_length=50, unique=True)
    description = models.TextField()
    is_active = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'case_categories'
        verbose_name_plural = 'case categories'

    def __str__(self):
        return self.name


class Case(models.Model):
    """Legal and administrative cases"""
    STATUS_CHOICES = [
        ('open', 'Open'),
        ('under_review', 'Under Review'),
        ('pending_hearing', 'Pending Hearing'),
        ('resolved', 'Resolved'),
        ('closed', 'Closed'),
        ('appealed', 'Appealed'),
    ]
    
    case_number = models.CharField(max_length=50, unique=True)
    category = models.ForeignKey(CaseCategory, on_delete=models.CASCADE, related_name='cases')
    
    title = models.CharField(max_length=500)
    description = models.TextField()
    
    complainant = models.ForeignKey(Citizen, on_delete=models.CASCADE, related_name='cases_filed', null=True, blank=True)
    respondent = models.ForeignKey(Citizen, on_delete=models.CASCADE, related_name='cases_responded', null=True, blank=True)
    
    filing_date = models.DateField()
    hearing_date = models.DateField(null=True, blank=True)
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='open')
    
    case_officer = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='assigned_cases')
    
    resolution = models.TextField(blank=True)
    resolution_date = models.DateField(null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'cases'

    def __str__(self):
        return f"{self.case_number} - {self.title}"


class CaseDocument(models.Model):
    """Case documents"""
    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name='documents')
    document_type = models.CharField(max_length=100)
    document_name = models.CharField(max_length=200)
    file = models.FileField(upload_to='cases/documents/')
    description = models.TextField(blank=True)
    
    uploaded_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'case_documents'

    def __str__(self):
        return f"{self.case.case_number} - {self.document_name}"


class CaseHearing(models.Model):
    """Case hearing records"""
    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name='hearings')
    hearing_date = models.DateTimeField()
    venue = models.CharField(max_length=200)
    
    proceedings = models.TextField(blank=True)
    decision = models.TextField(blank=True)
    
    presiding_officer = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'case_hearings'

    def __str__(self):
        return f"{self.case.case_number} - {self.hearing_date}"


# ============================================================================
# ELECTRONIC RECORDS MANAGEMENT
# ============================================================================

class DocumentCategory(models.Model):
    """Document categories"""
    name = models.CharField(max_length=200, unique=True)
    code = models.CharField(max_length=50, unique=True)
    description = models.TextField()
    retention_period_years = models.IntegerField(default=0)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'document_categories'
        verbose_name_plural = 'document categories'

    def __str__(self):
        return self.name


class ElectronicDocument(models.Model):
    """Electronic document management"""
    STATUS_CHOICES = [
        ('draft', 'Draft'),
        ('active', 'Active'),
        ('archived', 'Archived'),
        ('destroyed', 'Destroyed'),
    ]
    
    document_number = models.CharField(max_length=50, unique=True)
    title = models.CharField(max_length=500)
    category = models.ForeignKey(DocumentCategory, on_delete=models.CASCADE, related_name='documents')
    
    description = models.TextField(blank=True)
    
    file = models.FileField(upload_to='electronic_records/')
    file_size = models.BigIntegerField()
    file_type = models.CharField(max_length=50)
    
    department = models.ForeignKey(Department, on_delete=models.CASCADE)
    
    document_date = models.DateField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='draft')
    
    retention_until = models.DateField(null=True, blank=True)
    
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'electronic_documents'

    def __str__(self):
        return f"{self.document_number} - {self.title}"


class DocumentAccess(models.Model):
    """Document access log"""
    document = models.ForeignKey(ElectronicDocument, on_delete=models.CASCADE, related_name='access_logs')
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    access_type = models.CharField(max_length=20)  # view, download, edit
    access_date = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    
    class Meta:
        db_table = 'document_access'

    def __str__(self):
        return f"{self.document.document_number} - {self.user.username} - {self.access_type}"


# ============================================================================
# AUDIT TRAIL
# ============================================================================

class AuditLog(models.Model):
    """System-wide audit trail"""
    ACTION_CHOICES = [
        ('create', 'Create'),
        ('update', 'Update'),
        ('delete', 'Delete'),
        ('view', 'View'),
        ('approve', 'Approve'),
        ('reject', 'Reject'),
        ('reverse', 'Reverse'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    
    model_name = models.CharField(max_length=100)
    object_id = models.CharField(max_length=50)
    object_repr = models.CharField(max_length=200)
    
    changes = models.JSONField(null=True, blank=True)
    
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'audit_logs'
        indexes = [
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['model_name', 'object_id']),
        ]

    def __str__(self):
        return f"{self.user} - {self.action} - {self.model_name} - {self.timestamp}"


# ============================================================================
# NOTIFICATION SYSTEM
# ============================================================================

class Notification(models.Model):
    """System notifications"""
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('sent', 'Sent'),
        ('failed', 'Failed'),
    ]
    
    NOTIFICATION_TYPE_CHOICES = [
        ('sms', 'SMS'),
        ('email', 'Email'),
        ('system', 'System'),
    ]
    
    recipient = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    notification_type = models.CharField(max_length=20, choices=NOTIFICATION_TYPE_CHOICES)
    
    subject = models.CharField(max_length=200)
    message = models.TextField()
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    
    sent_at = models.DateTimeField(null=True, blank=True)
    read_at = models.DateTimeField(null=True, blank=True)
    
    related_model = models.CharField(max_length=100, blank=True)
    related_object_id = models.CharField(max_length=50, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'notifications'
        indexes = [
            models.Index(fields=['recipient', 'read_at']),
        ]

    def __str__(self):
        return f"{self.recipient.username} - {self.subject}"


# ============================================================================
# SYSTEM CONFIGURATION
# ============================================================================

class SystemConfiguration(models.Model):
    """System-wide configuration settings"""
    key = models.CharField(max_length=100, unique=True)
    value = models.TextField()
    description = models.TextField()
    data_type = models.CharField(max_length=20)  # string, integer, boolean, json
    is_editable = models.BooleanField(default=True)
    updated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'system_configuration'

    def __str__(self):
        return self.key


class BankReconciliation(models.Model):
    """Bank reconciliation records"""
    reconciliation_date = models.DateField()
    bank_account = models.CharField(max_length=100)
    opening_balance = models.DecimalField(max_digits=15, decimal_places=2)
    closing_balance = models.DecimalField(max_digits=15, decimal_places=2)
    total_receipts = models.DecimalField(max_digits=15, decimal_places=2)
    total_payments = models.DecimalField(max_digits=15, decimal_places=2)
    variance = models.DecimalField(max_digits=15, decimal_places=2)
    is_reconciled = models.BooleanField(default=False)
    reconciled_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    reconciled_at = models.DateTimeField(null=True, blank=True)
    notes = models.TextField(blank=True)
    
    class Meta:
        db_table = 'bank_reconciliations'

    def __str__(self):
        return f"Reconciliation - {self.reconciliation_date}"


# ============================================================================
# PERMITS & LICENSES
# ============================================================================

class BusinessCategory(models.Model):
    """Business categories for licensing"""
    name = models.CharField(max_length=200, unique=True)
    code = models.CharField(max_length=50, unique=True)
    description = models.TextField()
    parent_category = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'business_categories'
        verbose_name_plural = 'business categories'

    def __str__(self):
        return self.name


class LicenseType(models.Model):
    """Types of licenses/permits"""
    name = models.CharField(max_length=200, unique=True)
    code = models.CharField(max_length=50, unique=True)
    description = models.TextField()
    business_category = models.ForeignKey(BusinessCategory, on_delete=models.CASCADE, related_name='license_types')
    revenue_stream = models.ForeignKey(RevenueStream, on_delete=models.CASCADE)
    validity_period_days = models.IntegerField()
    is_renewable = models.BooleanField(default=True)
    requires_inspection = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'license_types'

    def __str__(self):
        return self.name


class LicenseRequirement(models.Model):
    """Requirements checklist for license application"""
    license_type = models.ForeignKey(LicenseType, on_delete=models.CASCADE, related_name='requirements')
    requirement_name = models.CharField(max_length=200)
    description = models.TextField()
    is_mandatory = models.BooleanField(default=True)
    display_order = models.IntegerField(default=0)
    
    class Meta:
        db_table = 'license_requirements'
        ordering = ['display_order']

    def __str__(self):
        return f"{self.license_type.code} - {self.requirement_name}"


class Business(models.Model):
    """Business registration"""
    business_number = models.CharField(max_length=50, unique=True)
    citizen = models.ForeignKey(Citizen, on_delete=models.CASCADE, related_name='businesses')
    business_name = models.CharField(max_length=200)
    trading_name = models.CharField(max_length=200, blank=True)
    business_category = models.ForeignKey(BusinessCategory, on_delete=models.CASCADE)
    registration_number = models.CharField(max_length=100, blank=True)
    
    physical_address = models.TextField()
    sub_county = models.ForeignKey(SubCounty, on_delete=models.CASCADE)
    ward = models.ForeignKey(Ward, on_delete=models.CASCADE)
    location = gis_models.PointField()
    plot_number = models.CharField(max_length=50, blank=True)
    
    nature_of_business = models.TextField()
    number_of_employees = models.IntegerField(default=0)
    annual_turnover = models.DecimalField(max_digits=15, decimal_places=2, null=True, blank=True)
    
    phone = models.CharField(max_length=15)
    email = models.EmailField(blank=True)
    
    is_active = models.BooleanField(default=True)
    registration_date = models.DateField()
    
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'businesses'
        verbose_name_plural = 'businesses'

    def __str__(self):
        return f"{self.business_number} - {self.business_name}"


class License(models.Model):
    """Business licenses and permits"""
    LICENSE_STATUS_CHOICES = [
        ('draft', 'Draft'),
        ('submitted', 'Submitted'),
        ('under_review', 'Under Review'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
        ('issued', 'Issued'),
        ('active', 'Active'),
        ('expired', 'Expired'),
        ('suspended', 'Suspended'),
        ('revoked', 'Revoked'),
    ]
    
    license_number = models.CharField(max_length=50, unique=True)
    business = models.ForeignKey(Business, on_delete=models.CASCADE, related_name='licenses')
    license_type = models.ForeignKey(LicenseType, on_delete=models.CASCADE)
    
    application_date = models.DateField()
    approval_date = models.DateField(null=True, blank=True)
    issue_date = models.DateField(null=True, blank=True)
    expiry_date = models.DateField(null=True, blank=True)
    
    status = models.CharField(max_length=20, choices=LICENSE_STATUS_CHOICES, default='draft')
    
    is_provisional = models.BooleanField(default=False)
    is_renewal = models.BooleanField(default=False)
    previous_license = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True, related_name='renewals')
    
    reviewed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='reviewed_licenses')
    approved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='approved_licenses')
    
    notes = models.TextField(blank=True)
    rejection_reason = models.TextField(blank=True)
    
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'licenses'

    def __str__(self):
        return f"{self.license_number} - {self.business.business_name}"


class LicenseDocument(models.Model):
    """Documents attached to license applications"""
    license = models.ForeignKey(License, on_delete=models.CASCADE, related_name='documents')
    requirement = models.ForeignKey(LicenseRequirement, on_delete=models.CASCADE, null=True, blank=True)
    document_name = models.CharField(max_length=200)
    file = models.FileField(upload_to='licenses/documents/')
    uploaded_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'license_documents'

    def __str__(self):
        return f"{self.license.license_number} - {self.document_name}"


# ============================================================================
# PARKING MANAGEMENT
# ============================================================================

class ParkingZone(models.Model):
    """Parking zones/areas"""
    name = models.CharField(max_length=200)
    code = models.CharField(max_length=50, unique=True)
    zone_type = models.CharField(max_length=50)
    sub_county = models.ForeignKey(SubCounty, on_delete=models.CASCADE)
    ward = models.ForeignKey(Ward, on_delete=models.CASCADE)
    boundary = gis_models.PolygonField(null=True, blank=True)
    capacity = models.IntegerField(default=0)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'parking_zones'

    def __str__(self):
        return f"{self.code} - {self.name}"


class Sacco(models.Model):
    """Vehicle Saccos/Organizations"""
    name = models.CharField(max_length=200, unique=True)
    registration_number = models.CharField(max_length=100, unique=True)
    citizen = models.ForeignKey(Citizen, on_delete=models.CASCADE, related_name='saccos')
    
    phone = models.CharField(max_length=15)
    email = models.EmailField(blank=True)
    physical_address = models.TextField()
    
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'saccos'

    def __str__(self):
        return self.name


class Vehicle(models.Model):
    """Vehicle registration"""
    registration_number = models.CharField(max_length=20, unique=True)
    owner = models.ForeignKey(Citizen, on_delete=models.CASCADE, related_name='vehicles')
    sacco = models.ForeignKey(Sacco, on_delete=models.SET_NULL, null=True, blank=True, related_name='vehicles')
    
    make = models.CharField(max_length=100)
    model = models.CharField(max_length=100)
    year = models.IntegerField()
    color = models.CharField(max_length=50)
    vehicle_type = models.CharField(max_length=50)
    
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'vehicles'

    def __str__(self):
        return f"{self.registration_number} - {self.make} {self.model}"


class ParkingPayment(models.Model):
    """Parking payment records"""
    PAYMENT_TYPE_CHOICES = [
        ('daily', 'Daily'),
        ('monthly', 'Monthly'),
        ('yearly', 'Yearly'),
        ('reserved', 'Reserved Parking'),
    ]
    
    vehicle = models.ForeignKey(Vehicle, on_delete=models.CASCADE, related_name='parking_payments')
    parking_zone = models.ForeignKey(ParkingZone, on_delete=models.CASCADE)
    payment_type = models.CharField(max_length=20, choices=PAYMENT_TYPE_CHOICES)
    payment = models.ForeignKey(Payment, on_delete=models.CASCADE)
    
    start_date = models.DateField()
    end_date = models.DateField()
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'parking_payments'

    def __str__(self):
        return f"{self.vehicle.registration_number} - {self.payment_type}"


class ClampingRecord(models.Model):
    """Vehicle clamping records"""
    CLAMPING_STATUS_CHOICES = [
        ('clamped', 'Clamped'),
        ('towed', 'Towed'),
        ('released', 'Released'),
    ]
    
    vehicle = models.ForeignKey(Vehicle, on_delete=models.CASCADE, related_name='clamping_records')
    clamping_number = models.CharField(max_length=50, unique=True)
    
    clamped_date = models.DateTimeField()
    clamped_location = gis_models.PointField()
    parking_zone = models.ForeignKey(ParkingZone, on_delete=models.CASCADE)
    
    reason = models.TextField()
    clamping_fee = models.DecimalField(max_digits=10, decimal_places=2)
    towing_fee = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    storage_fee = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    total_fee = models.DecimalField(max_digits=10, decimal_places=2)
    
    status = models.CharField(max_length=20, choices=CLAMPING_STATUS_CHOICES, default='clamped')
    
    clamped_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='clamping_actions')
    released_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='release_actions')
    released_date = models.DateTimeField(null=True, blank=True)
    
    payment = models.ForeignKey(Payment, on_delete=models.SET_NULL, null=True, blank=True)
    
    class Meta:
        db_table = 'clamping_records'

    def __str__(self):
        return f"{self.clamping_number} - {self.vehicle.registration_number}"


# ============================================================================
# OUTDOOR ADVERTISING - BILLBOARDS, SIGNAGE, BRANDING
# ============================================================================

class AdvertisingCategory(models.Model):
    """Categories for outdoor advertising"""
    name = models.CharField(max_length=100, unique=True)
    code = models.CharField(max_length=20, unique=True)
    description = models.TextField()
    is_active = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'advertising_categories'
        verbose_name_plural = 'advertising categories'

    def __str__(self):
        return self.name


class OutdoorAdvertising(models.Model):
    """Billboards, signage, and branding structures"""
    ADVERTISING_TYPE_CHOICES = [
        ('billboard', 'Billboard'),
        ('signage', 'Signage'),
        ('branding', 'Branding'),
    ]
    
    STATUS_CHOICES = [
        ('pending', 'Pending Approval'),
        ('approved', 'Approved'),
        ('active', 'Active'),
        ('expired', 'Expired'),
        ('removed', 'Removed'),
    ]
    
    reference_number = models.CharField(max_length=50, unique=True)
    owner = models.ForeignKey(Citizen, on_delete=models.CASCADE, related_name='outdoor_advertising')
    advertising_type = models.CharField(max_length=20, choices=ADVERTISING_TYPE_CHOICES)
    category = models.ForeignKey(AdvertisingCategory, on_delete=models.CASCADE)
    
    description = models.TextField()
    width = models.DecimalField(max_digits=10, decimal_places=2)
    height = models.DecimalField(max_digits=10, decimal_places=2)
    size_sqm = models.DecimalField(max_digits=10, decimal_places=2)
    
    location = gis_models.PointField()
    sub_county = models.ForeignKey(SubCounty, on_delete=models.CASCADE)
    ward = models.ForeignKey(Ward, on_delete=models.CASCADE)
    landmark = models.CharField(max_length=200)
    
    start_date = models.DateField()
    end_date = models.DateField()
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'outdoor_advertising'

    def __str__(self):
        return f"{self.reference_number} - {self.advertising_type}"


class OutdoorAdvertisingDocument(models.Model):
    """Documents for outdoor advertising"""
    advertising = models.ForeignKey(OutdoorAdvertising, on_delete=models.CASCADE, related_name='documents')
    document_type = models.CharField(max_length=100)
    file = models.FileField(upload_to='advertising/documents/')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'outdoor_advertising_documents'

    def __str__(self):
        return f"{self.advertising.reference_number} - {self.document_type}"


# ============================================================================
# PROPERTY & LAND MANAGEMENT
# ============================================================================

class PropertyType(models.Model):
    """Property classification types"""
    name = models.CharField(max_length=100, unique=True)
    code = models.CharField(max_length=20, unique=True)
    description = models.TextField()
    is_active = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'property_types'

    def __str__(self):
        return self.name


class LandUseType(models.Model):
    """Land use classifications"""
    name = models.CharField(max_length=100, unique=True)
    code = models.CharField(max_length=20, unique=True)
    description = models.TextField()
    is_active = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'land_use_types'

    def __str__(self):
        return self.name


class Property(models.Model):
    """Property/Land parcels"""
    PROPERTY_STATUS_CHOICES = [
        ('active', 'Active'),
        ('inactive', 'Inactive'),
        ('disputed', 'Disputed'),
        ('subdivided', 'Subdivided'),
        ('amalgamated', 'Amalgamated'),
    ]
    
    parcel_number = models.CharField(max_length=50, unique=True)
    original_parcel_number = models.CharField(max_length=50, blank=True)
    
    owner = models.ForeignKey(Citizen, on_delete=models.CASCADE, related_name='properties')
    
    property_type = models.ForeignKey(PropertyType, on_delete=models.CASCADE)
    land_use_type = models.ForeignKey(LandUseType, on_delete=models.CASCADE)
    
    area_sqm = models.DecimalField(max_digits=15, decimal_places=2)
    assessed_value = models.DecimalField(max_digits=15, decimal_places=2, null=True, blank=True)
    
    location = gis_models.PointField()
    boundary = gis_models.PolygonField(null=True, blank=True)
    sub_county = models.ForeignKey(SubCounty, on_delete=models.CASCADE)
    ward = models.ForeignKey(Ward, on_delete=models.CASCADE)
    
    street = models.CharField(max_length=200, blank=True)
    plot_number = models.CharField(max_length=50, blank=True)
    building_name = models.CharField(max_length=200, blank=True)
    
    status = models.CharField(max_length=20, choices=PROPERTY_STATUS_CHOICES, default='active')
    has_caveat = models.BooleanField(default=False)
    
    annual_rate = models.DecimalField(max_digits=15, decimal_places=2, default=0)
    
    registration_date = models.DateField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'properties'
        verbose_name_plural = 'properties'

    def __str__(self):
        return f"{self.parcel_number} - {self.owner}"


class PropertyOwnershipHistory(models.Model):
    """Property ownership transfer history"""
    property = models.ForeignKey(Property, on_delete=models.CASCADE, related_name='ownership_history')
    previous_owner = models.ForeignKey(Citizen, on_delete=models.CASCADE, related_name='previous_properties')
    new_owner = models.ForeignKey(Citizen, on_delete=models.CASCADE, related_name='acquired_properties')
    
    transfer_date = models.DateField()
    transfer_type = models.CharField(max_length=50)
    transfer_value = models.DecimalField(max_digits=15, decimal_places=2, null=True, blank=True)
    
    deed_number = models.CharField(max_length=100, blank=True)
    notes = models.TextField(blank=True)
    
    recorded_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    recorded_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'property_ownership_history'
        verbose_name_plural = 'property ownership histories'

    def __str__(self):
        return f"{self.property.parcel_number} - {self.transfer_date}"


class PropertySubdivision(models.Model):
    """Property subdivision records"""
    parent_property = models.ForeignKey(Property, on_delete=models.CASCADE, related_name='subdivisions')
    child_properties = models.ManyToManyField(Property, related_name='parent_subdivisions')
    
    subdivision_date = models.DateField()
    approval_number = models.CharField(max_length=100)
    surveyor = models.CharField(max_length=200)
    
    notes = models.TextField(blank=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'property_subdivisions'

    def __str__(self):
        return f"Subdivision - {self.parent_property.parcel_number}"


class PropertyAmalgamation(models.Model):
    """Property amalgamation records"""
    parent_properties = models.ManyToManyField(Property, related_name='amalgamations')
    new_property = models.ForeignKey(Property, on_delete=models.CASCADE, related_name='source_amalgamation')
    
    amalgamation_date = models.DateField()
    approval_number = models.CharField(max_length=100)
    surveyor = models.CharField(max_length=200)
    
    notes = models.TextField(blank=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'property_amalgamations'

    def __str__(self):
        return f"Amalgamation - {self.new_property.parcel_number}"


class PropertyCaveat(models.Model):
    """Property caveats"""
    property = models.ForeignKey(Property, on_delete=models.CASCADE, related_name='caveats')
    caveat_type = models.CharField(max_length=100)
    description = models.TextField()
    
    lodged_by = models.CharField(max_length=200)
    lodged_date = models.DateField()
    
    is_active = models.BooleanField(default=True)
    removed_date = models.DateField(null=True, blank=True)
    removal_reason = models.TextField(blank=True)
    
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'property_caveats'

    def __str__(self):
        return f"{self.property.parcel_number} - {self.caveat_type}"


class PropertyDocument(models.Model):
    """Documents attached to properties"""
    property = models.ForeignKey(Property, on_delete=models.CASCADE, related_name='documents')
    document_type = models.CharField(max_length=100)
    document_number = models.CharField(max_length=100, blank=True)
    file = models.FileField(upload_to='properties/documents/')
    description = models.TextField(blank=True)
    uploaded_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'property_documents'

    def __str__(self):
        return f"{self.property.parcel_number} - {self.document_type}"


class PropertyValuation(models.Model):
    """Property valuation records"""
    property = models.ForeignKey(Property, on_delete=models.CASCADE, related_name='valuations')
    valuation_date = models.DateField()
    valuation_method = models.CharField(max_length=100)
    land_value = models.DecimalField(max_digits=15, decimal_places=2)
    improvement_value = models.DecimalField(max_digits=15, decimal_places=2, default=0)
    total_value = models.DecimalField(max_digits=15, decimal_places=2)
    
    valuer_name = models.CharField(max_length=200)
    valuation_report = models.FileField(upload_to='valuations/', null=True, blank=True)
    
    is_current = models.BooleanField(default=True)
    
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'property_valuations'

    def __str__(self):
        return f"{self.property.parcel_number} - {self.valuation_date}"


# ============================================================================
# PHYSICAL PLANNING & DEVELOPMENT
# ============================================================================

class DevelopmentApplication(models.Model):
    """Development and building approval applications"""
    APPLICATION_TYPE_CHOICES = [
        ('building_plan', 'Building Plan Approval'),
        ('change_of_use', 'Change of Use'),
        ('subdivision', 'Subdivision'),
        ('amalgamation', 'Amalgamation'),
        ('extension', 'Extension'),
    ]
    
    STATUS_CHOICES = [
        ('submitted', 'Submitted'),
        ('under_review', 'Under Review'),
        ('site_visit', 'Site Visit Scheduled'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
        ('conditional', 'Conditionally Approved'),
    ]
    
    application_number = models.CharField(max_length=50, unique=True)
    applicant = models.ForeignKey(Citizen, on_delete=models.CASCADE, related_name='development_applications')
    property = models.ForeignKey(Property, on_delete=models.CASCADE, related_name='development_applications')
    
    application_type = models.CharField(max_length=50, choices=APPLICATION_TYPE_CHOICES)
    description = models.TextField()
    
    proposed_use = models.CharField(max_length=200)
    estimated_cost = models.DecimalField(max_digits=15, decimal_places=2, null=True, blank=True)
    floor_area = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    
    application_date = models.DateField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='submitted')
    
    reviewed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='reviewed_developments')
    approved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='approved_developments')
    approval_date = models.DateField(null=True, blank=True)
    
    conditions = models.TextField(blank=True)
    rejection_reason = models.TextField(blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'development_applications'

    def __str__(self):
        return f"{self.application_number} - {self.application_type}"


class DevelopmentDocument(models.Model):
    """Documents for development applications"""
    application = models.ForeignKey(DevelopmentApplication, on_delete=models.CASCADE, related_name='documents')
    document_type = models.CharField(max_length=100)
    file = models.FileField(upload_to='development/documents/')
    uploaded_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'development_documents'

    def __str__(self):
        return f"{self.application.application_number} - {self.document_type}"



# ============================================================================
# FINES & PENALTIES
# ============================================================================

class FineCategory(models.Model):
    """Categories of fines"""
    name = models.CharField(max_length=200, unique=True)
    code = models.CharField(max_length=50, unique=True)
    description = models.TextField()
    revenue_stream = models.ForeignKey(RevenueStream, on_delete=models.CASCADE)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'fine_categories'
        verbose_name_plural = 'fine categories'

    def __str__(self):
        return self.name


class Fine(models.Model):
    """Fines and penalties issued"""
    STATUS_CHOICES = [
        ('issued', 'Issued'),
        ('paid', 'Paid'),
        ('partially_paid', 'Partially Paid'),
        ('waived', 'Waived'),
        ('cancelled', 'Cancelled'),
    ]
    
    fine_number = models.CharField(max_length=50, unique=True)
    category = models.ForeignKey(FineCategory, on_delete=models.CASCADE, related_name='fines')
    offender = models.ForeignKey(Citizen, on_delete=models.CASCADE, related_name='fines')
    
    offense_description = models.TextField()
    offense_date = models.DateField()
    offense_location = gis_models.PointField(null=True, blank=True)
    
    fine_amount = models.DecimalField(max_digits=10, decimal_places=2)
    amount_paid = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    balance = models.DecimalField(max_digits=10, decimal_places=2)
    
    due_date = models.DateField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='issued')
    
    issued_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='issued_fines')
    issued_date = models.DateField()
    
    payment = models.ForeignKey(Payment, on_delete=models.SET_NULL, null=True, blank=True)
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    
    def __str__(self):
        return f"{self.fine_number} - {self.offender}"
    
class FinePayment(models.Model):
    """Payments made towards fines"""
    fine = models.ForeignKey(Fine, on_delete=models.CASCADE, related_name='payments')
    payment = models.ForeignKey(Payment, on_delete=models.CASCADE)
    amount_paid = models.DecimalField(max_digits=10, decimal_places=2)
    payment_date = models.DateField()
    
    recorded_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    recorded_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'fine_payments'

    def __str__(self):
        return f"{self.fine.fine_number} - {self.amount_paid}"
    
