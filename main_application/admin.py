"""
Wajir County Government ERP System - Django Admin Configuration
Complete admin interface for all modules
"""

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.gis.admin import GISModelAdmin
from django.utils.html import format_html
from django.urls import reverse
from django.db.models import Count, Sum
from .models import *


# ============================================================================
# CORE MODELS - User Management & Authentication
# ============================================================================

@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = ['username', 'get_full_name', 'email', 'employee_number', 'department', 'is_active_staff', 'is_staff']
    list_filter = ['is_active', 'is_staff', 'is_superuser', 'department', 'sub_county']
    search_fields = ['username', 'first_name', 'last_name', 'email', 'employee_number', 'phone_number', 'id_number']
    ordering = ['-date_joined']
    
    fieldsets = BaseUserAdmin.fieldsets + (
        ('County Information', {
            'fields': ('employee_number', 'phone_number', 'id_number', 'department', 'sub_county', 'is_active_staff', 'biometric_id')
        }),
    )


@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    list_display = ['name', 'parent_role', 'is_active', 'permission_count', 'created_at']
    list_filter = ['is_active', 'created_at']
    search_fields = ['name', 'description']
    filter_horizontal = ['permissions']
    
    def permission_count(self, obj):
        return obj.permissions.count()
    permission_count.short_description = 'Permissions'


@admin.register(Permission)
class PermissionAdmin(admin.ModelAdmin):
    list_display = ['name', 'codename', 'module']
    list_filter = ['module']
    search_fields = ['name', 'codename', 'module']


@admin.register(UserRole)
class UserRoleAdmin(admin.ModelAdmin):
    list_display = ['user', 'role', 'assigned_by', 'assigned_at', 'expires_at', 'is_active']
    list_filter = ['is_active', 'assigned_at', 'role']
    search_fields = ['user__username', 'role__name']
    date_hierarchy = 'assigned_at'


# ============================================================================
# ADMINISTRATIVE STRUCTURE
# ============================================================================

@admin.register(County)
class CountyAdmin(GISModelAdmin):
    list_display = ['name', 'code', 'county_number', 'headquarters', 'area_sq_km']
    search_fields = ['name', 'code']


@admin.register(SubCounty)
class SubCountyAdmin(GISModelAdmin):
    list_display = ['name', 'code', 'county', 'headquarters', 'is_active']
    list_filter = ['county', 'is_active']
    search_fields = ['name', 'code']


@admin.register(Ward)
class WardAdmin(GISModelAdmin):
    list_display = ['name', 'code', 'sub_county', 'population', 'is_active']
    list_filter = ['sub_county', 'is_active']
    search_fields = ['name', 'code']


@admin.register(Department)
class DepartmentAdmin(admin.ModelAdmin):
    list_display = ['name', 'code', 'parent_department', 'head_of_department', 'is_active']
    list_filter = ['is_active', 'parent_department']
    search_fields = ['name', 'code']


# ============================================================================
# CITIZEN MANAGEMENT
# ============================================================================

class CitizenDocumentInline(admin.TabularInline):
    model = CitizenDocument
    extra = 0


@admin.register(Citizen)
class CitizenAdmin(GISModelAdmin):
    list_display = ['unique_identifier', 'get_name', 'entity_type', 'phone_primary', 'sub_county', 'ward', 'is_active']
    list_filter = ['entity_type', 'sub_county', 'ward', 'is_active', 'has_portal_access']
    search_fields = ['unique_identifier', 'first_name', 'last_name', 'business_name', 'email', 'phone_primary', 'id_number']
    date_hierarchy = 'created_at'
    inlines = [CitizenDocumentInline]
    
    def get_name(self, obj):
        if obj.entity_type == 'individual':
            return f"{obj.first_name} {obj.last_name}"
        return obj.business_name
    get_name.short_description = 'Name'


# ============================================================================
# REVENUE MANAGEMENT
# ============================================================================

@admin.register(RevenueStream)
class RevenueStreamAdmin(admin.ModelAdmin):
    list_display = ['code', 'name', 'department', 'is_recurring', 'billing_frequency', 'is_active']
    list_filter = ['department', 'is_recurring', 'is_active']
    search_fields = ['name', 'code']


@admin.register(ChargeRate)
class ChargeRateAdmin(admin.ModelAdmin):
    list_display = ['revenue_stream', 'name', 'rate_type', 'amount', 'effective_from', 'effective_to', 'is_active']
    list_filter = ['revenue_stream', 'is_active', 'effective_from']
    search_fields = ['name', 'revenue_stream__name']
    date_hierarchy = 'effective_from'


@admin.register(PenaltyRule)
class PenaltyRuleAdmin(admin.ModelAdmin):
    list_display = ['revenue_stream', 'name', 'grace_period_days', 'penalty_type', 'penalty_amount', 'is_active']
    list_filter = ['revenue_stream', 'penalty_type', 'is_active']
    search_fields = ['name', 'revenue_stream__name']


@admin.register(RevenueBudget)
class RevenueBudgetAdmin(admin.ModelAdmin):
    list_display = ['revenue_stream', 'financial_year', 'period_type', 'target_amount', 'sub_county', 'ward']
    list_filter = ['financial_year', 'period_type', 'revenue_stream', 'sub_county']
    search_fields = ['revenue_stream__name', 'financial_year']
    date_hierarchy = 'created_at'


# ============================================================================
# BILLING & INVOICING
# ============================================================================

class BillLineItemInline(admin.TabularInline):
    model = BillLineItem
    extra = 0


@admin.register(Bill)
class BillAdmin(admin.ModelAdmin):
    list_display = ['bill_number', 'citizen', 'revenue_stream', 'bill_date', 'due_date', 'total_amount', 'amount_paid', 'balance', 'status_badge']
    list_filter = ['status', 'revenue_stream', 'sub_county', 'ward', 'bill_date', 'due_date']
    search_fields = ['bill_number', 'citizen__first_name', 'citizen__last_name', 'citizen__business_name']
    date_hierarchy = 'bill_date'
    inlines = [BillLineItemInline]
    readonly_fields = ['bill_number', 'created_at', 'updated_at']
    
    def status_badge(self, obj):
        colors = {
            'paid': 'green',
            'partially_paid': 'orange',
            'overdue': 'red',
            'issued': 'blue',
            'draft': 'gray',
        }
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 10px; border-radius: 3px;">{}</span>',
            colors.get(obj.status, 'gray'),
            obj.get_status_display()
        )
    status_badge.short_description = 'Status'


# ============================================================================
# PAYMENT MANAGEMENT
# ============================================================================

@admin.register(PaymentMethod)
class PaymentMethodAdmin(admin.ModelAdmin):
    list_display = ['name', 'code', 'provider', 'is_online', 'is_active']
    list_filter = ['is_online', 'is_active']
    search_fields = ['name', 'code', 'provider']


@admin.register(Payment)
class PaymentAdmin(admin.ModelAdmin):
    list_display = ['receipt_number', 'payer_name', 'amount', 'payment_method', 'revenue_stream', 'payment_date', 'status_badge']
    list_filter = ['status', 'payment_method', 'revenue_stream', 'sub_county', 'payment_date']
    search_fields = ['receipt_number', 'transaction_reference', 'payer_name', 'payer_phone']
    date_hierarchy = 'payment_date'
    readonly_fields = ['receipt_number', 'created_at', 'updated_at']
    
    def status_badge(self, obj):
        colors = {
            'completed': 'green',
            'pending': 'orange',
            'processing': 'blue',
            'failed': 'red',
        }
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 10px; border-radius: 3px;">{}</span>',
            colors.get(obj.status, 'gray'),
            obj.get_status_display()
        )
    status_badge.short_description = 'Status'


@admin.register(PaymentReversal)
class PaymentReversalAdmin(admin.ModelAdmin):
    list_display = ['payment', 'created_at']
    search_fields = ['payment__receipt_number']
    date_hierarchy = 'created_at'


# ============================================================================
# HOSPITAL MANAGEMENT
# ============================================================================

@admin.register(Patient)
class PatientAdmin(admin.ModelAdmin):
    list_display = ['patient_number', 'get_full_name', 'gender', 'date_of_birth', 'phone', 'is_active']
    list_filter = ['gender', 'is_active', 'registered_at']
    search_fields = ['patient_number', 'first_name', 'last_name', 'id_number', 'phone']
    date_hierarchy = 'registered_at'
    
    def get_full_name(self, obj):
        return f"{obj.first_name} {obj.last_name}"
    get_full_name.short_description = 'Full Name'


@admin.register(HealthFacility)
class HealthFacilityAdmin(GISModelAdmin):
    list_display = ['name', 'code', 'facility_level', 'sub_county', 'ward', 'bed_capacity', 'is_active']
    list_filter = ['facility_level', 'sub_county', 'ward', 'is_active']
    search_fields = ['name', 'code']


@admin.register(Triage)
class TriageAdmin(admin.ModelAdmin):
    list_display = ['patient', 'facility', 'visit_date', 'priority', 'triaged_by']
    list_filter = ['priority', 'facility', 'visit_date']
    search_fields = ['patient__patient_number', 'patient__first_name', 'patient__last_name']
    date_hierarchy = 'visit_date'


@admin.register(Visit)
class VisitAdmin(admin.ModelAdmin):
    list_display = ['visit_number', 'patient', 'facility', 'visit_type', 'visit_date', 'attended_by', 'is_complete']
    list_filter = ['visit_type', 'facility', 'is_complete', 'visit_date']
    search_fields = ['visit_number', 'patient__patient_number']
    date_hierarchy = 'visit_date'


@admin.register(HospitalWard)
class HospitalWardAdmin(admin.ModelAdmin):
    list_display = ['name', 'facility', 'ward_type', 'bed_capacity', 'is_active']
    list_filter = ['facility', 'is_active']
    search_fields = ['name', 'ward_type']


@admin.register(Admission)
class AdmissionAdmin(admin.ModelAdmin):
    list_display = ['admission_number', 'patient', 'ward', 'bed_number', 'admission_date', 'discharge_date', 'status']
    list_filter = ['status', 'ward', 'admission_date']
    search_fields = ['admission_number', 'patient__patient_number']
    date_hierarchy = 'admission_date'


@admin.register(LabTest)
class LabTestAdmin(admin.ModelAdmin):
    list_display = ['test_number', 'patient', 'test_name', 'test_category', 'requested_date', 'status', 'test_cost']
    list_filter = ['status', 'test_category', 'requested_date']
    search_fields = ['test_number', 'test_name', 'patient__patient_number']
    date_hierarchy = 'requested_date'


@admin.register(Imaging)
class ImagingAdmin(admin.ModelAdmin):
    list_display = ['imaging_number', 'patient', 'imaging_type', 'body_part', 'requested_date', 'status', 'imaging_cost']
    list_filter = ['status', 'imaging_type', 'requested_date']
    search_fields = ['imaging_number', 'imaging_type', 'patient__patient_number']
    date_hierarchy = 'requested_date'


@admin.register(Prescription)
class PrescriptionAdmin(admin.ModelAdmin):
    list_display = ['prescription_number', 'patient', 'medication_name', 'dosage', 'quantity', 'status', 'prescribed_by']
    list_filter = ['status', 'dispensed_date']
    search_fields = ['prescription_number', 'medication_name', 'patient__patient_number']


@admin.register(MorgueRecord)
class MorgueRecordAdmin(admin.ModelAdmin):
    list_display = ['morgue_number', 'deceased_name', 'age', 'gender', 'date_of_death', 'compartment_number', 'status']
    list_filter = ['status', 'facility', 'date_of_death']
    search_fields = ['morgue_number', 'deceased_name']
    date_hierarchy = 'date_of_death'


# ============================================================================
# FLEET MANAGEMENT
# ============================================================================

@admin.register(FleetVehicle)
class FleetVehicleAdmin(admin.ModelAdmin):
    list_display = ['fleet_number', 'registration_number', 'vehicle_type', 'make', 'model', 'department', 'current_driver', 'status']
    list_filter = ['vehicle_type', 'status', 'department', 'fuel_type']
    search_fields = ['fleet_number', 'registration_number', 'make', 'model']


@admin.register(FuelStation)
class FuelStationAdmin(GISModelAdmin):
    list_display = ['name', 'code', 'is_active']
    list_filter = ['is_active']
    search_fields = ['name', 'code']


@admin.register(FuelCard)
class FuelCardAdmin(admin.ModelAdmin):
    list_display = ['card_number', 'vehicle', 'daily_limit', 'monthly_limit', 'is_active', 'expiry_date']
    list_filter = ['is_active', 'expiry_date']
    search_fields = ['card_number', 'vehicle__registration_number']


@admin.register(FuelTransaction)
class FuelTransactionAdmin(admin.ModelAdmin):
    list_display = ['transaction_number', 'vehicle', 'transaction_type', 'fuel_station', 'quantity_liters', 'total_amount', 'transaction_date']
    list_filter = ['transaction_type', 'fuel_station', 'transaction_date']
    search_fields = ['transaction_number', 'vehicle__registration_number']
    date_hierarchy = 'transaction_date'


@admin.register(VehicleMaintenance)
class VehicleMaintenanceAdmin(admin.ModelAdmin):
    list_display = ['maintenance_number', 'vehicle', 'maintenance_type', 'scheduled_date', 'cost', 'status']
    list_filter = ['maintenance_type', 'status', 'scheduled_date']
    search_fields = ['maintenance_number', 'vehicle__registration_number']
    date_hierarchy = 'scheduled_date'


@admin.register(VehicleTrip)
class VehicleTripAdmin(admin.ModelAdmin):
    list_display = ['trip_number', 'vehicle', 'driver', 'destination', 'scheduled_departure', 'status']
    list_filter = ['status', 'scheduled_departure']
    search_fields = ['trip_number', 'vehicle__registration_number', 'destination']
    date_hierarchy = 'scheduled_departure'


# ============================================================================
# FACILITIES
# ============================================================================

@admin.register(FacilityCategory)
class FacilityCategoryAdmin(admin.ModelAdmin):
    list_display = ['name', 'code', 'is_active']
    list_filter = ['is_active']
    search_fields = ['name', 'code']


@admin.register(Facility)
class FacilityAdmin(GISModelAdmin):
    list_display = ['name', 'code', 'facility_type', 'category', 'sub_county', 'ward', 'capacity', 'is_active']
    list_filter = ['facility_type', 'category', 'sub_county', 'ward', 'is_active']
    search_fields = ['name', 'code']


@admin.register(FacilityUnit)
class FacilityUnitAdmin(admin.ModelAdmin):
    list_display = ['unit_number', 'facility', 'unit_type', 'status', 'current_tenant', 'rental_rate_monthly']
    list_filter = ['unit_type', 'status', 'facility']
    search_fields = ['unit_number', 'facility__name']


@admin.register(FacilityTenancy)
class FacilityTenancyAdmin(admin.ModelAdmin):
    list_display = ['tenancy_number', 'unit', 'tenant', 'start_date', 'end_date', 'rental_amount', 'status']
    list_filter = ['status', 'payment_frequency', 'start_date']
    search_fields = ['tenancy_number', 'tenant__first_name', 'tenant__last_name']
    date_hierarchy = 'start_date'


@admin.register(FacilityBooking)
class FacilityBookingAdmin(admin.ModelAdmin):
    list_display = ['booking_number', 'facility', 'customer', 'booking_date', 'booking_fee', 'status']
    list_filter = ['status', 'facility', 'booking_date']
    search_fields = ['booking_number', 'customer__first_name', 'customer__last_name']
    date_hierarchy = 'booking_date'


# ============================================================================
# HUMAN RESOURCE MANAGEMENT
# ============================================================================

@admin.register(BiometricDevice)
class BiometricDeviceAdmin(admin.ModelAdmin):
    list_display = ['device_id', 'device_name', 'location', 'ip_address', 'is_active']
    list_filter = ['is_active', 'facility']
    search_fields = ['device_id', 'device_name', 'location']


@admin.register(Attendance)
class AttendanceAdmin(GISModelAdmin):
    list_display = ['employee', 'attendance_date', 'attendance_time', 'attendance_type', 'biometric_verified', 'device']
    list_filter = ['attendance_type', 'biometric_verified', 'attendance_date', 'device']
    search_fields = ['employee__username', 'employee__first_name', 'employee__last_name']
    date_hierarchy = 'attendance_date'


@admin.register(LeaveType)
class LeaveTypeAdmin(admin.ModelAdmin):
    list_display = ['name', 'code', 'days_per_year', 'is_paid', 'requires_approval', 'is_active']
    list_filter = ['is_paid', 'requires_approval', 'is_active']
    search_fields = ['name', 'code']


@admin.register(LeaveApplication)
class LeaveApplicationAdmin(admin.ModelAdmin):
    list_display = ['application_number', 'employee', 'leave_type', 'start_date', 'end_date', 'days_requested', 'status']
    list_filter = ['status', 'leave_type', 'start_date']
    search_fields = ['application_number', 'employee__username']
    date_hierarchy = 'start_date'


@admin.register(Transfer)
class TransferAdmin(admin.ModelAdmin):
    list_display = ['transfer_number', 'employee', 'from_department', 'to_department', 'effective_date', 'status']
    list_filter = ['status', 'from_department', 'to_department', 'effective_date']
    search_fields = ['transfer_number', 'employee__username']
    date_hierarchy = 'effective_date'


@admin.register(PerformanceReview)
class PerformanceReviewAdmin(admin.ModelAdmin):
    list_display = ['review_number', 'employee', 'review_period_start', 'review_period_end', 'rating', 'status']
    list_filter = ['status', 'rating', 'review_period_start']
    search_fields = ['review_number', 'employee__username']


@admin.register(TrainingProgram)
class TrainingProgramAdmin(admin.ModelAdmin):
    list_display = ['program_name', 'program_code', 'provider', 'start_date', 'end_date', 'duration_days', 'max_participants']
    list_filter = ['start_date', 'is_active']
    search_fields = ['program_name', 'program_code', 'provider']
    date_hierarchy = 'start_date'


@admin.register(TrainingParticipant)
class TrainingParticipantAdmin(admin.ModelAdmin):
    list_display = ['employee', 'program', 'nomination_date', 'status', 'attendance_percentage', 'certificate_issued']
    list_filter = ['status', 'certificate_issued', 'program']
    search_fields = ['employee__username', 'program__program_name']


@admin.register(DisciplinaryCase)
class DisciplinaryCaseAdmin(admin.ModelAdmin):
    list_display = ['case_number', 'employee', 'offense_date', 'report_date', 'status']
    list_filter = ['status', 'offense_date', 'report_date']
    search_fields = ['case_number', 'employee__username']
    date_hierarchy = 'report_date'


@admin.register(StaffDocument)
class StaffDocumentAdmin(admin.ModelAdmin):
    list_display = ['employee', 'document_type', 'document_number', 'expiry_date', 'uploaded_at']
    list_filter = ['document_type', 'expiry_date']
    search_fields = ['employee__username', 'document_type']


# ============================================================================
# STORES & INVENTORY
# ============================================================================

@admin.register(Store)
class StoreAdmin(GISModelAdmin):
    list_display = ['name', 'code', 'sub_county', 'store_keeper', 'is_active']
    list_filter = ['sub_county', 'is_active']
    search_fields = ['name', 'code']


@admin.register(ItemCategory)
class ItemCategoryAdmin(admin.ModelAdmin):
    list_display = ['name', 'code', 'parent_category', 'is_active']
    list_filter = ['parent_category', 'is_active']
    search_fields = ['name', 'code']


@admin.register(InventoryItem)
class InventoryItemAdmin(admin.ModelAdmin):
    list_display = ['item_code', 'name', 'category', 'item_type', 'unit_of_measure', 'unit_cost', 'reorder_level']
    list_filter = ['category', 'item_type', 'is_active']
    search_fields = ['item_code', 'name']


@admin.register(StoreStock)
class StoreStockAdmin(admin.ModelAdmin):
    list_display = ['store', 'item', 'quantity', 'reserved_quantity', 'available_quantity', 'last_updated']
    list_filter = ['store', 'last_updated']
    search_fields = ['store__name', 'item__name']


@admin.register(GoodsReceiptNote)
class GoodsReceiptNoteAdmin(admin.ModelAdmin):
    list_display = ['grn_number', 'store', 'supplier', 'receipt_date', 'status']
    list_filter = ['status', 'store', 'receipt_date']
    search_fields = ['grn_number', 'supplier']
    date_hierarchy = 'receipt_date'


@admin.register(StoreRequisition)
class StoreRequisitionAdmin(admin.ModelAdmin):
    list_display = ['requisition_number', 'department', 'store', 'requisition_date', 'required_date', 'status']
    list_filter = ['status', 'department', 'store', 'requisition_date']
    search_fields = ['requisition_number']
    date_hierarchy = 'requisition_date'


# ============================================================================
# ASSET MANAGEMENT
# ============================================================================

@admin.register(AssetCategory)
class AssetCategoryAdmin(admin.ModelAdmin):
    list_display = ['name', 'code', 'depreciation_rate', 'useful_life_years', 'is_active']
    list_filter = ['is_active']
    search_fields = ['name', 'code']


@admin.register(Asset)
class AssetAdmin(GISModelAdmin):
    list_display = ['asset_number', 'name', 'category', 'asset_type', 'department', 'acquisition_cost', 'current_value', 'status']
    list_filter = ['asset_type', 'status', 'category', 'department', 'sub_county']
    search_fields = ['asset_number', 'name', 'serial_number', 'barcode']
    date_hierarchy = 'acquisition_date'


@admin.register(AssetTransfer)
class AssetTransferAdmin(admin.ModelAdmin):
    list_display = ['transfer_number', 'asset', 'from_department', 'to_department', 'transfer_date', 'status']
    list_filter = ['status', 'from_department', 'to_department', 'transfer_date']
    search_fields = ['transfer_number', 'asset__asset_number']
    date_hierarchy = 'transfer_date'


@admin.register(AssetMaintenance)
class AssetMaintenanceAdmin(admin.ModelAdmin):
    list_display = ['asset', 'maintenance_type', 'maintenance_date', 'cost', 'service_provider']
    list_filter = ['maintenance_type', 'maintenance_date']
    search_fields = ['asset__asset_number', 'service_provider']
    date_hierarchy = 'maintenance_date'


@admin.register(AssetDisposal)
class AssetDisposalAdmin(admin.ModelAdmin):
    list_display = ['disposal_number', 'asset', 'disposal_date', 'disposal_method', 'disposal_value']
    list_filter = ['disposal_method', 'disposal_date']
    search_fields = ['disposal_number', 'asset__asset_number']
    date_hierarchy = 'disposal_date'


# ============================================================================
# CASE MANAGEMENT
# ============================================================================

@admin.register(CaseCategory)
class CaseCategoryAdmin(admin.ModelAdmin):
    list_display = ['name', 'code', 'is_active']
    list_filter = ['is_active']
    search_fields = ['name', 'code']


@admin.register(Case)
class CaseAdmin(admin.ModelAdmin):
    list_display = ['case_number', 'category', 'title', 'filing_date', 'hearing_date', 'status', 'case_officer']
    list_filter = ['status', 'category', 'filing_date', 'hearing_date']
    search_fields = ['case_number', 'title']
    date_hierarchy = 'filing_date'


@admin.register(CaseHearing)
class CaseHearingAdmin(admin.ModelAdmin):
    list_display = ['case', 'hearing_date', 'venue', 'presiding_officer']
    list_filter = ['hearing_date']
    search_fields = ['case__case_number', 'venue']
    date_hierarchy = 'hearing_date'


# ============================================================================
# DOCUMENT MANAGEMENT
# ============================================================================

@admin.register(DocumentCategory)
class DocumentCategoryAdmin(admin.ModelAdmin):
    list_display = ['name', 'code', 'retention_period_years', 'is_active']
    list_filter = ['is_active']
    search_fields = ['name', 'code']


@admin.register(ElectronicDocument)
class ElectronicDocumentAdmin(admin.ModelAdmin):
    list_display = ['document_number', 'title', 'category', 'department', 'document_date', 'status']
    list_filter = ['status', 'category', 'department', 'document_date']
    search_fields = ['document_number', 'title']
    date_hierarchy = 'document_date'


# ============================================================================
# PERMITS & LICENSES
# ============================================================================

@admin.register(BusinessCategory)
class BusinessCategoryAdmin(admin.ModelAdmin):
    list_display = ['name', 'code', 'parent_category', 'is_active']
    list_filter = ['parent_category', 'is_active']
    search_fields = ['name', 'code']


@admin.register(LicenseType)
class LicenseTypeAdmin(admin.ModelAdmin):
    list_display = ['name', 'code', 'business_category', 'validity_period_days', 'is_renewable', 'requires_inspection']
    list_filter = ['business_category', 'is_renewable', 'requires_inspection', 'is_active']
    search_fields = ['name', 'code']


@admin.register(Business)
class BusinessAdmin(GISModelAdmin):
    list_display = ['business_number', 'business_name', 'business_category', 'sub_county', 'ward', 'is_active']
    list_filter = ['business_category', 'sub_county', 'ward', 'is_active']
    search_fields = ['business_number', 'business_name', 'trading_name']
    date_hierarchy = 'registration_date'


@admin.register(License)
class LicenseAdmin(admin.ModelAdmin):
    list_display = ['license_number', 'business', 'license_type', 'application_date', 'expiry_date', 'status_badge', 'is_renewal']
    list_filter = ['status', 'license_type', 'is_provisional', 'is_renewal', 'application_date']
    search_fields = ['license_number', 'business__business_name']
    date_hierarchy = 'application_date'
    
    def status_badge(self, obj):
        colors = {
            'active': 'green',
            'approved': 'blue',
            'issued': 'green',
            'expired': 'red',
            'suspended': 'orange',
            'revoked': 'red',
            'rejected': 'red',
        }
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 10px; border-radius: 3px;">{}</span>',
            colors.get(obj.status, 'gray'),
            obj.get_status_display()
        )
    status_badge.short_description = 'Status'


@admin.register(LicenseRequirement)
class LicenseRequirementAdmin(admin.ModelAdmin):
    list_display = ['license_type', 'requirement_name', 'is_mandatory', 'display_order']
    list_filter = ['license_type', 'is_mandatory']
    search_fields = ['requirement_name', 'license_type__name']
    ordering = ['display_order']


# ============================================================================
# PARKING MANAGEMENT
# ============================================================================

@admin.register(ParkingZone)
class ParkingZoneAdmin(GISModelAdmin):
    list_display = ['name', 'code', 'zone_type', 'sub_county', 'ward', 'capacity', 'is_active']
    list_filter = ['zone_type', 'sub_county', 'ward', 'is_active']
    search_fields = ['name', 'code']


@admin.register(Sacco)
class SaccoAdmin(admin.ModelAdmin):
    list_display = ['name', 'registration_number', 'phone', 'email', 'is_active']
    list_filter = ['is_active']
    search_fields = ['name', 'registration_number']


@admin.register(Vehicle)
class VehicleAdmin(admin.ModelAdmin):
    list_display = ['registration_number', 'owner', 'sacco', 'make', 'model', 'year', 'vehicle_type', 'is_active']
    list_filter = ['vehicle_type', 'sacco', 'is_active', 'year']
    search_fields = ['registration_number', 'make', 'model', 'owner__first_name', 'owner__last_name']


@admin.register(ParkingPayment)
class ParkingPaymentAdmin(admin.ModelAdmin):
    list_display = ['vehicle', 'parking_zone', 'payment_type', 'start_date', 'end_date', 'amount']
    list_filter = ['payment_type', 'parking_zone', 'start_date']
    search_fields = ['vehicle__registration_number']
    date_hierarchy = 'start_date'


@admin.register(ClampingRecord)
class ClampingRecordAdmin(GISModelAdmin):
    list_display = ['clamping_number', 'vehicle', 'clamped_date', 'parking_zone', 'total_fee', 'status', 'clamped_by']
    list_filter = ['status', 'parking_zone', 'clamped_date']
    search_fields = ['clamping_number', 'vehicle__registration_number']
    date_hierarchy = 'clamped_date'


# ============================================================================
# OUTDOOR ADVERTISING
# ============================================================================

@admin.register(AdvertisingCategory)
class AdvertisingCategoryAdmin(admin.ModelAdmin):
    list_display = ['name', 'code', 'is_active']
    list_filter = ['is_active']
    search_fields = ['name', 'code']


@admin.register(OutdoorAdvertising)
class OutdoorAdvertisingAdmin(GISModelAdmin):
    list_display = ['reference_number', 'owner', 'advertising_type', 'category', 'size_sqm', 'sub_county', 'ward', 'status']
    list_filter = ['advertising_type', 'category', 'status', 'sub_county', 'ward']
    search_fields = ['reference_number', 'owner__first_name', 'owner__last_name', 'owner__business_name']
    date_hierarchy = 'start_date'


# ============================================================================
# PROPERTY & LAND MANAGEMENT
# ============================================================================

@admin.register(PropertyType)
class PropertyTypeAdmin(admin.ModelAdmin):
    list_display = ['name', 'code', 'is_active']
    list_filter = ['is_active']
    search_fields = ['name', 'code']


@admin.register(LandUseType)
class LandUseTypeAdmin(admin.ModelAdmin):
    list_display = ['name', 'code', 'is_active']
    list_filter = ['is_active']
    search_fields = ['name', 'code']


@admin.register(Property)
class PropertyAdmin(GISModelAdmin):
    list_display = ['parcel_number', 'owner', 'property_type', 'land_use_type', 'area_sqm', 'assessed_value', 'sub_county', 'ward', 'status']
    list_filter = ['property_type', 'land_use_type', 'status', 'sub_county', 'ward', 'has_caveat']
    search_fields = ['parcel_number', 'original_parcel_number', 'owner__first_name', 'owner__last_name']
    date_hierarchy = 'registration_date'


@admin.register(PropertyOwnershipHistory)
class PropertyOwnershipHistoryAdmin(admin.ModelAdmin):
    list_display = ['property', 'previous_owner', 'new_owner', 'transfer_date', 'transfer_type', 'transfer_value']
    list_filter = ['transfer_type', 'transfer_date']
    search_fields = ['property__parcel_number', 'deed_number']
    date_hierarchy = 'transfer_date'


@admin.register(PropertySubdivision)
class PropertySubdivisionAdmin(admin.ModelAdmin):
    list_display = ['parent_property', 'subdivision_date', 'approval_number', 'surveyor']
    list_filter = ['subdivision_date']
    search_fields = ['parent_property__parcel_number', 'approval_number']
    date_hierarchy = 'subdivision_date'


@admin.register(PropertyAmalgamation)
class PropertyAmalgamationAdmin(admin.ModelAdmin):
    list_display = ['new_property', 'amalgamation_date', 'approval_number', 'surveyor']
    list_filter = ['amalgamation_date']
    search_fields = ['new_property__parcel_number', 'approval_number']
    date_hierarchy = 'amalgamation_date'


@admin.register(PropertyCaveat)
class PropertyCaveatAdmin(admin.ModelAdmin):
    list_display = ['property', 'caveat_type', 'lodged_by', 'lodged_date', 'is_active']
    list_filter = ['caveat_type', 'is_active', 'lodged_date']
    search_fields = ['property__parcel_number', 'lodged_by']
    date_hierarchy = 'lodged_date'


@admin.register(PropertyValuation)
class PropertyValuationAdmin(admin.ModelAdmin):
    list_display = ['property', 'valuation_date', 'land_value', 'improvement_value', 'total_value', 'valuer_name', 'is_current']
    list_filter = ['is_current', 'valuation_date']
    search_fields = ['property__parcel_number', 'valuer_name']
    date_hierarchy = 'valuation_date'


# ============================================================================
# PHYSICAL PLANNING
# ============================================================================

@admin.register(DevelopmentApplication)
class DevelopmentApplicationAdmin(admin.ModelAdmin):
    list_display = ['application_number', 'applicant', 'property', 'application_type', 'application_date', 'status']
    list_filter = ['application_type', 'status', 'application_date']
    search_fields = ['application_number', 'applicant__first_name', 'applicant__last_name', 'property__parcel_number']
    date_hierarchy = 'application_date'


# ============================================================================
# FINES & PENALTIES
# ============================================================================

@admin.register(FineCategory)
class FineCategoryAdmin(admin.ModelAdmin):
    list_display = ['name', 'code', 'revenue_stream', 'is_active']
    list_filter = ['revenue_stream', 'is_active']
    search_fields = ['name', 'code']


@admin.register(Fine)
class FineAdmin(GISModelAdmin):
    list_display = ['fine_number', 'offender', 'category', 'offense_date', 'fine_amount', 'amount_paid', 'balance', 'status']
    list_filter = ['status', 'category', 'offense_date', 'issued_date']
    search_fields = ['fine_number', 'offender__first_name', 'offender__last_name']
    date_hierarchy = 'offense_date'


@admin.register(FinePayment)
class FinePaymentAdmin(admin.ModelAdmin):
    list_display = ['fine', 'payment', 'amount_paid', 'payment_date', 'recorded_by']
    list_filter = ['payment_date']
    search_fields = ['fine__fine_number', 'payment__receipt_number']
    date_hierarchy = 'payment_date'


# ============================================================================
# AUDIT & SYSTEM
# ============================================================================

@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ['user', 'action', 'model_name', 'object_repr', 'timestamp', 'ip_address']
    list_filter = ['action', 'model_name', 'timestamp']
    search_fields = ['user__username', 'model_name', 'object_repr', 'object_id']
    date_hierarchy = 'timestamp'
    readonly_fields = ['user', 'action', 'model_name', 'object_id', 'object_repr', 'changes', 'ip_address', 'user_agent', 'timestamp']
    
    def has_add_permission(self, request):
        return False
    
    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ['recipient', 'notification_type', 'subject', 'status', 'sent_at', 'read_at']
    list_filter = ['notification_type', 'status', 'sent_at']
    search_fields = ['recipient__username', 'subject', 'message']
    date_hierarchy = 'created_at'


@admin.register(SystemConfiguration)
class SystemConfigurationAdmin(admin.ModelAdmin):
    list_display = ['key', 'value', 'data_type', 'is_editable', 'updated_by', 'updated_at']
    list_filter = ['data_type', 'is_editable']
    search_fields = ['key', 'description']
    readonly_fields = ['updated_at']


@admin.register(BankReconciliation)
class BankReconciliationAdmin(admin.ModelAdmin):
    list_display = ['reconciliation_date', 'bank_account', 'opening_balance', 'closing_balance', 'variance', 'is_reconciled', 'reconciled_by']
    list_filter = ['is_reconciled', 'reconciliation_date', 'bank_account']
    search_fields = ['bank_account']
    date_hierarchy = 'reconciliation_date'


# ============================================================================
# ADDITIONAL INLINES AND CUSTOMIZATIONS
# ============================================================================

class GoodsReceiptItemInline(admin.TabularInline):
    model = GoodsReceiptItem
    extra = 0


class RequisitionItemInline(admin.TabularInline):
    model = RequisitionItem
    extra = 0


class CaseDocumentInline(admin.TabularInline):
    model = CaseDocument
    extra = 0


class LicenseDocumentInline(admin.TabularInline):
    model = LicenseDocument
    extra = 0


class PropertyDocumentInline(admin.TabularInline):
    model = PropertyDocument
    extra = 0


class DevelopmentDocumentInline(admin.TabularInline):
    model = DevelopmentDocument
    extra = 0


class OutdoorAdvertisingDocumentInline(admin.TabularInline):
    model = OutdoorAdvertisingDocument
    extra = 0


# Register inlines with their parent models
# Update GoodsReceiptNote to include inline
admin.site.unregister(GoodsReceiptNote)
@admin.register(GoodsReceiptNote)
class GoodsReceiptNoteAdmin(admin.ModelAdmin):
    list_display = ['grn_number', 'store', 'supplier', 'receipt_date', 'status']
    list_filter = ['status', 'store', 'receipt_date']
    search_fields = ['grn_number', 'supplier']
    date_hierarchy = 'receipt_date'
    inlines = [GoodsReceiptItemInline]


# Update StoreRequisition to include inline
admin.site.unregister(StoreRequisition)
@admin.register(StoreRequisition)
class StoreRequisitionAdmin(admin.ModelAdmin):
    list_display = ['requisition_number', 'department', 'store', 'requisition_date', 'required_date', 'status']
    list_filter = ['status', 'department', 'store', 'requisition_date']
    search_fields = ['requisition_number']
    date_hierarchy = 'requisition_date'
    inlines = [RequisitionItemInline]


# Update Case to include inline
admin.site.unregister(Case)
@admin.register(Case)
class CaseAdmin(admin.ModelAdmin):
    list_display = ['case_number', 'category', 'title', 'filing_date', 'hearing_date', 'status', 'case_officer']
    list_filter = ['status', 'category', 'filing_date', 'hearing_date']
    search_fields = ['case_number', 'title']
    date_hierarchy = 'filing_date'
    inlines = [CaseDocumentInline]


# Update License to include inline
admin.site.unregister(License)
@admin.register(License)
class LicenseAdmin(admin.ModelAdmin):
    list_display = ['license_number', 'business', 'license_type', 'application_date', 'expiry_date', 'status_badge', 'is_renewal']
    list_filter = ['status', 'license_type', 'is_provisional', 'is_renewal', 'application_date']
    search_fields = ['license_number', 'business__business_name']
    date_hierarchy = 'application_date'
    inlines = [LicenseDocumentInline]
    
    def status_badge(self, obj):
        colors = {
            'active': 'green',
            'approved': 'blue',
            'issued': 'green',
            'expired': 'red',
            'suspended': 'orange',
            'revoked': 'red',
            'rejected': 'red',
        }
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 10px; border-radius: 3px;">{}</span>',
            colors.get(obj.status, 'gray'),
            obj.get_status_display()
        )
    status_badge.short_description = 'Status'


# Update Property to include inline
admin.site.unregister(Property)
@admin.register(Property)
class PropertyAdmin(GISModelAdmin):
    list_display = ['parcel_number', 'owner', 'property_type', 'land_use_type', 'area_sqm', 'assessed_value', 'sub_county', 'ward', 'status']
    list_filter = ['property_type', 'land_use_type', 'status', 'sub_county', 'ward', 'has_caveat']
    search_fields = ['parcel_number', 'original_parcel_number', 'owner__first_name', 'owner__last_name']
    date_hierarchy = 'registration_date'
    inlines = [PropertyDocumentInline]


# Update DevelopmentApplication to include inline
admin.site.unregister(DevelopmentApplication)
@admin.register(DevelopmentApplication)
class DevelopmentApplicationAdmin(admin.ModelAdmin):
    list_display = ['application_number', 'applicant', 'property', 'application_type', 'application_date', 'status']
    list_filter = ['application_type', 'status', 'application_date']
    search_fields = ['application_number', 'applicant__first_name', 'applicant__last_name', 'property__parcel_number']
    date_hierarchy = 'application_date'
    inlines = [DevelopmentDocumentInline]


# Update OutdoorAdvertising to include inline
admin.site.unregister(OutdoorAdvertising)
@admin.register(OutdoorAdvertising)
class OutdoorAdvertisingAdmin(GISModelAdmin):
    list_display = ['reference_number', 'owner', 'advertising_type', 'category', 'size_sqm', 'sub_county', 'ward', 'status']
    list_filter = ['advertising_type', 'category', 'status', 'sub_county', 'ward']
    search_fields = ['reference_number', 'owner__first_name', 'owner__last_name', 'owner__business_name']
    date_hierarchy = 'start_date'
    inlines = [OutdoorAdvertisingDocumentInline]


# ============================================================================
# ADMIN SITE CUSTOMIZATION
# ============================================================================

admin.site.site_header = "Wajir County Government ERP System"
admin.site.site_title = "Wajir County ERP"
admin.site.index_title = "County Administration Dashboard"


# ============================================================================
# CUSTOM ADMIN ACTIONS
# ============================================================================

def activate_items(modeladmin, request, queryset):
    queryset.update(is_active=True)
activate_items.short_description = "Activate selected items"


def deactivate_items(modeladmin, request, queryset):
    queryset.update(is_active=False)
deactivate_items.short_description = "Deactivate selected items"


def mark_as_paid(modeladmin, request, queryset):
    queryset.update(status='paid')
mark_as_paid.short_description = "Mark as Paid"


def mark_as_completed(modeladmin, request, queryset):
    queryset.update(status='completed')
mark_as_completed.short_description = "Mark as Completed"


# Add common actions to relevant admin classes
for model_admin in [RevenueStreamAdmin, ChargeRateAdmin, LeaveTypeAdmin, 
                    ItemCategoryAdmin, AssetCategoryAdmin, FacilityCategoryAdmin]:
    model_admin.actions = [activate_items, deactivate_items]


# Add status actions to relevant admin classes
BillAdmin.actions = [mark_as_paid]
PaymentAdmin.actions = [mark_as_completed]
FineAdmin.actions = [mark_as_paid]