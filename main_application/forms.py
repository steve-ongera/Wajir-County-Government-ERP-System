# forms.py

from django import forms
from django.contrib.auth.forms import UserCreationForm
from .models import *


class UserForm(forms.ModelForm):
    """Form for creating and updating users"""
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'form-control'}),
        required=False,
        help_text='Leave blank to keep current password'
    )
    confirm_password = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'form-control'}),
        required=False
    )
    
    class Meta:
        model = User
        fields = [
            'username', 'first_name', 'last_name', 'email', 
            'phone_number', 'employee_number', 'id_number',
            'department', 'sub_county', 'is_active', 'is_staff'
        ]
        widgets = {
            'username': forms.TextInput(attrs={'class': 'form-control'}),
            'first_name': forms.TextInput(attrs={'class': 'form-control'}),
            'last_name': forms.TextInput(attrs={'class': 'form-control'}),
            'email': forms.EmailInput(attrs={'class': 'form-control'}),
            'phone_number': forms.TextInput(attrs={'class': 'form-control'}),
            'employee_number': forms.TextInput(attrs={'class': 'form-control'}),
            'id_number': forms.TextInput(attrs={'class': 'form-control'}),
            'department': forms.Select(attrs={'class': 'form-control'}),
            'sub_county': forms.Select(attrs={'class': 'form-control'}),
            'is_active': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'is_staff': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        }
    
    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        confirm_password = cleaned_data.get('confirm_password')
        
        if password and password != confirm_password:
            raise forms.ValidationError("Passwords do not match")
        
        return cleaned_data


class RoleForm(forms.ModelForm):
    """Form for creating and updating roles"""
    
    class Meta:
        model = Role
        fields = ['name', 'description', 'parent_role', 'is_active']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
            'parent_role': forms.Select(attrs={'class': 'form-control'}),
            'is_active': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        }


class PermissionForm(forms.ModelForm):
    """Form for creating and updating permissions"""
    
    class Meta:
        model = Permission
        fields = ['name', 'codename', 'module', 'description']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'codename': forms.TextInput(attrs={'class': 'form-control'}),
            'module': forms.TextInput(attrs={'class': 'form-control'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
        }


class SystemConfigurationForm(forms.ModelForm):
    """Form for updating system configuration"""
    
    class Meta:
        model = SystemConfiguration
        fields = ['value', 'description']
        widgets = {
            'value': forms.Textarea(attrs={'class': 'form-control', 'rows': 2}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
        }



# Forms.py - Add these forms
from django import forms
from django.forms import inlineformset_factory


class LicenseTypeForm(forms.ModelForm):
    """Form for creating/updating license types"""
    
    class Meta:
        model = LicenseType
        fields = [
            'name', 'code', 'description', 'business_category',
            'revenue_stream', 'validity_period_days', 'is_renewable',
            'requires_inspection', 'is_active'
        ]
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter license type name'
            }),
            'code': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'e.g., LIC-001'
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 4,
                'placeholder': 'Enter detailed description'
            }),
            'business_category': forms.Select(attrs={
                'class': 'form-select'
            }),
            'revenue_stream': forms.Select(attrs={
                'class': 'form-select'
            }),
            'validity_period_days': forms.NumberInput(attrs={
                'class': 'form-control',
                'placeholder': 'e.g., 365'
            }),
            'is_renewable': forms.CheckboxInput(attrs={
                'class': 'form-check-input'
            }),
            'requires_inspection': forms.CheckboxInput(attrs={
                'class': 'form-check-input'
            }),
            'is_active': forms.CheckboxInput(attrs={
                'class': 'form-check-input'
            }),
        }
    
    def clean_code(self):
        code = self.cleaned_data.get('code')
        if code:
            code = code.upper()
            # Check for duplicate code
            qs = LicenseType.objects.filter(code=code)
            if self.instance.pk:
                qs = qs.exclude(pk=self.instance.pk)
            if qs.exists():
                raise forms.ValidationError('A license type with this code already exists.')
        return code
    
    def clean_validity_period_days(self):
        days = self.cleaned_data.get('validity_period_days')
        if days and days <= 0:
            raise forms.ValidationError('Validity period must be greater than 0.')
        return days


class LicenseRequirementForm(forms.ModelForm):
    """Form for license requirements"""
    
    class Meta:
        model = LicenseRequirement
        fields = ['requirement_name', 'description', 'is_mandatory', 'display_order']
        widgets = {
            'requirement_name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Requirement name'
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 2,
                'placeholder': 'Description'
            }),
            'is_mandatory': forms.CheckboxInput(attrs={
                'class': 'form-check-input'
            }),
            'display_order': forms.NumberInput(attrs={
                'class': 'form-control',
                'placeholder': 'Order'
            }),
        }


# Create formset for requirements
LicenseRequirementFormSet = inlineformset_factory(
    LicenseType,
    LicenseRequirement,
    form=LicenseRequirementForm,
    extra=3,
    can_delete=True,
    min_num=0,
    validate_min=False,
)