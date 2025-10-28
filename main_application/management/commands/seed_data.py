"""
Wajir County Government ERP System - Data Seeding Script
Management command to populate database with realistic Wajir County data

Usage: python manage.py seed_data
"""

from django.core.management.base import BaseCommand
from django.contrib.gis.geos import Point, Polygon, MultiPolygon
from django.utils import timezone
from datetime import datetime, timedelta, date
from decimal import Decimal
import random
from main_application.models import *


class Command(BaseCommand):
    help = 'Seeds the database with Wajir County data'

    def add_arguments(self, parser):
        parser.add_argument(
            '--clear',
            action='store_true',
            help='Clear existing data before seeding',
        )

    def handle(self, *args, **options):
        if options['clear']:
            self.stdout.write(self.style.WARNING('Clearing existing data...'))
            self.clear_data()

        self.stdout.write(self.style.SUCCESS('Starting data seeding...'))
        
        # Seed in order of dependencies
        self.seed_county()
        self.seed_sub_counties()
        self.seed_wards()
        self.seed_departments()
        self.seed_permissions_and_roles()
        self.seed_users()
        self.seed_citizens()
        self.seed_revenue_streams()
        self.seed_charge_rates()
        self.seed_penalty_rules()
        self.seed_payment_methods()
        self.seed_health_facilities()
        self.seed_patients()
        self.seed_fleet_vehicles()
        self.seed_fuel_stations()
        self.seed_biometric_devices()
        self.seed_leave_types()
        self.seed_facility_categories()
        self.seed_facilities()
        self.seed_facility_units()
        self.seed_stores()
        self.seed_item_categories()
        self.seed_inventory_items()
        self.seed_asset_categories()
        self.seed_assets()
        self.seed_case_categories()
        self.seed_document_categories()
        self.seed_business_categories()
        self.seed_license_types()
        self.seed_parking_zones()
        self.seed_saccos()
        self.seed_advertising_categories()
        self.seed_property_types()
        self.seed_land_use_types()
        self.seed_fine_categories()
        self.seed_training_programs()
        
        self.stdout.write(self.style.SUCCESS('Data seeding completed successfully!'))

    def clear_data(self):
        """Clear existing data (except superuser)"""
        models_to_clear = [
            Fine, Property, License, Business, OutdoorAdvertising,
            Vehicle, Asset, FacilityUnit, Facility, InventoryItem,
            Patient, FleetVehicle, Citizen, User,
        ]
        for model in models_to_clear:
            if model == User:
                model.objects.filter(is_superuser=False).delete()
            else:
                model.objects.all().delete()

    def seed_county(self):
        """Seed Wajir County information"""
        self.stdout.write('Seeding county data...')
        
        county, created = County.objects.get_or_create(
            code='WJR',
            defaults={
                'name': 'Wajir',
                'county_number': 8,
                'headquarters': 'Wajir Town',
                'area_sq_km': Decimal('55840.60'),
            }
        )
        self.county = county
        self.stdout.write(self.style.SUCCESS(f'✓ County: {county.name}'))

    def seed_sub_counties(self):
        """Seed Wajir sub-counties"""
        self.stdout.write('Seeding sub-counties...')
        
        sub_counties_data = [
            {'name': 'Wajir North', 'code': 'WJR-N', 'headquarters': 'Bute'},
            {'name': 'Wajir East', 'code': 'WJR-E', 'headquarters': 'Khorof Harar'},
            {'name': 'Tarbaj', 'code': 'WJR-T', 'headquarters': 'Tarbaj'},
            {'name': 'Wajir West', 'code': 'WJR-W', 'headquarters': 'Griftu'},
            {'name': 'Eldas', 'code': 'WJR-ELD', 'headquarters': 'Eldas'},
            {'name': 'Wajir South', 'code': 'WJR-S', 'headquarters': 'Habaswein'},
        ]
        
        self.sub_counties = []
        for data in sub_counties_data:
            sub_county, created = SubCounty.objects.get_or_create(
                code=data['code'],
                defaults={
                    'county': self.county,
                    'name': data['name'],
                    'headquarters': data['headquarters'],
                    'is_active': True,
                }
            )
            self.sub_counties.append(sub_county)
            self.stdout.write(f'  ✓ Sub-County: {sub_county.name}')

    def seed_wards(self):
        """Seed wards for each sub-county"""
        self.stdout.write('Seeding wards...')
        
        wards_data = {
            'Wajir North': ['Bute', 'Korondille', 'Malkagalla', 'Barwago'],
            'Wajir East': ['Khorof Harar', 'Wajir Township', 'Wagberi', 'Dadaja Bulla'],
            'Tarbaj': ['Tarbaj', 'Wargadud', 'Elben', 'Sarman'],
            'Wajir West': ['Griftu', 'Batalu', 'Ademasajida', 'Hadado Athibohol'],
            'Eldas': ['Eldas', 'Della', 'Lakoley South Ganyure'],
            'Wajir South': ['Habaswein', 'Benadir', 'Ibrahim Ure', 'Diif'],
        }
        
        self.wards = []
        for sub_county in self.sub_counties:
            ward_names = wards_data.get(sub_county.name, [])
            for idx, ward_name in enumerate(ward_names, 1):
                ward, created = Ward.objects.get_or_create(
                    code=f'{sub_county.code}-W{idx:02d}',
                    defaults={
                        'sub_county': sub_county,
                        'name': ward_name,
                        'population': random.randint(5000, 25000),
                        'is_active': True,
                    }
                )
                self.wards.append(ward)
                if created:
                    self.stdout.write(f'  ✓ Ward: {ward.name} ({sub_county.name})')

    def seed_departments(self):
        """Seed county departments"""
        self.stdout.write('Seeding departments...')
        
        departments_data = [
            {'name': 'Office of the Governor', 'code': 'GOV'},
            {'name': 'Finance and Economic Planning', 'code': 'FIN'},
            {'name': 'Health Services', 'code': 'HLT'},
            {'name': 'Education and ICT', 'code': 'EDU'},
            {'name': 'Water, Energy and Natural Resources', 'code': 'WTR'},
            {'name': 'Transport, Infrastructure and Public Works', 'code': 'TRN'},
            {'name': 'Agriculture, Livestock and Fisheries', 'code': 'AGR'},
            {'name': 'Trade, Tourism and Industrialization', 'code': 'TRD'},
            {'name': 'Lands, Physical Planning and Urban Development', 'code': 'LND'},
            {'name': 'Youth, Sports, Gender and Social Services', 'code': 'YTH'},
            {'name': 'Public Service Management', 'code': 'PSM'},
            {'name': 'County Administration', 'code': 'ADM'},
        ]
        
        self.departments = []
        for data in departments_data:
            dept, created = Department.objects.get_or_create(
                code=data['code'],
                defaults={
                    'name': data['name'],
                    'description': f'{data["name"]} department',
                    'is_active': True,
                }
            )
            self.departments.append(dept)
            if created:
                self.stdout.write(f'  ✓ Department: {dept.name}')

    def seed_permissions_and_roles(self):
        """Seed permissions and roles"""
        self.stdout.write('Seeding permissions and roles...')
        
        # Create permissions
        permissions_data = [
            {'name': 'View Revenue', 'codename': 'view_revenue', 'module': 'Revenue'},
            {'name': 'Collect Revenue', 'codename': 'collect_revenue', 'module': 'Revenue'},
            {'name': 'View Bills', 'codename': 'view_bills', 'module': 'Revenue'},
            {'name': 'Create Bills', 'codename': 'create_bills', 'module': 'Revenue'},
            {'name': 'Approve Payments', 'codename': 'approve_payments', 'module': 'Revenue'},
            {'name': 'View Patients', 'codename': 'view_patients', 'module': 'Health'},
            {'name': 'Register Patients', 'codename': 'register_patients', 'module': 'Health'},
            {'name': 'View Assets', 'codename': 'view_assets', 'module': 'Assets'},
            {'name': 'Manage Assets', 'codename': 'manage_assets', 'module': 'Assets'},
            {'name': 'Approve Licenses', 'codename': 'approve_licenses', 'module': 'Licensing'},
        ]
        
        permissions = []
        for perm_data in permissions_data:
            perm, created = Permission.objects.get_or_create(
                codename=perm_data['codename'],
                defaults=perm_data
            )
            permissions.append(perm)
        
        # Create roles
        roles_data = [
            {'name': 'System Administrator', 'description': 'Full system access'},
            {'name': 'Revenue Officer', 'description': 'Revenue collection and billing'},
            {'name': 'Health Worker', 'description': 'Patient management'},
            {'name': 'Fleet Manager', 'description': 'Fleet and transport management'},
            {'name': 'HR Manager', 'description': 'Human resource management'},
            {'name': 'Finance Officer', 'description': 'Financial management'},
            {'name': 'Lands Officer', 'description': 'Land and property management'},
        ]
        
        for role_data in roles_data:
            role, created = Role.objects.get_or_create(
                name=role_data['name'],
                defaults={
                    'description': role_data['description'],
                    'is_active': True,
                }
            )
            if created:
                # Assign random permissions
                role.permissions.set(random.sample(permissions, k=min(5, len(permissions))))
                self.stdout.write(f'  ✓ Role: {role.name}')

    def seed_users(self):
        """Seed staff users"""
        self.stdout.write('Seeding users...')
        
        users_data = [
            {'username': 'ahmed.mohamed', 'first_name': 'Ahmed', 'last_name': 'Mohamed', 'email': 'ahmed.mohamed@wajir.go.ke', 'phone': '0712345001'},
            {'username': 'fatuma.hassan', 'first_name': 'Fatuma', 'last_name': 'Hassan', 'email': 'fatuma.hassan@wajir.go.ke', 'phone': '0712345002'},
            {'username': 'mohamed.abdi', 'first_name': 'Mohamed', 'last_name': 'Abdi', 'email': 'mohamed.abdi@wajir.go.ke', 'phone': '0712345003'},
            {'username': 'halima.ali', 'first_name': 'Halima', 'last_name': 'Ali', 'email': 'halima.ali@wajir.go.ke', 'phone': '0712345004'},
            {'username': 'ibrahim.yusuf', 'first_name': 'Ibrahim', 'last_name': 'Yusuf', 'email': 'ibrahim.yusuf@wajir.go.ke', 'phone': '0712345005'},
            {'username': 'amina.omar', 'first_name': 'Amina', 'last_name': 'Omar', 'email': 'amina.omar@wajir.go.ke', 'phone': '0712345006'},
            {'username': 'hussein.sheikh', 'first_name': 'Hussein', 'last_name': 'Sheikh', 'email': 'hussein.sheikh@wajir.go.ke', 'phone': '0712345007'},
            {'username': 'maryam.aden', 'first_name': 'Maryam', 'last_name': 'Aden', 'email': 'maryam.aden@wajir.go.ke', 'phone': '0712345008'},
            {'username': 'abdullahi.farah', 'first_name': 'Abdullahi', 'last_name': 'Farah', 'email': 'abdullahi.farah@wajir.go.ke', 'phone': '0712345009'},
            {'username': 'Sofia.ibrahim', 'first_name': 'Sofia', 'last_name': 'Ibrahim', 'email': 'sofia.ibrahim@wajir.go.ke', 'phone': '0712345010'},
        ]
        
        self.users = []
        for idx, data in enumerate(users_data, 1):
            user, created = User.objects.get_or_create(
                username=data['username'],
                defaults={
                    'first_name': data['first_name'],
                    'last_name': data['last_name'],
                    'email': data['email'],
                    'phone_number': data['phone'],
                    'employee_number': f'WJR/EMP/{2024}/{idx:04d}',
                    'department': random.choice(self.departments),
                    'sub_county': random.choice(self.sub_counties),
                    'is_active': True,
                    'is_staff': True,
                    'is_active_staff': True,
                }
            )
            if created:
                user.set_password('password123')
                user.save()
                self.users.append(user)
                self.stdout.write(f'  ✓ User: {user.get_full_name()}')

    def seed_citizens(self):
        """Seed citizens"""
        self.stdout.write('Seeding citizens...')
        
        # Individual citizens
        individuals_data = [
            {'first_name': 'Abdirahman', 'last_name': 'Mohamed', 'phone': '0722111001', 'id': '12345001'},
            {'first_name': 'Khadija', 'last_name': 'Hassan', 'phone': '0722111002', 'id': '12345002'},
            {'first_name': 'Yusuf', 'last_name': 'Abdi', 'phone': '0722111003', 'id': '12345003'},
            {'first_name': 'Nuria', 'last_name': 'Ali', 'phone': '0722111004', 'id': '12345004'},
            {'first_name': 'Omar', 'last_name': 'Sheikh', 'phone': '0722111005', 'id': '12345005'},
            {'first_name': 'Zamzam', 'last_name': 'Aden', 'phone': '0722111006', 'id': '12345006'},
            {'first_name': 'Salat', 'last_name': 'Ibrahim', 'phone': '0722111007', 'id': '12345007'},
            {'first_name': 'Fardosa', 'last_name': 'Yusuf', 'phone': '0722111008', 'id': '12345008'},
            {'first_name': 'Bashir', 'last_name': 'Omar', 'phone': '0722111009', 'id': '12345009'},
            {'first_name': 'Rahma', 'last_name': 'Farah', 'phone': '0722111010', 'id': '12345010'},
        ]
        
        self.citizens = []
        for data in individuals_data:
            citizen, created = Citizen.objects.get_or_create(
                unique_identifier=data['id'],
                defaults={
                    'entity_type': 'individual',
                    'first_name': data['first_name'],
                    'last_name': data['last_name'],
                    'phone_primary': data['phone'],
                    'sub_county': random.choice(self.sub_counties),
                    'ward': random.choice(self.wards),
                    'date_of_birth': date(random.randint(1960, 2000), random.randint(1, 12), random.randint(1, 28)),
                    'gender': random.choice(['Male', 'Female']),
                    'is_active': True,
                    'created_by': random.choice(self.users) if self.users else None,
                }
            )
            self.citizens.append(citizen)
            if created:
                self.stdout.write(f'  ✓ Citizen: {citizen.first_name} {citizen.last_name}')
        
        # Business entities
        businesses_data = [
            {'name': 'Wajir Traders Ltd', 'reg': 'CPR/2020/12345'},
            {'name': 'Nomadic Enterprises', 'reg': 'CPR/2021/12346'},
            {'name': 'Garre Plaza', 'reg': 'CPR/2019/12347'},
            {'name': 'Degodia Supplies', 'reg': 'CPR/2022/12348'},
            {'name': 'Ajuran Business Centre', 'reg': 'CPR/2020/12349'},
        ]
        
        for data in businesses_data:
            citizen, created = Citizen.objects.get_or_create(
                unique_identifier=data['reg'],
                defaults={
                    'entity_type': 'business',
                    'business_name': data['name'],
                    'registration_number': data['reg'],
                    'phone_primary': f'072{random.randint(1000000, 9999999)}',
                    'sub_county': random.choice(self.sub_counties),
                    'ward': random.choice(self.wards),
                    'is_active': True,
                    'created_by': random.choice(self.users) if self.users else None,
                }
            )
            self.citizens.append(citizen)
            if created:
                self.stdout.write(f'  ✓ Business: {citizen.business_name}')

    def seed_revenue_streams(self):
        """Seed revenue streams"""
        self.stdout.write('Seeding revenue streams...')
        
        revenue_streams_data = [
            {'name': 'Single Business Permit', 'code': 'SBP', 'dept': 'TRD', 'recurring': True, 'freq': 'yearly'},
            {'name': 'Market Stall Rent', 'code': 'MSR', 'dept': 'TRD', 'recurring': True, 'freq': 'monthly'},
            {'name': 'Parking Fees', 'code': 'PRK', 'dept': 'TRN', 'recurring': False, 'freq': ''},
            {'name': 'Land Rates', 'code': 'LND-RT', 'dept': 'LND', 'recurring': True, 'freq': 'yearly'},
            {'name': 'Building Plan Approval', 'code': 'BLD-PLN', 'dept': 'LND', 'recurring': False, 'freq': ''},
            {'name': 'Health Facility Fees', 'code': 'HLT-FEE', 'dept': 'HLT', 'recurring': False, 'freq': ''},
            {'name': 'Outdoor Advertising', 'code': 'OUT-ADV', 'dept': 'TRD', 'recurring': True, 'freq': 'yearly'},
            {'name': 'Cess on Livestock', 'code': 'CESS-LVS', 'dept': 'AGR', 'recurring': False, 'freq': ''},
            {'name': 'Water Connection Fees', 'code': 'WTR-CON', 'dept': 'WTR', 'recurring': False, 'freq': ''},
            {'name': 'Fire Inspection Certificate', 'code': 'FIRE-CRT', 'dept': 'ADM', 'recurring': True, 'freq': 'yearly'},
        ]
        
        self.revenue_streams = []
        for data in revenue_streams_data:
            dept = Department.objects.get(code=data['dept'])
            stream, created = RevenueStream.objects.get_or_create(
                code=data['code'],
                defaults={
                    'name': data['name'],
                    'description': f'{data["name"]} revenue stream',
                    'department': dept,
                    'is_recurring': data['recurring'],
                    'billing_frequency': data['freq'],
                    'is_active': True,
                }
            )
            self.revenue_streams.append(stream)
            if created:
                self.stdout.write(f'  ✓ Revenue Stream: {stream.name}')

    def seed_charge_rates(self):
        """Seed charge rates"""
        self.stdout.write('Seeding charge rates...')
        
        for stream in self.revenue_streams:
            amounts = {
                'SBP': [(5000, 'Small'), (10000, 'Medium'), (25000, 'Large')],
                'MSR': [(500, 'Daily'), (12000, 'Monthly')],
                'PRK': [(50, 'Hourly'), (200, 'Daily'), (3000, 'Monthly')],
                'LND-RT': [(2000, 'Residential'), (5000, 'Commercial')],
                'BLD-PLN': [(5000, 'Residential'), (15000, 'Commercial')],
                'HLT-FEE': [(200, 'Consultation'), (1000, 'Lab Test')],
                'OUT-ADV': [(10000, 'Small Billboard'), (50000, 'Large Billboard')],
                'CESS-LVS': [(100, 'Per Head')],
                'WTR-CON': [(3000, 'Domestic'), (10000, 'Commercial')],
                'FIRE-CRT': [(5000, 'Annual')],
            }
            
            rates = amounts.get(stream.code, [(1000, 'Standard')])
            for amount, name in rates:
                ChargeRate.objects.get_or_create(
                    revenue_stream=stream,
                    name=name,
                    defaults={
                        'description': f'{name} rate for {stream.name}',
                        'rate_type': 'fixed',
                        'amount': Decimal(amount),
                        'effective_from': date(2024, 1, 1),
                        'is_active': True,
                    }
                )
        self.stdout.write('  ✓ Charge rates created')

    def seed_penalty_rules(self):
        """Seed penalty rules"""
        self.stdout.write('Seeding penalty rules...')
        
        for stream in self.revenue_streams[:5]:
            PenaltyRule.objects.get_or_create(
                revenue_stream=stream,
                name=f'Late Payment Penalty - {stream.code}',
                defaults={
                    'grace_period_days': 30,
                    'penalty_type': 'percentage',
                    'penalty_amount': Decimal('2.5'),
                    'effective_from': date(2024, 1, 1),
                    'is_active': True,
                }
            )
        self.stdout.write('  ✓ Penalty rules created')

    def seed_payment_methods(self):
        """Seed payment methods"""
        self.stdout.write('Seeding payment methods...')
        
        methods = [
            {'name': 'M-Pesa', 'code': 'MPESA', 'provider': 'Safaricom', 'online': True},
            {'name': 'Bank Transfer', 'code': 'BANK', 'provider': 'Various Banks', 'online': True},
            {'name': 'Cash', 'code': 'CASH', 'provider': 'County Revenue Office', 'online': False},
            {'name': 'Airtel Money', 'code': 'AIRTEL', 'provider': 'Airtel Kenya', 'online': True},
        ]
        
        for method in methods:
            PaymentMethod.objects.get_or_create(
                code=method['code'],
                defaults={
                    'name': method['name'],
                    'provider': method['provider'],
                    'is_online': method['online'],
                    'is_active': True,
                }
            )
        self.stdout.write('  ✓ Payment methods created')

    def seed_health_facilities(self):
        """Seed health facilities"""
        self.stdout.write('Seeding health facilities...')
        
        facilities_data = [
            {'name': 'Wajir County Referral Hospital', 'code': 'WCRH', 'level': 'level_5', 'sub': 'Wajir East', 'beds': 150},
            {'name': 'Habaswein Sub-County Hospital', 'code': 'HSCH', 'level': 'level_4', 'sub': 'Wajir South', 'beds': 80},
            {'name': 'Bute Health Centre', 'code': 'BHC', 'level': 'level_3', 'sub': 'Wajir North', 'beds': 30},
            {'name': 'Tarbaj Health Centre', 'code': 'THC', 'level': 'level_3', 'sub': 'Tarbaj', 'beds': 25},
            {'name': 'Eldas Health Centre', 'code': 'EHC', 'level': 'level_3', 'sub': 'Eldas', 'beds': 20},
            {'name': 'Griftu Dispensary', 'code': 'GRD', 'level': 'level_2', 'sub': 'Wajir West', 'beds': 10},
        ]
        
        self.health_facilities = []
        for data in facilities_data:
            sub_county = SubCounty.objects.get(name=data['sub'])
            ward = sub_county.wards.first()
            
            facility, created = HealthFacility.objects.get_or_create(
                code=data['code'],
                defaults={
                    'name': data['name'],
                    'facility_level': data['level'],
                    'sub_county': sub_county,
                    'ward': ward,
                    'location': Point(40.5 + random.uniform(-0.5, 0.5), 1.75 + random.uniform(-0.5, 0.5)),
                    'phone': f'072{random.randint(1000000, 9999999)}',
                    'bed_capacity': data['beds'],
                    'is_active': True,
                }
            )
            self.health_facilities.append(facility)
            if created:
                self.stdout.write(f'  ✓ Health Facility: {facility.name}')

    def seed_patients(self):
        """Seed patient records"""
        self.stdout.write('Seeding patients...')
        
        # Get individual citizens only (not businesses)
        individual_citizens = [c for c in self.citizens if c.entity_type == 'individual']
        
        # Create additional patient names for those without citizen records
        additional_patients = [
            {'first_name': 'Hassan', 'last_name': 'Mohamed', 'gender': 'M'},
            {'first_name': 'Amina', 'last_name': 'Abdi', 'gender': 'F'},
            {'first_name': 'Farah', 'last_name': 'Ali', 'gender': 'M'},
            {'first_name': 'Sahra', 'last_name': 'Omar', 'gender': 'F'},
            {'first_name': 'Ali', 'last_name': 'Hassan', 'gender': 'M'},
            {'first_name': 'Habiba', 'last_name': 'Yusuf', 'gender': 'F'},
            {'first_name': 'Adan', 'last_name': 'Ibrahim', 'gender': 'M'},
            {'first_name': 'Fatima', 'last_name': 'Sheikh', 'gender': 'F'},
            {'first_name': 'Abdirashid', 'last_name': 'Aden', 'gender': 'M'},
            {'first_name': 'Hawa', 'last_name': 'Farah', 'gender': 'F'},
        ]
        
        # Create patients linked to citizens (one-to-one)
        for idx, citizen in enumerate(individual_citizens[:10], 1):
            patient, created = Patient.objects.get_or_create(
                patient_number=f'PAT/{2024}/{idx:05d}',
                defaults={
                    'citizen': citizen,
                    'first_name': citizen.first_name,
                    'last_name': citizen.last_name,
                    'date_of_birth': citizen.date_of_birth or date(random.randint(1950, 2010), random.randint(1, 12), 1),
                    'gender': 'M' if citizen.gender == 'Male' else 'F',
                    'phone': citizen.phone_primary,
                    'address': 'Wajir Town',
                    'next_of_kin_name': f'{citizen.first_name} Next of Kin',
                    'next_of_kin_phone': '0722000000',
                    'next_of_kin_relationship': 'Spouse',
                    'is_active': True,
                }
            )
            if created:
                self.stdout.write(f'  ✓ Patient: {patient.patient_number} - {patient.first_name} {patient.last_name}')
        
        # Create additional patients without citizen records
        for idx, patient_data in enumerate(additional_patients, 11):
            patient, created = Patient.objects.get_or_create(
                patient_number=f'PAT/{2024}/{idx:05d}',
                defaults={
                    'citizen': None,
                    'first_name': patient_data['first_name'],
                    'last_name': patient_data['last_name'],
                    'date_of_birth': date(random.randint(1950, 2010), random.randint(1, 12), 1),
                    'gender': patient_data['gender'],
                    'phone': f'072{random.randint(1000000, 9999999)}',
                    'address': 'Wajir Town',
                    'next_of_kin_name': f'{patient_data["first_name"]} Next of Kin',
                    'next_of_kin_phone': f'072{random.randint(1000000, 9999999)}',
                    'next_of_kin_relationship': random.choice(['Spouse', 'Parent', 'Sibling', 'Child']),
                    'is_active': True,
                }
            )
            if created:
                self.stdout.write(f'  ✓ Patient: {patient.patient_number} - {patient.first_name} {patient.last_name}')

    def seed_fleet_vehicles(self):
        """Seed fleet vehicles"""
        self.stdout.write('Seeding fleet vehicles...')
        
        vehicles_data = [
            {'type': 'car', 'make': 'Toyota', 'model': 'Land Cruiser', 'reg': 'KBW 001C'},
            {'type': 'car', 'make': 'Toyota', 'model': 'Prado', 'reg': 'KBW 002C'},
            {'type': 'truck', 'make': 'Isuzu', 'model': 'FRR', 'reg': 'KBW 003T'},
            {'type': 'bus', 'make': 'Isuzu', 'model': 'NQR', 'reg': 'KBW 004B'},
            {'type': 'machinery', 'make': 'Caterpillar', 'model': 'Grader', 'reg': 'KBW 005M'},
        ]
        
        for idx, data in enumerate(vehicles_data, 1):
            FleetVehicle.objects.get_or_create(
                registration_number=data['reg'],
                defaults={
                    'fleet_number': f'FLT/{2024}/{idx:03d}',
                    'vehicle_type': data['type'],
                    'make': data['make'],
                    'model': data['model'],
                    'year': random.randint(2015, 2024),
                    'department': random.choice(self.departments),
                    'fuel_type': 'Diesel' if data['type'] != 'car' else random.choice(['Petrol', 'Diesel']),
                    'purchase_date': date(2020, 1, 1),
                    'purchase_cost': Decimal(random.randint(2000000, 8000000)),
                    'insurance_expiry': date(2025, 12, 31),
                    'inspection_due': date(2025, 6, 30),
                    'current_mileage': random.randint(10000, 100000),
                    'status': 'active',
                    'has_gps': random.choice([True, False]),
                }
            )
        self.stdout.write('  ✓ Fleet vehicles created')

    def seed_fuel_stations(self):
        """Seed fuel stations"""
        self.stdout.write('Seeding fuel stations...')
        
        stations_data = [
            {'name': 'Total Wajir', 'code': 'TOTAL-WJR'},
            {'name': 'Shell Wajir Town', 'code': 'SHELL-WJR'},
            {'name': 'Rubis Habaswein', 'code': 'RUBIS-HBS'},
        ]
        
        for data in stations_data:
            FuelStation.objects.get_or_create(
                code=data['code'],
                defaults={
                    'name': data['name'],
                    'location': Point(40.5 + random.uniform(-0.3, 0.3), 1.75 + random.uniform(-0.3, 0.3)),
                    'address': 'Wajir Town',
                    'is_active': True,
                }
            )
        self.stdout.write('  ✓ Fuel stations created')

    def seed_biometric_devices(self):
        """Seed biometric devices"""
        self.stdout.write('Seeding biometric devices...')
        
        devices_data = [
            {'id': 'BIO-001', 'name': 'Main Entrance', 'loc': 'County HQ'},
            {'id': 'BIO-002', 'name': 'Finance Department', 'loc': 'Finance Block'},
            {'id': 'BIO-003', 'name': 'Health Department', 'loc': 'Health Block'},
        ]
        
        for data in devices_data:
            BiometricDevice.objects.get_or_create(
                device_id=data['id'],
                defaults={
                    'device_name': data['name'],
                    'location': data['loc'],
                    'ip_address': f'192.168.1.{random.randint(10, 250)}',
                    'is_active': True,
                }
            )
        self.stdout.write('  ✓ Biometric devices created')

    def seed_leave_types(self):
        """Seed leave types"""
        self.stdout.write('Seeding leave types...')
        
        leave_types_data = [
            {'name': 'Annual Leave', 'code': 'AL', 'days': 30, 'paid': True},
            {'name': 'Sick Leave', 'code': 'SL', 'days': 30, 'paid': True},
            {'name': 'Maternity Leave', 'code': 'ML', 'days': 90, 'paid': True},
            {'name': 'Paternity Leave', 'code': 'PL', 'days': 14, 'paid': True},
            {'name': 'Study Leave', 'code': 'STL', 'days': 90, 'paid': False},
            {'name': 'Compassionate Leave', 'code': 'CL', 'days': 7, 'paid': True},
        ]
        
        for data in leave_types_data:
            LeaveType.objects.get_or_create(
                code=data['code'],
                defaults={
                    'name': data['name'],
                    'description': f'{data["name"]} for county staff',
                    'days_per_year': data['days'],
                    'requires_approval': True,
                    'is_paid': data['paid'],
                    'is_active': True,
                }
            )
        self.stdout.write('  ✓ Leave types created')

    def seed_facility_categories(self):
        """Seed facility categories"""
        self.stdout.write('Seeding facility categories...')
        
        categories = [
            {'name': 'Markets', 'code': 'MKT'},
            {'name': 'Stadia', 'code': 'STD'},
            {'name': 'Public Toilets', 'code': 'TOI'},
            {'name': 'County Housing', 'code': 'HSG'},
            {'name': 'Bus Parks', 'code': 'BUS'},
        ]
        
        self.facility_categories = []
        for data in categories:
            cat, created = FacilityCategory.objects.get_or_create(
                code=data['code'],
                defaults={
                    'name': data['name'],
                    'description': f'{data["name"]} facilities',
                    'is_active': True,
                }
            )
            self.facility_categories.append(cat)
        self.stdout.write('  ✓ Facility categories created')

    def seed_facilities(self):
        """Seed facilities"""
        self.stdout.write('Seeding facilities...')
        
        facilities_data = [
            {'name': 'Wajir Main Market', 'code': 'WMM', 'type': 'market', 'cat': 'MKT', 'cap': 200},
            {'name': 'Habaswein Market', 'code': 'HBM', 'type': 'market', 'cat': 'MKT', 'cap': 100},
            {'name': 'Wajir Stadium', 'code': 'WST', 'type': 'stadium', 'cat': 'STD', 'cap': 5000},
            {'name': 'Central Bus Park', 'code': 'CBP', 'type': 'other', 'cat': 'BUS', 'cap': 50},
        ]
        
        self.facilities = []
        for data in facilities_data:
            cat = FacilityCategory.objects.get(code=data['cat'])
            sub_county = random.choice(self.sub_counties)
            ward = sub_county.wards.first()
            
            facility, created = Facility.objects.get_or_create(
                code=data['code'],
                defaults={
                    'name': data['name'],
                    'facility_type': data['type'],
                    'category': cat,
                    'location': Point(40.5 + random.uniform(-0.2, 0.2), 1.75 + random.uniform(-0.2, 0.2)),
                    'sub_county': sub_county,
                    'ward': ward,
                    'physical_address': 'Wajir Town',
                    'capacity': data['cap'],
                    'is_active': True,
                }
            )
            self.facilities.append(facility)
            if created:
                self.stdout.write(f'  ✓ Facility: {facility.name}')

    def seed_facility_units(self):
        """Seed facility units (stalls, shops)"""
        self.stdout.write('Seeding facility units...')
        
        for facility in self.facilities:
            if facility.facility_type == 'market':
                for i in range(1, 21):
                    FacilityUnit.objects.get_or_create(
                        facility=facility,
                        unit_number=f'STALL-{i:03d}',
                        defaults={
                            'unit_type': 'stall',
                            'description': f'Market stall {i}',
                            'size_sqm': Decimal('9.00'),
                            'rental_rate_daily': Decimal('100'),
                            'rental_rate_monthly': Decimal('2000'),
                            'status': random.choice(['vacant', 'occupied']),
                            'is_active': True,
                        }
                    )
                self.stdout.write(f'  ✓ Created units for {facility.name}')

    def seed_stores(self):
        """Seed stores"""
        self.stdout.write('Seeding stores...')
        
        stores_data = [
            {'name': 'Main County Store', 'code': 'MCS', 'sub': 'Wajir East'},
            {'name': 'Habaswein Sub-County Store', 'code': 'HSS', 'sub': 'Wajir South'},
            {'name': 'Health Department Store', 'code': 'HDS', 'sub': 'Wajir East'},
        ]
        
        self.stores = []
        for data in stores_data:
            sub_county = SubCounty.objects.get(name=data['sub'])
            store, created = Store.objects.get_or_create(
                code=data['code'],
                defaults={
                    'name': data['name'],
                    'sub_county': sub_county,
                    'location': Point(40.5, 1.75),
                    'is_active': True,
                }
            )
            self.stores.append(store)
            if created:
                self.stdout.write(f'  ✓ Store: {store.name}')

    def seed_item_categories(self):
        """Seed item categories"""
        self.stdout.write('Seeding item categories...')
        
        categories_data = [
            {'name': 'Office Supplies', 'code': 'OFF'},
            {'name': 'Medical Supplies', 'code': 'MED'},
            {'name': 'Cleaning Materials', 'code': 'CLN'},
            {'name': 'ICT Equipment', 'code': 'ICT'},
            {'name': 'Construction Materials', 'code': 'CNS'},
        ]
        
        self.item_categories = []
        for data in categories_data:
            cat, created = ItemCategory.objects.get_or_create(
                code=data['code'],
                defaults={
                    'name': data['name'],
                    'description': f'{data["name"]} category',
                    'is_active': True,
                }
            )
            self.item_categories.append(cat)
        self.stdout.write('  ✓ Item categories created')

    def seed_inventory_items(self):
        """Seed inventory items"""
        self.stdout.write('Seeding inventory items...')
        
        items_data = [
            {'name': 'A4 Paper Ream', 'code': 'OFF-001', 'cat': 'OFF', 'unit': 'Ream', 'type': 'consumable', 'cost': 450},
            {'name': 'Pen Box', 'code': 'OFF-002', 'cat': 'OFF', 'unit': 'Box', 'type': 'consumable', 'cost': 200},
            {'name': 'Surgical Gloves', 'code': 'MED-001', 'cat': 'MED', 'unit': 'Box', 'type': 'consumable', 'cost': 800},
            {'name': 'Detergent', 'code': 'CLN-001', 'cat': 'CLN', 'unit': 'Kg', 'type': 'consumable', 'cost': 150},
            {'name': 'Desktop Computer', 'code': 'ICT-001', 'cat': 'ICT', 'unit': 'Unit', 'type': 'non_consumable', 'cost': 45000},
        ]
        
        for data in items_data:
            cat = ItemCategory.objects.get(code=data['cat'])
            InventoryItem.objects.get_or_create(
                item_code=data['code'],
                defaults={
                    'name': data['name'],
                    'description': f'{data["name"]} for county use',
                    'category': cat,
                    'item_type': data['type'],
                    'unit_of_measure': data['unit'],
                    'reorder_level': 10,
                    'unit_cost': Decimal(data['cost']),
                    'is_active': True,
                }
            )
        self.stdout.write('  ✓ Inventory items created')

    def seed_asset_categories(self):
        """Seed asset categories"""
        self.stdout.write('Seeding asset categories...')
        
        categories_data = [
            {'name': 'Motor Vehicles', 'code': 'VEH', 'dep': 25, 'life': 4},
            {'name': 'Furniture & Fittings', 'code': 'FUR', 'dep': 10, 'life': 10},
            {'name': 'ICT Equipment', 'code': 'ICT', 'dep': 33.33, 'life': 3},
            {'name': 'Buildings', 'code': 'BLD', 'dep': 2.5, 'life': 40},
            {'name': 'Machinery', 'code': 'MCH', 'dep': 20, 'life': 5},
        ]
        
        self.asset_categories = []
        for data in categories_data:
            cat, created = AssetCategory.objects.get_or_create(
                code=data['code'],
                defaults={
                    'name': data['name'],
                    'description': f'{data["name"]} assets',
                    'depreciation_rate': Decimal(data['dep']),
                    'useful_life_years': data['life'],
                    'is_active': True,
                }
            )
            self.asset_categories.append(cat)
        self.stdout.write('  ✓ Asset categories created')

    def seed_assets(self):
        """Seed assets"""
        self.stdout.write('Seeding assets...')
        
        assets_data = [
            {'name': 'County Headquarters Building', 'cat': 'BLD', 'type': 'immovable', 'cost': 50000000, 'serial': 'BLD-HQ-001'},
            {'name': 'Office Desk Set - Executive', 'cat': 'FUR', 'type': 'movable', 'cost': 35000, 'serial': 'FUR-DSK-001'},
            {'name': 'HP LaserJet Printer', 'cat': 'ICT', 'type': 'movable', 'cost': 25000, 'serial': 'ICT-PRT-001'},
            {'name': 'Conference Table - 20 Seater', 'cat': 'FUR', 'type': 'movable', 'cost': 80000, 'serial': 'FUR-TBL-001'},
            {'name': 'Perkins Generator Set 100KVA', 'cat': 'MCH', 'type': 'movable', 'cost': 450000, 'serial': 'MCH-GEN-001'},
            {'name': 'Dell Desktop Computer', 'cat': 'ICT', 'type': 'movable', 'cost': 45000, 'serial': 'ICT-CPU-001'},
            {'name': 'Office Chair - Ergonomic', 'cat': 'FUR', 'type': 'movable', 'cost': 15000, 'serial': 'FUR-CHR-001'},
            {'name': 'Filing Cabinet - 4 Drawer', 'cat': 'FUR', 'type': 'movable', 'cost': 12000, 'serial': 'FUR-FIL-001'},
        ]
        
        for idx, data in enumerate(assets_data, 1):
            cat = AssetCategory.objects.get(code=data['cat'])
            Asset.objects.get_or_create(
                asset_number=f'AST/{2024}/{idx:05d}',
                defaults={
                    'name': data['name'],
                    'description': f'{data["name"]} - County asset',
                    'category': cat,
                    'asset_type': data['type'],
                    'acquisition_date': date(2020, 1, 1),
                    'acquisition_cost': Decimal(data['cost']),
                    'current_value': Decimal(data['cost']) * Decimal('0.8'),
                    'sub_county': random.choice(self.sub_counties),
                    'department': random.choice(self.departments),
                    'location': Point(40.5, 1.75) if data['type'] == 'immovable' else None,
                    'serial_number': data['serial'],
                    'barcode': f'BC{2024}{idx:06d}',  # Generate unique barcode
                    'status': 'active',
                }
            )
            if idx <= len(assets_data):
                self.stdout.write(f'  ✓ Asset: {data["name"]}')

    def seed_case_categories(self):
        """Seed case categories"""
        self.stdout.write('Seeding case categories...')
        
        categories = [
            {'name': 'Land Disputes', 'code': 'LND-DIS'},
            {'name': 'Employment Disputes', 'code': 'EMP-DIS'},
            {'name': 'Contract Disputes', 'code': 'CNT-DIS'},
            {'name': 'Revenue Disputes', 'code': 'REV-DIS'},
        ]
        
        for data in categories:
            CaseCategory.objects.get_or_create(
                code=data['code'],
                defaults={
                    'name': data['name'],
                    'description': f'{data["name"]} category',
                    'is_active': True,
                }
            )
        self.stdout.write('  ✓ Case categories created')

    def seed_document_categories(self):
        """Seed document categories"""
        self.stdout.write('Seeding document categories...')
        
        categories = [
            {'name': 'County Assembly Bills', 'code': 'CAB', 'retention': 50},
            {'name': 'Financial Reports', 'code': 'FIN-RPT', 'retention': 10},
            {'name': 'Personnel Files', 'code': 'PER-FIL', 'retention': 75},
            {'name': 'Procurement Records', 'code': 'PRO-REC', 'retention': 15},
        ]
        
        for data in categories:
            DocumentCategory.objects.get_or_create(
                code=data['code'],
                defaults={
                    'name': data['name'],
                    'description': f'{data["name"]} category',
                    'retention_period_years': data['retention'],
                    'is_active': True,
                }
            )
        self.stdout.write('  ✓ Document categories created')

    def seed_business_categories(self):
        """Seed business categories"""
        self.stdout.write('Seeding business categories...')
        
        categories_data = [
            {'name': 'Retail Trade', 'code': 'RET'},
            {'name': 'Wholesale Trade', 'code': 'WHO'},
            {'name': 'Hospitality', 'code': 'HOS'},
            {'name': 'Professional Services', 'code': 'PRO'},
            {'name': 'Manufacturing', 'code': 'MAN'},
            {'name': 'Transport', 'code': 'TRN'},
        ]
        
        self.business_categories = []
        for data in categories_data:
            cat, created = BusinessCategory.objects.get_or_create(
                code=data['code'],
                defaults={
                    'name': data['name'],
                    'description': f'{data["name"]} businesses',
                    'is_active': True,
                }
            )
            self.business_categories.append(cat)
        self.stdout.write('  ✓ Business categories created')

    def seed_license_types(self):
        """Seed license types"""
        self.stdout.write('Seeding license types...')
        
        license_types_data = [
            {'name': 'Small Business Permit', 'cat': 'RET', 'stream': 'SBP', 'validity': 365},
            {'name': 'Medium Business Permit', 'cat': 'WHO', 'stream': 'SBP', 'validity': 365},
            {'name': 'Large Business Permit', 'cat': 'MAN', 'stream': 'SBP', 'validity': 365},
            {'name': 'Hotel License', 'cat': 'HOS', 'stream': 'SBP', 'validity': 365},
            {'name': 'Restaurant License', 'cat': 'HOS', 'stream': 'SBP', 'validity': 365},
            {'name': 'Bar & Lounge License', 'cat': 'HOS', 'stream': 'SBP', 'validity': 365},
            {'name': 'Professional Services License', 'cat': 'PRO', 'stream': 'SBP', 'validity': 365},
            {'name': 'Transport Business License', 'cat': 'TRN', 'stream': 'SBP', 'validity': 365},
            {'name': 'Retail Shop License', 'cat': 'RET', 'stream': 'SBP', 'validity': 365},
            {'name': 'Wholesale Business License', 'cat': 'WHO', 'stream': 'SBP', 'validity': 365},
        ]
        
        for idx, data in enumerate(license_types_data, 1):
            try:
                category = BusinessCategory.objects.get(code=data['cat'])
                stream = RevenueStream.objects.get(code=data['stream'])
                
                license_type, created = LicenseType.objects.get_or_create(
                    code=f'LIC-{data["cat"]}-{idx:02d}',
                    defaults={
                        'name': data['name'],
                        'description': f'License for {data["name"]}',
                        'business_category': category,
                        'revenue_stream': stream,
                        'validity_period_days': data['validity'],
                        'is_renewable': True,
                        'requires_inspection': random.choice([True, False]),
                        'is_active': True,
                    }
                )
                if created:
                    self.stdout.write(f'  ✓ License Type: {license_type.name}')
            except BusinessCategory.DoesNotExist:
                self.stdout.write(self.style.WARNING(f'  ✗ Business category {data["cat"]} not found'))
            except RevenueStream.DoesNotExist:
                self.stdout.write(self.style.WARNING(f'  ✗ Revenue stream {data["stream"]} not found'))

    def seed_parking_zones(self):
        """Seed parking zones"""
        self.stdout.write('Seeding parking zones...')
        
        zones_data = [
            {'name': 'Wajir CBD Zone A', 'code': 'CBD-A', 'type': 'Commercial', 'cap': 100},
            {'name': 'Wajir CBD Zone B', 'code': 'CBD-B', 'type': 'Commercial', 'cap': 150},
            {'name': 'Hospital Parking', 'code': 'HOSP', 'type': 'Public', 'cap': 50},
        ]
        
        for data in zones_data:
            sub_county = SubCounty.objects.get(name='Wajir East')
            ward = sub_county.wards.first()
            ParkingZone.objects.get_or_create(
                code=data['code'],
                defaults={
                    'name': data['name'],
                    'zone_type': data['type'],
                    'sub_county': sub_county,
                    'ward': ward,
                    'capacity': data['cap'],
                    'is_active': True,
                }
            )
        self.stdout.write('  ✓ Parking zones created')

    def seed_saccos(self):
        """Seed vehicle saccos"""
        self.stdout.write('Seeding saccos...')
        
        saccos_data = [
            {'name': 'Wajir Matatu Sacco', 'reg': 'SACCO/2020/001'},
            {'name': 'Habaswein Transport Sacco', 'reg': 'SACCO/2019/002'},
            {'name': 'North Eastern Bus Sacco', 'reg': 'SACCO/2021/003'},
        ]
        
        for data in saccos_data:
            citizen = random.choice(self.citizens)
            Sacco.objects.get_or_create(
                registration_number=data['reg'],
                defaults={
                    'name': data['name'],
                    'citizen': citizen,
                    'phone': f'072{random.randint(1000000, 9999999)}',
                    'physical_address': 'Wajir Town',
                    'is_active': True,
                }
            )
        self.stdout.write('  ✓ Saccos created')

    def seed_advertising_categories(self):
        """Seed advertising categories"""
        self.stdout.write('Seeding advertising categories...')
        
        categories = [
            {'name': 'Large Billboards', 'code': 'LBB'},
            {'name': 'Small Billboards', 'code': 'SBB'},
            {'name': 'Shop Signage', 'code': 'SSG'},
            {'name': 'Vehicle Branding', 'code': 'VBR'},
        ]
        
        for data in categories:
            AdvertisingCategory.objects.get_or_create(
                code=data['code'],
                defaults={
                    'name': data['name'],
                    'description': f'{data["name"]} category',
                    'is_active': True,
                }
            )
        self.stdout.write('  ✓ Advertising categories created')

    def seed_property_types(self):
        """Seed property types"""
        self.stdout.write('Seeding property types...')
        
        types = [
            {'name': 'Residential', 'code': 'RES'},
            {'name': 'Commercial', 'code': 'COM'},
            {'name': 'Agricultural', 'code': 'AGR'},
            {'name': 'Industrial', 'code': 'IND'},
            {'name': 'Mixed Use', 'code': 'MIX'},
        ]
        
        for data in types:
            PropertyType.objects.get_or_create(
                code=data['code'],
                defaults={
                    'name': data['name'],
                    'description': f'{data["name"]} property',
                    'is_active': True,
                }
            )
        self.stdout.write('  ✓ Property types created')

    def seed_land_use_types(self):
        """Seed land use types"""
        self.stdout.write('Seeding land use types...')
        
        types = [
            {'name': 'Residential', 'code': 'RES'},
            {'name': 'Commercial', 'code': 'COM'},
            {'name': 'Grazing Land', 'code': 'GRZ'},
            {'name': 'Government', 'code': 'GOV'},
        ]
        
        for data in types:
            LandUseType.objects.get_or_create(
                code=data['code'],
                defaults={
                    'name': data['name'],
                    'description': f'{data["name"]} land use',
                    'is_active': True,
                }
            )
        self.stdout.write('  ✓ Land use types created')

    def seed_fine_categories(self):
        """Seed fine categories"""
        self.stdout.write('Seeding fine categories...')
        
        categories = [
            {'name': 'Illegal Parking', 'code': 'FIN-PRK'},
            {'name': 'Operating Without License', 'code': 'FIN-LIC'},
            {'name': 'Environmental Offences', 'code': 'FIN-ENV'},
            {'name': 'Building Code Violations', 'code': 'FIN-BLD'},
        ]
        
        for data in categories:
            stream = random.choice(self.revenue_streams)
            FineCategory.objects.get_or_create(
                code=data['code'],
                defaults={
                    'name': data['name'],
                    'description': f'{data["name"]} fines',
                    'revenue_stream': stream,
                    'is_active': True,
                }
            )
        self.stdout.write('  ✓ Fine categories created')

    def seed_training_programs(self):
        """Seed training programs"""
        self.stdout.write('Seeding training programs...')
        
        programs = [
            {'name': 'Customer Service Excellence', 'code': 'TRN-CS', 'provider': 'Kenya School of Government', 'days': 5, 'cost': 15000},
            {'name': 'Financial Management', 'code': 'TRN-FM', 'provider': 'ICPAK', 'days': 10, 'cost': 35000},
            {'name': 'ICT Skills Training', 'code': 'TRN-ICT', 'provider': 'Technical University', 'days': 7, 'cost': 20000},
        ]
        
        for data in programs:
            start_date = date.today() + timedelta(days=random.randint(30, 90))
            TrainingProgram.objects.get_or_create(
                program_code=data['code'],
                defaults={
                    'program_name': data['name'],
                    'description': f'{data["name"]} training program',
                    'provider': data['provider'],
                    'duration_days': data['days'],
                    'cost_per_participant': Decimal(data['cost']),
                    'start_date': start_date,
                    'end_date': start_date + timedelta(days=data['days']),
                    'venue': 'Wajir County Training Centre',
                    'max_participants': 30,
                    'is_active': True,
                }
            )
        self.stdout.write('  ✓ Training programs created')
        
        self.stdout.write(self.style.SUCCESS('\n' + '='*70))
        self.stdout.write(self.style.SUCCESS('DATA SEEDING SUMMARY'))
        self.stdout.write(self.style.SUCCESS('='*70))
        self.stdout.write(f'County: {County.objects.count()}')
        self.stdout.write(f'Sub-Counties: {SubCounty.objects.count()}')
        self.stdout.write(f'Wards: {Ward.objects.count()}')
        self.stdout.write(f'Departments: {Department.objects.count()}')
        self.stdout.write(f'Users: {User.objects.count()}')
        self.stdout.write(f'Citizens: {Citizen.objects.count()}')
        self.stdout.write(f'Revenue Streams: {RevenueStream.objects.count()}')
        self.stdout.write(f'Health Facilities: {HealthFacility.objects.count()}')
        self.stdout.write(f'Patients: {Patient.objects.count()}')
        self.stdout.write(f'Fleet Vehicles: {FleetVehicle.objects.count()}')
        self.stdout.write(f'Facilities: {Facility.objects.count()}')
        self.stdout.write(f'Assets: {Asset.objects.count()}')
        self.stdout.write(self.style.SUCCESS('='*70))