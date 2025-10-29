"""
Django Management Command: Seed Revenue and Hospital Data
Location: main_application/management/commands/seed_revenue.py
Run: python manage.py seed_revenue
"""

import random
from datetime import datetime, timedelta
from decimal import Decimal
from django.core.management.base import BaseCommand
from django.utils import timezone
from django.db import transaction
from django.db import models as django_models

from main_application.models import (
    User, Citizen, Department, SubCounty, Ward, County,
    RevenueStream, ChargeRate, PenaltyRule, Bill, BillLineItem,
    PaymentMethod, Payment, Patient, HealthFacility, Triage, Visit, HospitalWard
)


class Command(BaseCommand):
    help = 'Seeds revenue and hospital management data for Wajir County ERP'

    def add_arguments(self, parser):
        parser.add_argument(
            '--citizens',
            type=int,
            default=300,
            help='Number of citizens to create (default: 300)'
        )
        parser.add_argument(
            '--start-date',
            type=str,
            default='2024-01-01',
            help='Start date for historical data (format: YYYY-MM-DD)'
        )
        parser.add_argument(
            '--skip-citizens',
            action='store_true',
            help='Skip citizen creation (use existing citizens only)'
        )
        parser.add_argument(
            '--skip-revenue',
            action='store_true',
            help='Skip revenue streams and bills creation'
        )
        parser.add_argument(
            '--skip-hospital',
            action='store_true',
            help='Skip hospital/patient data creation'
        )

    def handle(self, *args, **options):
        self.stdout.write("=" * 70)
        self.stdout.write(self.style.SUCCESS("🚀 WAJIR COUNTY ERP - DATA SEEDING"))
        self.stdout.write("=" * 70)

        # Parse options
        self.total_citizens = options['citizens']
        self.start_date = datetime.strptime(options['start_date'], '%Y-%m-%d')
        self.end_date = datetime.now()
        
        self.stdout.write(f"📅 Date Range: {self.start_date.date()} to {self.end_date.date()}")
        self.stdout.write(f"👥 Target Citizens: {self.total_citizens}")
        self.stdout.write("=" * 70)

        try:
            # Get existing data
            self.data = self.get_existing_data()
            
            if not self.data['sub_counties'] or not self.data['wards']:
                self.stdout.write(self.style.ERROR(
                    "\n❌ ERROR: No sub-counties or wards found in database!"
                ))
                self.stdout.write("Please seed administrative structure first.")
                return

            # Execute seeding based on options
            if not options['skip_revenue']:
                self.create_revenue_streams()
                self.create_payment_methods()

            if not options['skip_citizens']:
                self.citizens = self.create_citizens()
            else:
                self.citizens = list(Citizen.objects.all())
                self.stdout.write(f"\n👥 Using {len(self.citizens)} existing citizens")

            if not options['skip_revenue']:
                self.create_bills_and_payments()

            if not options['skip_hospital']:
                self.create_patients_and_visits()

            # Print summary
            self.print_summary()

        except Exception as e:
            self.stdout.write(self.style.ERROR(f"\n❌ ERROR: {str(e)}"))
            import traceback
            traceback.print_exc()

    def get_existing_data(self):
        """Fetch existing data from database"""
        self.stdout.write("\n📊 Fetching existing data...")
        
        data = {
            'county': County.objects.first(),
            'sub_counties': list(SubCounty.objects.filter(is_active=True)),
            'wards': list(Ward.objects.filter(is_active=True)),
            'departments': list(Department.objects.filter(is_active=True)),
            'users': list(User.objects.filter(is_active=True)),
            'facilities': list(HealthFacility.objects.filter(is_active=True))
        }
        
        self.stdout.write(f"  ✓ County: {data['county']}")
        self.stdout.write(f"  ✓ Sub-counties: {len(data['sub_counties'])}")
        self.stdout.write(f"  ✓ Wards: {len(data['wards'])}")
        self.stdout.write(f"  ✓ Departments: {len(data['departments'])}")
        self.stdout.write(f"  ✓ Users: {len(data['users'])}")
        self.stdout.write(f"  ✓ Health Facilities: {len(data['facilities'])}")
        
        return data

    def create_revenue_streams(self):
        """Create revenue streams and charge rates"""
        self.stdout.write("\n💰 Creating Revenue Streams...")
        
        streams_config = [
            {
                'name': 'Single Business Permit',
                'code': 'SBP',
                'description': 'Annual business operating license',
                'is_recurring': True,
                'billing_frequency': 'annual',
                'rates': [
                    {'name': 'Small Business (Annual)', 'amount': Decimal('5000.00')},
                    {'name': 'Medium Business (Annual)', 'amount': Decimal('10000.00')},
                    {'name': 'Large Business (Annual)', 'amount': Decimal('20000.00')},
                ]
            },
            {
                'name': 'Land Rates',
                'code': 'LR',
                'description': 'Property tax on land and buildings',
                'is_recurring': True,
                'billing_frequency': 'annual',
                'rates': [
                    {'name': 'Residential Property', 'amount': Decimal('3000.00')},
                    {'name': 'Commercial Property', 'amount': Decimal('8000.00')},
                    {'name': 'Industrial Property', 'amount': Decimal('15000.00')},
                ]
            },
            {
                'name': 'Market Fees',
                'code': 'MKT',
                'description': 'Daily market stall fees',
                'is_recurring': True,
                'billing_frequency': 'daily',
                'rates': [
                    {'name': 'Small Stall (Daily)', 'amount': Decimal('50.00')},
                    {'name': 'Medium Stall (Daily)', 'amount': Decimal('100.00')},
                    {'name': 'Large Stall (Daily)', 'amount': Decimal('200.00')},
                ]
            },
            {
                'name': 'Parking Fees',
                'code': 'PKG',
                'description': 'Vehicle parking charges',
                'is_recurring': False,
                'billing_frequency': '',
                'rates': [
                    {'name': 'Motorcycle (Hourly)', 'amount': Decimal('20.00')},
                    {'name': 'Car (Hourly)', 'amount': Decimal('50.00')},
                    {'name': 'Truck (Hourly)', 'amount': Decimal('100.00')},
                ]
            },
            {
                'name': 'Health Facility Fees',
                'code': 'HF',
                'description': 'Hospital and clinic service charges',
                'is_recurring': False,
                'billing_frequency': '',
                'rates': [
                    {'name': 'Consultation', 'amount': Decimal('200.00')},
                    {'name': 'Laboratory Test', 'amount': Decimal('500.00')},
                    {'name': 'X-Ray', 'amount': Decimal('800.00')},
                    {'name': 'Minor Surgery', 'amount': Decimal('3000.00')},
                ]
            },
            {
                'name': 'Building Permit',
                'code': 'BP',
                'description': 'Construction and building approvals',
                'is_recurring': False,
                'billing_frequency': '',
                'rates': [
                    {'name': 'Residential (per sq meter)', 'amount': Decimal('50.00')},
                    {'name': 'Commercial (per sq meter)', 'amount': Decimal('100.00')},
                ]
            },
        ]
        
        department = self.data['departments'][0] if self.data['departments'] else None
        
        for stream_config in streams_config:
            # Check if stream exists by code OR name
            stream = RevenueStream.objects.filter(
                django_models.Q(code=stream_config['code']) | django_models.Q(name=stream_config['name'])
            ).first()
            
            if stream:
                self.stdout.write(f"  → Stream exists: {stream.name} ({stream.code})")
                created = False
            else:
                # Create new stream
                with transaction.atomic():
                    stream = RevenueStream.objects.create(
                        code=stream_config['code'],
                        name=stream_config['name'],
                        description=stream_config['description'],
                        department=department,
                        is_recurring=stream_config['is_recurring'],
                        billing_frequency=stream_config['billing_frequency'],
                        is_active=True
                    )
                    created = True
                    self.stdout.write(f"  ✓ Created stream: {stream.name} ({stream.code})")
            
            # Only create rates and penalties if stream was just created
            if created:
                with transaction.atomic():
                    # Create charge rates
                    for rate_config in stream_config['rates']:
                        ChargeRate.objects.create(
                            revenue_stream=stream,
                            name=rate_config['name'],
                            rate_type='fixed',
                            amount=rate_config['amount'],
                            effective_from=self.start_date.date(),
                            is_active=True
                        )
                    
                    # Create penalty rule
                    PenaltyRule.objects.create(
                        revenue_stream=stream,
                        name=f'{stream.name} Late Payment Penalty',
                        grace_period_days=30,
                        penalty_type='percentage',
                        penalty_amount=Decimal('5.00'),
                        max_penalty_amount=Decimal('10000.00'),
                        effective_from=self.start_date.date(),
                        is_active=True
                    )
                    self.stdout.write(f"    → Added {len(stream_config['rates'])} charge rates and penalty rule")

    def create_payment_methods(self):
        """Create payment methods"""
        self.stdout.write("\n💳 Creating Payment Methods...")
        
        methods = [
            {'name': 'M-Pesa', 'code': 'MPESA', 'provider': 'Safaricom', 'is_online': True},
            {'name': 'Bank Transfer', 'code': 'BANK', 'provider': 'Various Banks', 'is_online': True},
            {'name': 'Cash', 'code': 'CASH', 'provider': 'Manual', 'is_online': False},
            {'name': 'Cheque', 'code': 'CHEQUE', 'provider': 'Manual', 'is_online': False},
        ]
        
        with transaction.atomic():
            for method_data in methods:
                method, created = PaymentMethod.objects.get_or_create(
                    code=method_data['code'],
                    defaults=method_data
                )
                if created:
                    self.stdout.write(f"  ✓ Created: {method.name}")
                else:
                    self.stdout.write(f"  → Exists: {method.name}")

    def create_citizens(self):
        """Create citizen records"""
        self.stdout.write(f"\n👥 Creating Citizens (Target: {self.total_citizens})...")
        
        existing_count = Citizen.objects.count()
        
        if existing_count > 0:
            self.stdout.write(f"  ℹ️  Found {existing_count} existing citizens")
        
        citizens_to_create = self.total_citizens - existing_count
        
        if citizens_to_create <= 0:
            self.stdout.write(f"  ✅ Target already met")
            return list(Citizen.objects.all())
        
        # Kenyan names
        first_names_male = [
            'Mohamed', 'Ahmed', 'Hassan', 'Ibrahim', 'Abdi', 'Ali', 'Omar', 'Yusuf',
            'Abdullahi', 'Adan', 'Khalif', 'Issack', 'Issa', 'Mohamud', 'Abdirashid',
            'John', 'Peter', 'David', 'James', 'Joseph', 'Daniel', 'Samuel', 'Michael',
            'Francis', 'Paul', 'Patrick', 'Anthony', 'Robert', 'William', 'Charles'
        ]
        
        first_names_female = [
            'Halima', 'Fatuma', 'Amina', 'Asha', 'Maryam', 'Habiba', 'Zainab', 'Farhiya',
            'Iftin', 'Anab', 'Fardowsa', 'Suad', 'Sahra', 'Faduma', 'Ubah',
            'Mary', 'Jane', 'Elizabeth', 'Grace', 'Faith', 'Lucy', 'Agnes', 'Catherine',
            'Margaret', 'Rose', 'Sarah', 'Ruth', 'Rebecca', 'Ann', 'Joyce'
        ]
        
        last_names = [
            'Mohamed', 'Ahmed', 'Hassan', 'Abdi', 'Ali', 'Ibrahim', 'Omar', 'Yusuf',
            'Abdullahi', 'Hussein', 'Adan', 'Mohamud', 'Khalif', 'Issack', 'Abdirashid',
            'Kamau', 'Mwangi', 'Ochieng', 'Otieno', 'Kipchoge', 'Korir', 'Mutua', 'Njoroge'
        ]
        
        business_types = [
            'Shop', 'Hotel', 'Restaurant', 'Butchery', 'Pharmacy', 'Hardware', 'Supermarket',
            'Wholesale', 'Electronics', 'Clothing Store', 'Salon', 'Bakery', 'Transport',
            'Garage', 'Internet Cafe', 'Mobile Money Agent', 'Construction', 'Welding'
        ]
        
        created_count = 0
        batch_size = 50
        
        for i in range(0, citizens_to_create, batch_size):
            batch_end = min(i + batch_size, citizens_to_create)
            
            for j in range(i, batch_end):
                entity_type = random.choices(['individual', 'business'], weights=[0.7, 0.3])[0]
                ward = random.choice(self.data['wards'])
                
                # Generate unique identifiers
                max_attempts = 10
                for attempt in range(max_attempts):
                    try:
                        if entity_type == 'individual':
                            gender = random.choice(['Male', 'Female'])
                            first_name = random.choice(first_names_male if gender == 'Male' else first_names_female)
                            last_name = random.choice(last_names)
                            unique_id = self.generate_id_number()
                            phone = self.random_phone()
                            
                            # Check if unique_identifier or phone already exists
                            if Citizen.objects.filter(
                                django_models.Q(unique_identifier=unique_id) | 
                                django_models.Q(phone_primary=phone)
                            ).exists():
                                continue
                            
                            citizen = Citizen(
                                entity_type='individual',
                                unique_identifier=unique_id,
                                first_name=first_name,
                                last_name=last_name,
                                date_of_birth=self.random_date(datetime(1960, 1, 1), datetime(2005, 12, 31)).date(),
                                gender=gender,
                                phone_primary=phone,
                                email=f"{first_name.lower()}.{last_name.lower()}{random.randint(1,999)}@example.com" if random.random() > 0.3 else '',
                                sub_county=ward.sub_county,
                                ward=ward,
                                is_active=True,
                                created_by=random.choice(self.data['users']) if self.data['users'] else None
                            )
                        else:
                            business_type = random.choice(business_types)
                            business_name = f"{random.choice(last_names)} {business_type}"
                            unique_id = f"BUS{random.randint(100000, 999999)}"
                            phone = self.random_phone()
                            
                            # Check if unique_identifier or phone already exists
                            if Citizen.objects.filter(
                                django_models.Q(unique_identifier=unique_id) | 
                                django_models.Q(phone_primary=phone)
                            ).exists():
                                continue
                            
                            citizen = Citizen(
                                entity_type='business',
                                unique_identifier=unique_id,
                                business_name=business_name,
                                registration_number=f"BN{random.randint(100000, 999999)}",
                                phone_primary=phone,
                                email=f"{business_name.lower().replace(' ', '')}{random.randint(1,999)}@business.com" if random.random() > 0.5 else '',
                                sub_county=ward.sub_county,
                                ward=ward,
                                is_active=True,
                                created_by=random.choice(self.data['users']) if self.data['users'] else None
                            )
                        
                        # Save immediately to get ID
                        citizen.save()
                        created_count += 1
                        break  # Successfully created, exit retry loop
                        
                    except Exception as e:
                        if attempt == max_attempts - 1:
                            self.stdout.write(self.style.WARNING(f"  ⚠️  Failed to create citizen after {max_attempts} attempts"))
                        continue
            
            self.stdout.write(f"  ✓ Created {created_count}/{citizens_to_create} citizens")
        
        # Return ALL citizens (existing + newly created)
        all_citizens = list(Citizen.objects.all())
        self.stdout.write(self.style.SUCCESS(f"  ✅ Total citizens available: {len(all_citizens)}"))
        return all_citizens

    def create_bills_and_payments(self):
        """Create bills and payments"""
        self.stdout.write("\n📄 Creating Bills and Payments...")
        
        revenue_streams = list(RevenueStream.objects.all())
        payment_methods = list(PaymentMethod.objects.all())
        
        if not revenue_streams:
            self.stdout.write(self.style.WARNING("  ⚠️  No revenue streams found. Skipping..."))
            return
        
        total_bills = 0
        total_payments = 0
        
        current_date = self.start_date
        
        while current_date <= self.end_date:
            month_end = current_date + timedelta(days=30)
            
            num_bills = random.randint(20, 50)
            selected_citizens = random.sample(self.citizens, min(num_bills, len(self.citizens)))
            
            for citizen in selected_citizens:
                stream = random.choice(revenue_streams)
                charge_rates = list(stream.charge_rates.filter(is_active=True))
                
                if not charge_rates:
                    continue
                
                charge_rate = random.choice(charge_rates)
                base_amount = charge_rate.amount
                variation = Decimal(random.uniform(0.9, 1.1))
                bill_amount = (base_amount * variation).quantize(Decimal('0.01'))
                
                penalty = Decimal('0.00')
                if random.random() < 0.2:
                    penalty = (bill_amount * Decimal('0.05')).quantize(Decimal('0.01'))
                
                total_amount = bill_amount + penalty
                bill_date = self.random_date(current_date, month_end)
                due_date = bill_date + timedelta(days=30)
                
                with transaction.atomic():
                    bill = Bill.objects.create(
                        bill_number=self.generate_bill_number(),
                        citizen=citizen,
                        revenue_stream=stream,
                        bill_date=bill_date.date(),
                        due_date=due_date.date(),
                        bill_amount=bill_amount,
                        penalty_amount=penalty,
                        total_amount=total_amount,
                        amount_paid=Decimal('0.00'),
                        balance=total_amount,
                        status='issued',
                        sub_county=citizen.sub_county,
                        ward=citizen.ward,
                        description=f"{stream.name} - {charge_rate.name}",
                        created_by=random.choice(self.data['users']) if self.data['users'] else None,
                        created_at=bill_date
                    )
                    
                    BillLineItem.objects.create(
                        bill=bill,
                        description=charge_rate.name,
                        quantity=Decimal('1.00'),
                        unit_price=bill_amount,
                        amount=bill_amount,
                        charge_rate=charge_rate
                    )
                    
                    total_bills += 1
                    
                    # 80% payment rate
                    if random.random() < 0.8:
                        payment_method = random.choice(payment_methods)
                        payment_date = self.random_date(bill_date, min(month_end, self.end_date))
                        
                        if random.random() < 0.7:
                            payment_amount = total_amount
                            bill.status = 'paid'
                        else:
                            payment_amount = (total_amount * Decimal(random.uniform(0.3, 0.9))).quantize(Decimal('0.01'))
                            bill.status = 'partially_paid'
                        
                        bill.amount_paid = payment_amount
                        bill.balance = total_amount - payment_amount
                        bill.save()
                        
                        # Generate unique transaction reference
                        txn_ref = f"TXN{random.randint(1000000, 9999999)}"
                        while Payment.objects.filter(transaction_reference=txn_ref).exists():
                            txn_ref = f"TXN{random.randint(1000000, 9999999)}"
                        
                        Payment.objects.create(
                            receipt_number=self.generate_receipt_number(),
                            transaction_reference=txn_ref,
                            citizen=citizen,
                            bill=bill,
                            payment_method=payment_method,
                            payment_date=payment_date,
                            amount=payment_amount,
                            status='completed',
                            payer_name=citizen.first_name if citizen.entity_type == 'individual' else citizen.business_name,
                            payer_phone=citizen.phone_primary,
                            revenue_stream=stream,
                            sub_county=citizen.sub_county,
                            ward=citizen.ward,
                            collected_by=random.choice(self.data['users']) if self.data['users'] else None,
                            created_at=payment_date
                        )
                        
                        total_payments += 1
            
            current_date = month_end
            self.stdout.write(f"  ✓ Processed {current_date.strftime('%B %Y')}")
        
        self.stdout.write(self.style.SUCCESS(
            f"  ✅ Created {total_bills} bills and {total_payments} payments"
        ))

    def create_patients_and_visits(self):
        """Create patient records and hospital visits"""
        self.stdout.write("\n🏥 Creating Patient Records and Visits...")
        
        facilities = self.data['facilities']
        if not facilities:
            self.stdout.write(self.style.WARNING("  ⚠️  No health facilities found. Skipping..."))
            return
        
        num_patients = int(len(self.citizens) * 0.4)
        patient_citizens = random.sample(
            [c for c in self.citizens if c.entity_type == 'individual'],
            min(num_patients, len([c for c in self.citizens if c.entity_type == 'individual']))
        )
        
        # Names for next of kin
        first_names_male = ['Mohamed', 'Ahmed', 'Hassan', 'Ibrahim', 'Abdi', 'Ali', 'John', 'Peter', 'David']
        last_names = ['Mohamed', 'Ahmed', 'Hassan', 'Abdi', 'Ali', 'Kamau', 'Mwangi']
        
        patients = []
        total_visits = 0
        
        # Create patients
        for citizen in patient_citizens:
            patient = Patient.objects.create(
                patient_number=self.generate_patient_number(),
                citizen=citizen,
                first_name=citizen.first_name,
                last_name=citizen.last_name,
                date_of_birth=citizen.date_of_birth,
                gender='M' if citizen.gender == 'Male' else 'F',
                phone=citizen.phone_primary,
                email=citizen.email or '',
                address=citizen.physical_address or 'Wajir County',
                next_of_kin_name=f"{random.choice(first_names_male)} {random.choice(last_names)}",
                next_of_kin_phone=self.random_phone(),
                next_of_kin_relationship=random.choice(['Spouse', 'Parent', 'Sibling', 'Child']),
                blood_group=random.choice(['A+', 'A-', 'B+', 'B-', 'O+', 'O-', 'AB+', 'AB-']),
                is_active=True
            )
            patients.append(patient)
        
        self.stdout.write(f"  ✓ Created {len(patients)} patient records")
        
        # Create visits
        diagnoses = [
            'Malaria', 'Upper Respiratory Tract Infection', 'Diarrhea', 'Typhoid',
            'Pneumonia', 'Hypertension', 'Diabetes Mellitus', 'Skin Infection',
            'Urinary Tract Infection', 'Gastritis', 'Anemia', 'Asthma'
        ]
        
        treatments = [
            'Antimalarial drugs prescribed', 'Antibiotics prescribed', 'ORS and fluids',
            'Antihypertensive medication', 'Insulin therapy', 'Wound dressing',
            'Oral medication', 'Injection administered', 'Nebulization done'
        ]
        
        for patient in patients:
            num_visits = random.randint(1, 5)
            
            for _ in range(num_visits):
                facility = random.choice(facilities)
                visit_date = self.random_date(self.start_date, self.end_date)
                
                with transaction.atomic():
                    triage = Triage.objects.create(
                        patient=patient,
                        facility=facility,
                        visit_date=visit_date,
                        priority=random.choice(['emergency', 'urgent', 'normal']),
                        temperature=Decimal(random.uniform(36.0, 39.5)),
                        blood_pressure=f"{random.randint(90, 140)}/{random.randint(60, 90)}",
                        pulse_rate=random.randint(60, 100),
                        weight=Decimal(random.uniform(40.0, 90.0)),
                        height=Decimal(random.uniform(150.0, 180.0)),
                        chief_complaint=random.choice(['Fever', 'Headache', 'Cough', 'Abdominal pain', 'Chest pain']),
                        triaged_by=random.choice(self.data['users']) if self.data['users'] else None
                    )
                    
                    Visit.objects.create(
                        visit_number=self.generate_visit_number(),
                        patient=patient,
                        facility=facility,
                        triage=triage,
                        visit_type=random.choice(['outpatient', 'emergency']),
                        visit_date=visit_date,
                        diagnosis=random.choice(diagnoses),
                        treatment=random.choice(treatments),
                        notes=f"Patient examined and treated. Follow-up in {random.randint(1, 4)} weeks.",
                        attended_by=random.choice(self.data['users']) if self.data['users'] else None,
                        is_complete=True,
                        created_at=visit_date
                    )
                    
                    total_visits += 1
        
        self.stdout.write(self.style.SUCCESS(f"  ✅ Created {total_visits} hospital visits"))

    def print_summary(self):
        """Print summary of seeded data"""
        self.stdout.write("\n" + "=" * 70)
        self.stdout.write(self.style.SUCCESS("✅ DATA SEEDING COMPLETED!"))
        self.stdout.write("=" * 70)
        
        self.stdout.write("\n📊 SUMMARY:")
        self.stdout.write(f"  Citizens: {Citizen.objects.count()}")
        self.stdout.write(f"  Revenue Streams: {RevenueStream.objects.count()}")
        self.stdout.write(f"  Charge Rates: {ChargeRate.objects.count()}")
        self.stdout.write(f"  Bills: {Bill.objects.count()}")
        self.stdout.write(f"  Payments: {Payment.objects.count()}")
        self.stdout.write(f"  Patients: {Patient.objects.count()}")
        self.stdout.write(f"  Hospital Visits: {Visit.objects.count()}")
        self.stdout.write("\n" + self.style.SUCCESS("🎉 System ready with realistic data!"))

    # Utility methods
    def random_date(self, start, end):
        """Generate random date between start and end"""
        delta = end - start
        random_days = random.randint(0, delta.days)
        return start + timedelta(days=random_days)

    def random_phone(self):
        """Generate random Kenyan phone number"""
        prefixes = ['0712', '0713', '0714', '0715', '0722', '0723', '0724', '0725', 
                    '0732', '0733', '0734', '0735', '0740', '0741', '0742', '0745']
        return f"{random.choice(prefixes)}{random.randint(100000, 999999)}"

    def generate_id_number(self):
        """Generate random Kenyan ID number"""
        return f"{random.randint(10000000, 39999999)}"

    def generate_bill_number(self):
        """Generate unique bill number"""
        max_attempts = 20
        for _ in range(max_attempts):
            bill_number = f"BILL{datetime.now().year}{random.randint(100000, 999999)}"
            if not Bill.objects.filter(bill_number=bill_number).exists():
                return bill_number
        # Fallback with timestamp
        return f"BILL{datetime.now().year}{int(datetime.now().timestamp())}"

    def generate_receipt_number(self):
        """Generate unique receipt number"""
        max_attempts = 20
        for _ in range(max_attempts):
            receipt_number = f"RCT{datetime.now().year}{random.randint(100000, 999999)}"
            if not Payment.objects.filter(receipt_number=receipt_number).exists():
                return receipt_number
        # Fallback with timestamp
        return f"RCT{datetime.now().year}{int(datetime.now().timestamp())}"

    def generate_patient_number(self):
        """Generate unique patient number"""
        max_attempts = 20
        for _ in range(max_attempts):
            patient_number = f"PAT{random.randint(100000, 999999)}"
            if not Patient.objects.filter(patient_number=patient_number).exists():
                return patient_number
        # Fallback with timestamp
        return f"PAT{int(datetime.now().timestamp())}"

    def generate_visit_number(self):
        """Generate unique visit number"""
        max_attempts = 20
        for _ in range(max_attempts):
            visit_number = f"VISIT{datetime.now().year}{random.randint(10000, 99999)}"
            if not Visit.objects.filter(visit_number=visit_number).exists():
                return visit_number
        # Fallback with timestamp
        return f"VISIT{datetime.now().year}{int(datetime.now().timestamp())}"