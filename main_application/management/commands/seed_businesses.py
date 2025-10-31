from django.core.management.base import BaseCommand
from django.contrib.gis.geos import Point
from django.contrib.auth import get_user_model   # ✅ Correct way
import random
from datetime import datetime, timedelta

from main_application.models import Business, Citizen, BusinessCategory, SubCounty, Ward

User = get_user_model()  # ✅ Use custom user


class Command(BaseCommand):
    help = "Seed real Kenyan-like businesses in Wajir County (no faker)"

    def handle(self, *args, **kwargs):
        admin = User.objects.filter(is_superuser=True).first()
        citizens = list(Citizen.objects.all())
        categories = list(BusinessCategory.objects.all())
        subcounties = list(SubCounty.objects.all())

        if not citizens or not categories or not subcounties:
            self.stdout.write(self.style.ERROR("Ensure Citizens, Categories, & Subcounties exist."))
            return

        # Real-style Kenyan business names
        business_list = [
            "Wajir General Stores", "Al-Huda Electronics", "Eastleigh Traders Wajir",
            "Baraza Cyber & Printing", "Wajir Modern Butchery", "North Frontier Mini-Mart",
            "Madina Medical Clinic", "Al-Rahma Pharmaceuticals", "Safari Fast Foods",
            "Wajir Livestock Traders", "Al-Aqsa Hardware", "Hassan & Sons Transport",
            "Jubba Construction Co.", "Wajir Fresh Bakery", "Kismayu Textiles",
            "Garissa Road Hotel", "Nairobi Auto Parts Wajir", "Eyo M-Pesa & Airtel Money",
            "Wajir Timber & Furniture", "North Eastern Plastics & Water Tanks",
            "Sheikh Supermarket", "Wajir Premier Academy Canteen", "Mama Halima Restaurant",
            "Bulla Jogoo Water Supply", "Al-Shamsa Ladies Salon", "Youth Innovation Hub Wajir",
            "Sabri Butchery & Grill", "Nomad Logistics Wajir", "Wajir ICT Solutions",
            "Desert Fuel Suppliers"
        ]

        # Wajir town center coordinates (public data)
        WAJIR_LAT = 1.7470
        WAJIR_LON = 40.0573

        def random_phone():
            return f"07{random.randint(00, 99)}{random.randint(100000, 999999)}"

        count = 0

        for biz_name in business_list:
            citizen = random.choice(citizens)
            category = random.choice(categories)
            subcounty = random.choice(subcounties)

            wards = Ward.objects.filter(sub_county=subcounty)
            ward = random.choice(wards) if wards else random.choice(Ward.objects.all())

            business_number = f"WAJIR-{random.randint(10000,99999)}"
            trading_name = f"{biz_name} Ltd"
            registration_no = f"BN-{random.randint(100000, 999999)}"
            employees = random.randint(1, 25)
            turnover = random.choice([250000, 500000, 1200000, 2500000, 3500000, 5000000])

            # random safe gps nearby wajir town
            lat = WAJIR_LAT + random.uniform(-0.030, 0.030)
            lon = WAJIR_LON + random.uniform(-0.030, 0.030)

            Business.objects.create(
                business_number=business_number,
                citizen=citizen,
                business_name=biz_name,
                trading_name=trading_name,
                business_category=category,
                registration_number=registration_no,
                physical_address=f"{ward.name}, {subcounty.name}, Wajir County",
                sub_county=subcounty,
                ward=ward,
                location=Point(lon, lat),
                plot_number=f"Plot-{random.randint(1,490)}",
                nature_of_business="General Trading & Services",
                number_of_employees=employees,
                annual_turnover=turnover,
                phone=random_phone(),
                email=f"{biz_name.replace(' ', '').lower()}@gmail.com",
                registration_date=datetime.now().date() - timedelta(days=random.randint(60, 1200)),
                created_by=admin
            )

            count += 1
            self.stdout.write(self.style.SUCCESS(f"✅ Created: {biz_name}"))

        self.stdout.write(self.style.SUCCESS(f"🎯 Completed: {count} businesses seeded in Wajir County"))
