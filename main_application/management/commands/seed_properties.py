from django.core.management.base import BaseCommand
from django.contrib.gis.geos import Point, Polygon
from django.utils import timezone
import random
from datetime import timedelta

from django.contrib.auth import get_user_model
from main_application.models import (
    Property, Citizen, SubCounty, Ward,
    PropertyType, LandUseType
)

User = get_user_model()

class Command(BaseCommand):
    help = "Seed 25 properties for Wajir County"

    def handle(self, *args, **kwargs):
        citizens = list(Citizen.objects.all())
        subcounties = list(SubCounty.objects.all())
        wards = list(Ward.objects.all())
        ptypes = list(PropertyType.objects.all())
        landuses = list(LandUseType.objects.all())

        if not citizens or not subcounties or not wards or not ptypes or not landuses:
            self.stdout.write(self.style.ERROR(
                "Ensure Citizens, SubCounties, Wards, Property Types & Land Use Types exist first!"
            ))
            return
        
        property_statuses = ["active", "inactive", "disputed", "subdivided"]
        streets = [
            "Waberi Street", "Madaraka Road", "Township Market Rd",
            "Airport Road", "Griftu Road", "Mandera Road", "Garissa Road"
        ]

        base_lat, base_lon = 1.7500, 40.0570   # Wajir Town central coords

        for i in range(1, 26):
            citizen = random.choice(citizens)
            subcounty = random.choice(subcounties)
            ward = random.choice([w for w in wards if w.sub_county == subcounty])

            # Create small random variations around Wajir town
            lat = base_lat + random.uniform(-0.02, 0.02)
            lon = base_lon + random.uniform(-0.02, 0.02)
            location = Point(lon, lat)

            # Demo square polygon around point (fake parcel shape)
            poly_buffer = 0.0005
            boundary = Polygon((
                (lon - poly_buffer, lat - poly_buffer),
                (lon - poly_buffer, lat + poly_buffer),
                (lon + poly_buffer, lat + poly_buffer),
                (lon + poly_buffer, lat - poly_buffer),
                (lon - poly_buffer, lat - poly_buffer),
            ))

            parcel_no = f"WJR/PRCL/{timezone.now().year}/{1000 + i}"

            area = random.randint(500, 8000)  # sqm
            rate = area * random.uniform(1.5, 4.5)
            assessed = rate * random.uniform(5, 12)

            reg_date = timezone.now().date() - timedelta(days=random.randint(30, 2000))

            Property.objects.create(
                parcel_number=parcel_no,
                original_parcel_number=parcel_no if random.random() > 0.2 else "",

                owner=citizen,
                property_type=random.choice(ptypes),
                land_use_type=random.choice(landuses),

                area_sqm=area,
                assessed_value=round(assessed, 2),

                location=location,
                boundary=boundary,
                sub_county=subcounty,
                ward=ward,

                street=random.choice(streets),
                plot_number=str(random.randint(1, 400)),
                building_name=random.choice(["", "Al-Ansaar Building", "Wajir Mall", "Town Plaza"]),

                status=random.choice(property_statuses),
                has_caveat=random.choice([True, False]),

                annual_rate=round(rate, 2),
                registration_date=reg_date
            )

            self.stdout.write(self.style.SUCCESS(f"✅ Parcel {parcel_no} created"))

        self.stdout.write(self.style.SUCCESS("🎯 Done! 25 Wajir properties seeded successfully"))
