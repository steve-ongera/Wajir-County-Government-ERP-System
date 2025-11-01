from django.core.management.base import BaseCommand
from datetime import date
from decimal import Decimal
from django.contrib.auth import get_user_model
from main_application.models import DevelopmentApplication, Property, Citizen

User = get_user_model()

class Command(BaseCommand):
    help = "Seed Wajir County — Development & Building Applications"

    def handle(self, *args, **kwargs):
        admin_user = User.objects.filter(username__icontains="admin").first()
        if not admin_user:
            admin_user = User.objects.first()

        application_types = [
            ("building_plan", "New commercial building construction"),
            ("change_of_use", "Convert residential house to commercial shops"),
            ("subdivision", "Subdivision of agricultural land into plots"),
            ("amalgamation", "Merge adjacent parcels for mall construction"),
            ("extension", "Extension of existing residential building"),
        ]

        statuses = ["submitted", "under_review", "site_visit", "approved", "rejected", "conditional"]

        citizens = list(Citizen.objects.all())
        properties = list(Property.objects.all())

        if not citizens or not properties:
            self.stdout.write(self.style.ERROR("❌ No Citizens or Properties found. Seed those first."))
            return

        applications = [
            (1,  "2024-01-10", 3500000, "Commercial use - office block", 800.50),
            (2,  "2024-02-15", 1200000, "Convert home to retail shops", 300.75),
            (3,  "2024-03-01", 8500000, "Subdivide land for housing units", 0),
            (4,  "2024-03-20", 15000000, "Merge land for shopping mall", 1500.20),
            (5,  "2024-04-11", 2300000, "Build additional floor", 450.00),
            (6,  "2024-04-28", 4100000, "Residential apartments", 900.00),
            (7,  "2024-05-12", 500000, "Business kiosk upgrade", 50.00),
            (8,  "2024-05-29", 6200000, "Commercial godown", 1100.00),
            (9,  "2024-06-18", 9800000, "Subdivision for shops & offices", 0),
            (10, "2024-07-02", 1500000, "Home extension", 220.00),
            (11, "2024-07-21", 4700000, "Commercial plaza", 1300.50),
            (12, "2024-08-09", 7500000, "Educational facility", 900.80),
            (13, "2024-08-26", 1100000, "Convert storage to retail", 300.00),
            (14, "2024-09-12", 4300000, "Mosque extension", 500.00),
            (15, "2024-09-29", 2500000, "Clinic expansion", 350.00),
        ]

        for idx, (prop_id, app_date, cost, use, area) in enumerate(applications, start=1):
            if prop_id > len(properties):
                break

            property_obj = properties[prop_id - 1]
            citizen_obj = property_obj.owner  # linked owner

            app_type, desc = application_types[idx % len(application_types)]
            status = statuses[idx % len(statuses)]

            application_number = f"WJR-DEV-{1000 + idx}"

            DevelopmentApplication.objects.create(
                application_number=application_number,
                applicant=citizen_obj,
                property=property_obj,

                application_type=app_type,
                description=desc,
                proposed_use=use,
                estimated_cost=Decimal(cost),
                floor_area=Decimal(area) if area else None,

                application_date=date.fromisoformat(app_date),
                status=status,

                reviewed_by=admin_user if status != "submitted" else None,
                approved_by=admin_user if status in ["approved", "conditional"] else None,
                approval_date=date.fromisoformat(app_date) if status in ["approved", "conditional"] else None,

                conditions="Subject to site inspection and compliance approvals." if status == "conditional" else "",
                rejection_reason="Land use incompatible with zoning regulations." if status == "rejected" else "",
            )

            self.stdout.write(self.style.SUCCESS(f"✔ Added development application {application_number}"))

        self.stdout.write(self.style.SUCCESS("🎯 Development Application seeding completed!"))
