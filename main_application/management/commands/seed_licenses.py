from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.utils import timezone
from datetime import timedelta, datetime
import random

from main_application.models import Business, License, LicenseType

User = get_user_model()

class Command(BaseCommand):
    help = "Seed realistic Wajir County business licenses"

    def handle(self, *args, **kwargs):
        businesses = list(Business.objects.all()[:50])
        license_types = list(LicenseType.objects.all())
        admin = User.objects.filter(is_superuser=True).first()

        if not businesses or not license_types:
            self.stdout.write(self.style.ERROR("Ensure Businesses & LicenseTypes exist first!"))
            return
        
        statuses = [
            "submitted", "under_review", "approved",
            "issued", "active"
        ]

        count = 0

        for biz in businesses:
            ltype = random.choice(license_types)

            # dates
            application_date = timezone.now().date() - timedelta(days=random.randint(30, 365))
            approval_date = application_date + timedelta(days=random.randint(3, 20))
            issue_date = approval_date + timedelta(days=2)
            expiry_date = issue_date + timedelta(days=365)

            status = random.choice(statuses)

            # Generate License Number
            license_no = f"WJR-LIC-{issue_date.year}-{random.randint(10000,99999)}"

            License.objects.create(
                license_number=license_no,
                business=biz,
                license_type=ltype,

                application_date=application_date,
                approval_date=approval_date if status in ["approved", "issued", "active"] else None,
                issue_date=issue_date if status in ["issued", "active"] else None,
                expiry_date=expiry_date if status == "active" else None,

                status=status,
                is_provisional=False,
                is_renewal=False,
                previous_license=None,

                reviewed_by=admin if status in ["under_review", "approved", "issued", "active"] else None,
                approved_by=admin if status in ["approved", "issued", "active"] else None,

                notes="Wajir County Business License",
                rejection_reason="" if status != "rejected" else "Non-compliance with county rules",

                created_by=admin
            )

            count += 1
            self.stdout.write(self.style.SUCCESS(f"✅ License Issued: {license_no} for {biz.business_name}"))

        self.stdout.write(self.style.SUCCESS(f"🎯 Done! Seeded {count} business licenses"))
