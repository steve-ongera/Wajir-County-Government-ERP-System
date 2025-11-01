from django.core.management.base import BaseCommand
from datetime import date
from decimal import Decimal
from django.contrib.auth import get_user_model
from main_application.models import Property, PropertyValuation

User = get_user_model()

class Command(BaseCommand):
    help = "Seed Wajir County - Property Valuation Records"

    def handle(self, *args, **kwargs):
        created_by_user = User.objects.filter(username__icontains="admin").first()
        if not created_by_user:
            created_by_user = User.objects.first()

        valuations = [
            (1, "2024-01-15", "Market Comparison", 3200000, 250000, "Ahmed Abdullahi & Associates"),
            (2, "2024-02-10", "Income Capitalization", 5100000, 800000, "Wajir Real Estate Valuers Ltd"),
            (3, "2024-03-05", "Cost Approach", 2750000, 500000, "North Eastern Valuation Bureau"),
            (4, "2024-01-28", "Market Comparison", 4500000, 750000, "Northern Frontier Valuers"),
            (5, "2024-04-12", "Market Comparison", 6100000, 1500000, "Kenya National Valuers - Wajir Branch"),
            (6, "2024-05-01", "Cost Approach", 3500000, 400000, "Jubba Valuers & Consultants"),
            (7, "2024-02-19", "Market Comparison", 1800000, 0, "Pastoralist Land Surveyors & Valuers"),
            (8, "2024-06-10", "Income Capitalization", 9000000, 2000000, "Frontier City Valuation Group"),
            (9, "2024-03-30", "Market Comparison", 4200000, 300000, "Wajir Land & Property Experts"),
            (10,"2024-07-15", "Cost Approach", 2500000, 200000, "Ahmed Abdullahi & Associates"),
            (11,"2024-04-02", "Market Comparison", 5200000, 1000000, "North Eastern Valuation Bureau"),
            (12,"2024-05-22", "Income Capitalization", 11000000, 3500000, "Kenya National Valuers - Wajir Branch"),
            (13,"2024-06-14", "Market Comparison", 2900000, 0, "Wajir Real Estate Valuers Ltd"),
            (14,"2024-01-07", "Cost Approach", 3300000, 300000, "Frontier City Valuation Group"),
            (15,"2024-02-25", "Market Comparison", 4000000, 500000, "Jubba Valuers & Consultants"),
            (16,"2024-03-11", "Market Comparison", 2100000, 0, "Pastoralist Land Surveyors & Valuers"),
            (17,"2024-05-09", "Income Capitalization", 8700000, 1800000, "Northern Frontier Valuers"),
            (18,"2024-06-29", "Market Comparison", 2600000, 150000, "Ahmed Abdullahi & Associates"),
            (19,"2024-07-04", "Cost Approach", 3800000, 500000, "Kenya National Valuers - Wajir Branch"),
            (20,"2024-08-01", "Market Comparison", 4600000, 700000, "Wajir Land & Property Experts"),
        ]

        for item in valuations:
            prop_id, v_date, method, land_val, impr_val, valuer = item
            
            try:
                property_obj = Property.objects.get(id=prop_id)
            except Property.DoesNotExist:
                self.stdout.write(self.style.WARNING(f"Skipping valuation — Property ID {prop_id} does not exist"))
                continue
            
            total = Decimal(land_val) + Decimal(impr_val)

            PropertyValuation.objects.create(
                property=property_obj,
                valuation_date=date.fromisoformat(v_date),
                valuation_method=method,
                land_value=Decimal(land_val),
                improvement_value=Decimal(impr_val),
                total_value=total,
                valuer_name=valuer,
                created_by=created_by_user,
                is_current=True,
            )

            self.stdout.write(self.style.SUCCESS(f"✔ Added valuation for parcel {property_obj.parcel_number}"))

        self.stdout.write(self.style.SUCCESS("🎯 Property Valuation seeding completed successfully."))
