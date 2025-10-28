# Wajir County Government ERP System

A comprehensive Enterprise Resource Planning (ERP) system built for Wajir County Government to digitize and streamline county operations.

## 🚀 Features

### Core Modules

#### 1. **Revenue Management**
- Revenue stream configuration
- Bill generation and management
- Payment processing (M-Pesa, Bank, Cash, Airtel Money)
- Charge rates and penalty rules
- Revenue budgets and targets
- Payment reversals and audit trails

#### 2. **Citizen Management**
- Unified citizen/business registry
- Individual and business entity profiles
- Document management
- Portal access for citizens
- Geographic location tracking

#### 3. **Hospital Management Information System (HMIS)**
- Patient registration and management
- Triage and vitals recording
- Visit/encounter management
- Admissions (IPD) and discharges
- Laboratory tests and results
- Imaging/Radiology services
- Prescriptions and pharmacy
- Morgue management
- Multi-facility support (Level 1-5)

#### 4. **Human Resource Management**
- Staff registration and profiles
- Biometric attendance tracking
- Leave management (Annual, Sick, Maternity, etc.)
- Staff transfers and postings
- Performance reviews and appraisals
- Training and development programs
- Disciplinary case management
- Document management (certificates, contracts)

#### 5. **Fleet Management**
- Vehicle and machinery registration
- Fuel card management
- Fuel, oil & lubricant tracking
- Vehicle maintenance scheduling
- Trip/work ticket management
- GPS tracking integration
- Mileage monitoring

#### 6. **Asset Management**
- Movable and immovable asset tracking
- Asset categorization with depreciation
- Asset transfers between departments
- Maintenance records
- Asset disposal management
- Barcode/QR code support

#### 7. **Stores & Inventory Management**
- Multiple store/warehouse support
- Item categorization (consumable/non-consumable)
- Stock level tracking
- Goods Receipt Notes (GRN)
- Store requisitions and issues
- Reorder level alerts

#### 8. **Facilities Management**
- Markets and market stalls
- County housing units
- Stadia and sports facilities
- Public toilets
- Facility bookings
- Tenancy management
- Rental collection

#### 9. **Business Licensing & Permits**
- Business registration
- License application and approval workflow
- Multiple license types (SBP, Food Handler, etc.)
- Document requirements checklist
- License renewal management
- Inspection scheduling

#### 10. **Land & Property Management**
- Property/parcel registration
- Property valuation records
- Ownership history tracking
- Property subdivision and amalgamation
- Caveat management
- Land rates billing

#### 11. **Physical Planning & Development**
- Building plan approval applications
- Change of use applications
- Development control
- Site visit scheduling
- Approval workflow

#### 12. **Parking Management**
- Parking zones configuration
- Vehicle registration
- SACCO management
- Parking fee collection
- Vehicle clamping and towing records

#### 13. **Outdoor Advertising**
- Billboard registration and licensing
- Signage and branding permits
- Size-based charging
- Location tracking

#### 14. **Fines & Penalties**
- Fine categorization
- Fine issuance and tracking
- Payment recording
- Fine waivers

#### 15. **Case Management**
- Legal and administrative cases
- Case document management
- Hearing scheduling
- Case resolution tracking

#### 16. **Electronic Records Management**
- Document categorization
- Document retention policies
- Access control and logging
- Full-text search

#### 17. **Audit & Compliance**
- Comprehensive audit trails
- User activity logging
- Bank reconciliation
- System configuration management

#### 18. **Notifications**
- SMS notifications
- Email notifications
- In-system notifications
- Configurable notification triggers

## 🛠️ Technology Stack

- **Backend Framework:** Django 5.x
- **Database:** PostgreSQL with PostGIS extension
- **GIS Support:** Django GIS (GeoDjango)
- **Python Version:** 3.10+

## 📋 Prerequisites

- Python 3.10 or higher
- PostgreSQL 14+ with PostGIS extension
- pip (Python package manager)
- virtualenv (recommended)

## 🔧 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/your-org/wajir-erp.git
cd wajir-erp
```

### 2. Create Virtual Environment

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/Mac
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Database Setup

#### Install PostgreSQL and PostGIS

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install postgresql postgresql-contrib postgis
```

**Windows:**
Download and install from [PostgreSQL official website](https://www.postgresql.org/download/)

#### Create Database

```bash
# Access PostgreSQL
sudo -u postgres psql

# Create database and user
CREATE DATABASE wajir_erp;
CREATE USER wajir_user WITH PASSWORD 'your_secure_password';
ALTER ROLE wajir_user SET client_encoding TO 'utf8';
ALTER ROLE wajir_user SET default_transaction_isolation TO 'read committed';
ALTER ROLE wajir_user SET timezone TO 'Africa/Nairobi';
GRANT ALL PRIVILEGES ON DATABASE wajir_erp TO wajir_user;

# Enable PostGIS extension
\c wajir_erp
CREATE EXTENSION postgis;
\q
```

### 5. Configure Environment Variables

Create a `.env` file in the project root:

```env
# Database Configuration
DB_NAME=wajir_erp
DB_USER=wajir_user
DB_PASSWORD=your_secure_password
DB_HOST=localhost
DB_PORT=5432

# Django Settings
SECRET_KEY=your-secret-key-here
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1

# Email Configuration (Optional)
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=your-email@example.com
EMAIL_HOST_PASSWORD=your-email-password

# M-Pesa Configuration (Optional)
MPESA_CONSUMER_KEY=your_consumer_key
MPESA_CONSUMER_SECRET=your_consumer_secret
MPESA_SHORTCODE=your_shortcode
MPESA_PASSKEY=your_passkey
```

### 6. Run Migrations

```bash
python manage.py makemigrations
python manage.py migrate
```

### 7. Create Superuser

```bash
python manage.py createsuperuser
```

### 8. Seed Test Data

```bash
# Seed database with Wajir County sample data
python manage.py seed_data

# Clear and re-seed (caution: deletes existing data)
python manage.py seed_data --clear
```

### 9. Run Development Server

```bash
python manage.py runserver
```

Visit `http://127.0.0.1:8000/admin` to access the admin panel.

## 📊 Sample Data

The seed command creates realistic Wajir County data including:

- **1 County** (Wajir)
- **6 Sub-Counties** (Wajir North, East, South, West, Tarbaj, Eldas)
- **23 Wards** (Real ward names)
- **12 Departments** (Governor, Finance, Health, Education, etc.)
- **10 Staff Users** with Somali names
- **15 Citizens** (10 individuals + 5 businesses)
- **10 Revenue Streams** (SBP, Market Rent, Parking, etc.)
- **6 Health Facilities** (County hospital to dispensaries)
- **20 Patients**
- **5 Fleet Vehicles**
- **40 Market Stalls** across 2 markets
- **8 Fixed Assets**
- And much more...

## 🔐 Default Credentials

After seeding, you can login with any of these users (password: `password123`):

- ahmed.mohamed
- fatuma.hassan
- mohamed.abdi
- halima.ali
- ibrahim.yusuf

Or use your superuser credentials.

## 📁 Project Structure

```
wajir_erp/
├── main_application/          # Main application
│   ├── models.py              # All database models
│   ├── admin.py               # Django admin configuration
│   ├── views.py               # Application views
│   ├── management/
│   │   └── commands/
│   │       └── seed_data.py   # Data seeding script
│   └── migrations/            # Database migrations
├── wajir_erp/                 # Project settings
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
├── static/                    # Static files
├── media/                     # Uploaded files
├── requirements.txt           # Python dependencies
└── manage.py                  # Django management script
```

## 🗂️ Database Schema

### Key Model Relationships

- **Citizen** → One-to-Many → Bills, Payments, Properties, Licenses, Vehicles
- **User** → Many-to-Many → Roles → Permissions
- **Patient** → One-to-One → Citizen
- **Bill** → Many-to-One → Revenue Stream, Citizen
- **Payment** → Many-to-One → Bill, Citizen, Payment Method
- **Property** → Many-to-One → Citizen, Property Type, Land Use Type
- **License** → Many-to-One → Business, License Type
- **Asset** → Many-to-One → Department, Asset Category

## 🔌 API Integration

The system supports integration with:

- **M-Pesa** - Mobile money payment gateway
- **Airtel Money** - Mobile money payment gateway
- **Banks** - Direct bank integration
- **SMS Gateways** - For notifications
- **Email Services** - For notifications
- **GPS Tracking** - Fleet vehicle tracking

## 🚀 Deployment

### Production Checklist

1. Set `DEBUG=False` in settings
2. Configure `ALLOWED_HOSTS`
3. Use strong `SECRET_KEY`
4. Set up HTTPS/SSL
5. Configure production database
6. Set up static file serving (WhiteNoise/Nginx)
7. Configure media file storage (AWS S3/Local)
8. Set up backup strategy
9. Configure logging
10. Set up monitoring (Sentry, etc.)

### Recommended Stack

- **Web Server:** Nginx
- **Application Server:** Gunicorn
- **Process Manager:** Supervisor/Systemd
- **Database:** PostgreSQL with regular backups
- **Caching:** Redis
- **Static Files:** AWS S3 or CDN

## 📝 License

This project is proprietary software developed for Wajir County Government.

## 👥 Development Team

- **Project Lead:** [Your Name]
- **Backend Developer:** [Developer Name]
- **Frontend Developer:** [Developer Name]
- **Database Administrator:** [DBA Name]

## 📞 Support

For technical support and inquiries:
- **Email:** support@wajir.go.ke
- **Phone:** +254 XXX XXX XXX
- **Website:** https://wajir.go.ke

## 🤝 Contributing

This is a closed-source project. Internal contributions should follow:

1. Create feature branch from `develop`
2. Make changes and test thoroughly
3. Submit pull request with detailed description
4. Code review required before merge
5. Merge to `develop`, then to `main` for production

## 📚 Documentation

Detailed documentation available at:
- [User Manual](docs/user-manual.md)
- [API Documentation](docs/api-docs.md)
- [Administrator Guide](docs/admin-guide.md)
- [Developer Guide](docs/developer-guide.md)

## 🔄 Version History

### Version 1.0.0 (Current)
- Initial release
- All core modules implemented
- Full admin interface
- Sample data seeding
- Basic reporting

### Planned Features (v1.1.0)
- REST API endpoints
- Mobile application support
- Advanced analytics dashboard
- Bulk operations
- Export to Excel/PDF
- SMS integration
- Email integration
- Online payment gateway integration

## ⚠️ Known Issues

- Geographic coordinates need validation for actual property locations
- M-Pesa integration requires testing with live credentials
- Some reports need optimization for large datasets

## 🧪 Testing

```bash
# Run all tests
python manage.py test

# Run specific app tests
python manage.py test main_application

# Run with coverage
coverage run --source='.' manage.py test
coverage report
```

## 📈 Performance

- Database indexing on frequently queried fields
- Query optimization using select_related and prefetch_related
- Caching strategy for static data
- Pagination for large datasets

## 🔒 Security Features

- Role-based access control (RBAC)
- Audit trail for all critical operations
- Password encryption
- Session management
- CSRF protection
- SQL injection protection
- XSS protection

---

**Built by Steve for Wajir County Government**