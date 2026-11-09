import os
import sys

from app import app, db
from models import User

def init_database():
    """Initialize database with admin user"""
    with app.app_context():
        try:
            db.create_all()
            print("✓ Database tables created successfully")
        except Exception as e:
            print(f"✗ Error creating database tables: {e}")
            return False
        
        admin_username = os.getenv('DEFAULT_ADMIN_USERNAME', 'admin')
        environment = os.getenv('ENVIRONMENT', 'development').lower()
        admin_password = os.getenv('DEFAULT_ADMIN_PASSWORD')
        if not admin_password and environment != 'production':
            admin_password = 'password'

        try:
            existing_admin = User.query.filter_by(username=admin_username).first()
            if not existing_admin and admin_password:
                admin = User(username=admin_username, role='admin')
                admin.set_password(admin_password)
                db.session.add(admin)
                db.session.commit()
                print(f"✓ Default admin user created: {admin_username}")
            elif existing_admin:
                print(f"✓ Admin user already exists: {admin_username}")
            else:
                print(f"⚠ DEFAULT_ADMIN_PASSWORD not set. Cannot create/update admin user.")
        except Exception as e:
            print(f"✗ Error setting up admin user: {e}")
            db.session.rollback()
            return False
        
        return True

if __name__ == "__main__":
    success = init_database()
    sys.exit(0 if success else 1)