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
        admin_password = os.getenv('DEFAULT_ADMIN_PASSWORD', 'admin')
        
        try:
            existing_admin = User.query.filter_by(username=admin_username).first()
            if not existing_admin:
                admin = User(username=admin_username, role='admin')
                admin.set_password(admin_password)
                db.session.add(admin)
                db.session.commit()
                print(f"✓ Default admin user created: {admin_username}")
            else:
                if not existing_admin.check_password(admin_password):
                    existing_admin.set_password(admin_password)
                    db.session.commit()
                    print(f"✓ Admin password updated for: {admin_username}")
                else:
                    print(f"✓ Admin user already exists: {admin_username}")
        except Exception as e:
            print(f"✗ Error setting up admin user: {e}")
            db.session.rollback()
            return False
        
        return True

if __name__ == "__main__":
    success = init_database()
    sys.exit(0 if success else 1)