import os

from app import app, db
from models import User

with app.app_context():
    db.create_all()
    admin_username = os.getenv('DEFAULT_ADMIN_USERNAME', 'admin')
    admin_password = os.getenv('DEFAULT_ADMIN_PASSWORD', 'admin')
    existing_admin = User.query.filter_by(username=admin_username).first()
    if not existing_admin:
        admin = User(username=admin_username, role='admin')
        admin.set_password(admin_password)
        db.session.add(admin)
        db.session.commit()
        print("Default admin user created.")
    elif not existing_admin.check_password(admin_password):
        existing_admin.set_password(admin_password)
        db.session.commit()
        print("Default admin password updated to match environment settings.")