from app import create_app, db
from app.admin import admin  # Import the admin instance

app = create_app()
admin.init_app(app)  # Initialize admin with the app

if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Ensure tables are created
    app.run(debug=True)
