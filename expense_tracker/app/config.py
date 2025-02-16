from datetime import timedelta


class Config:
    # SQLALCHEMY_DATABASE_URI = 'postgresql://username:password@localhost:5432/yourdatabase'
    # SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_DATABASE_URI = 'sqlite:///expenses.db'
    JWT_SECRET_KEY = 'supersecretkey'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(days=1)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=7)
    MAIL_SERVER = 'smtp.example.com'  # Update with your mail server details
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'noshin@co.design'
    MAIL_PASSWORD = 'zrwyengrbaqhtuth'
    MAIL_DEFAULT_SENDER = 'noshin@co.design'  # Default sender
