"""
================================================================================
Intelligent Login Attempt Monitoring and Intrusion Detection System (IDS)
Configuration Module - System Parameters & Security Policies
================================================================================
"""

import os
import secrets

class Config:
    """Base application configuration with default security settings."""
    
    # Fundamental Flask Application Settings
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
    DEBUG = False
    TESTING = False
    
    # Application Paths
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    LOGS_DIR = os.path.join(BASE_DIR, 'logs')
    REPORTS_DIR = os.path.join(BASE_DIR, 'reports')
    
    # Database Configuration (XAMPP MySQL Primary / SQLite Fallback)
    DB_ENGINE = os.environ.get('DB_ENGINE', 'mysql')
    SQLITE_DB_PATH = os.path.join(BASE_DIR, 'ids_cyber_security.db')
    
    MYSQL_HOST = os.environ.get('MYSQL_HOST', '127.0.0.1')
    MYSQL_PORT = int(os.environ.get('MYSQL_PORT', 3306))
    MYSQL_USER = os.environ.get('MYSQL_USER', 'root')
    MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD', '')
    MYSQL_DB = os.environ.get('MYSQL_DB', 'cyber_ids_db')
    
    # Security Policies & Thresholds
    MAX_FAILED_ATTEMPTS = 5         # Auto-lock after N failed logins
    ACCOUNT_LOCK_MINUTES = 15       # Lockout duration in minutes
    OTP_EXPIRY_MINUTES = 10         # OTP validity duration
    RESET_LINK_EXPIRY_MINUTES = 30  # Password reset link validity
    
    # AI Threat & Risk Engine Parameters
    AI_RISK_THRESHOLD_SAFE = 20.0
    AI_RISK_THRESHOLD_LOW = 40.0
    AI_RISK_THRESHOLD_MEDIUM = 65.0
    AI_RISK_THRESHOLD_HIGH = 85.0
    
    # MFA & Step-Up Security Threshold
    STEP_UP_MFA_RISK_TRIGGER = 65.0  # Trigger MFA step-up when risk >= Medium/High
    
    # Flask Session & Cookie Security
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = 3600
    
    # System OTP & Email Gateway Settings
    SENDER_EMAIL = 'dhaduksanketkumar10@gmail.com'
    ALERT_EMAIL_ENABLED = True
    SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
    SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
    SMTP_USERNAME = os.environ.get('SMTP_USERNAME', 'dhaduksanketkumar10@gmail.com')
    SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', '')
    
    @classmethod
    def init_app(cls, app):
        """Ensure necessary runtime directories exist."""
        os.makedirs(cls.LOGS_DIR, exist_ok=True)
        os.makedirs(cls.REPORTS_DIR, exist_ok=True)

class DevelopmentConfig(Config):
    """Development environment configuration with verbose logging."""
    DEBUG = True

class ProductionConfig(Config):
    """Production environment configuration with hardened settings."""
    DEBUG = False
    SESSION_COOKIE_SECURE = True

# Dictionary mapper for environment setups
config_by_name = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
