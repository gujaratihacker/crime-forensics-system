import os
import secrets

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
    
    # Database Settings
    DB_HOST = os.environ.get('DB_HOST', 'localhost')
    DB_USER = os.environ.get('DB_USER', 'root')
    DB_PASSWORD = os.environ.get('DB_PASSWORD', '')
    DB_NAME = os.environ.get('DB_NAME', 'crime_forensics_db')
    
    # Secure Evidence Vault Settings
    UPLOAD_FOLDER = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'uploads', 'evidence')
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50 MB limits
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'mp4', 'webm', 'wav', 'mp3', 'txt', 'zip'}
    
    # Session lifecycle
    SESSION_PERMANENT = False
    
    # Simulated Live Stream snapshot storage
    LIVE_SNAPSHOTS_FOLDER = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'uploads', 'live_snapshots')
    
    # Missing Persons Photos Upload folder
    MISSING_PERSONS_UPLOAD_FOLDER = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'uploads', 'missing_persons')
    
    # Verification uploads folder
    VERIFICATION_UPLOAD_FOLDER = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'uploads', 'verification')
