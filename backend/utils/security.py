import secrets
import string
from datetime import datetime, timezone, timedelta
import jwt
from passlib.hash import pbkdf2_sha256
from config.settings import JWT_SECRET_KEY, JWT_ACCESS_TOKEN_EXPIRES, JWT_REFRESH_TOKEN_EXPIRES

def hash_password(password):
    """Hash a password using PBKDF2 with SHA-256"""
    return pbkdf2_sha256.hash(password)

def verify_password(password, password_hash):
    """Verify a password against its hash"""
    return pbkdf2_sha256.verify(password, password_hash)

def generate_token(length=32):
    """Generate a secure random token"""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def create_access_token(user_id):
    """Create a JWT access token for authentication"""
    payload = {
        'sub': user_id,
        'iat': datetime.now(timezone.utc),
        'exp': datetime.now(timezone.utc) + JWT_ACCESS_TOKEN_EXPIRES,
        'type': 'access'
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm='HS256')

def create_refresh_token(user_id):
    """Create a JWT refresh token for refreshing access tokens"""
    payload = {
        'sub': user_id,
        'iat': datetime.now(timezone.utc),
        'exp': datetime.now(timezone.utc) + JWT_REFRESH_TOKEN_EXPIRES,
        'type': 'refresh'
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm='HS256')

def decode_token(token):
    """Decode and validate a JWT token"""
    try:
        return jwt.decode(token, JWT_SECRET_KEY, algorithms=['HS256'])
    except jwt.PyJWTError:
        return None