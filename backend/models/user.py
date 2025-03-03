from datetime import datetime, timezone
from services.db_service import execute_query
from utils.security import hash_password, verify_password

class User:
    @staticmethod
    def create(username, email, password):
        """Create a new user"""
        hashed_password = hash_password(password)
        
        query = """
            INSERT INTO users (username, email, password_hash)
            VALUES (%(username)s, %(email)s, %(password_hash)s)
            RETURNING id, username, email, created_at
        """
        params = {
            'username': username,
            'email': email,
            'password_hash': hashed_password
        }
        
        result = execute_query(query, params)
        return result[0] if result else None

    @staticmethod
    def find_by_username(username):
        """Find a user by username"""
        query = """
            SELECT id, username, email, password_hash, created_at, last_login, is_active
            FROM users
            WHERE username = %(username)s
        """
        result = execute_query(query, {'username': username})
        return result[0] if result else None

    @staticmethod
    def find_by_email(email):
        """Find a user by email"""
        query = """
            SELECT id, username, email, password_hash, created_at, last_login, is_active
            FROM users
            WHERE email = %(email)s
        """
        result = execute_query(query, {'email': email})
        return result[0] if result else None
    
    @staticmethod
    def authenticate(username_or_email, password):
        """Authenticate a user by username/email and password"""
        # Try to find by username first
        user = User.find_by_username(username_or_email)
        
        # If not found, try by email
        if not user:
            user = User.find_by_email(username_or_email)
            
        # If still not found or password doesn't match, return None
        if not user or not verify_password(password, user['password_hash']):
            return None
            
        # Update last login timestamp
        update_query = """
            UPDATE users
            SET last_login = %(last_login)s
            WHERE id = %(id)s
        """
        execute_query(
            update_query, 
            {'id': user['id'], 'last_login': datetime.now(timezone.utc)},
            fetch=False
        )
        
        return user