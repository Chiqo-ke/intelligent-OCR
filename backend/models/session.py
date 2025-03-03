from datetime import datetime, timezone, timedelta
from services.db_service import execute_query
from utils.security import generate_token

class Session:
    @staticmethod
    def create(user_id, ip_address=None, user_agent=None, expires_in=timedelta(hours=24)):
        """Create a new session for a user"""
        token = generate_token(64)
        expires_at = datetime.now(timezone.utc) + expires_in
        
        query = """
            INSERT INTO sessions 
            (user_id, session_token, expires_at, ip_address, user_agent)
            VALUES (%(user_id)s, %(token)s, %(expires_at)s, %(ip_address)s, %(user_agent)s)
            RETURNING id, user_id, session_token, expires_at, created_at
        """
        params = {
            'user_id': user_id,
            'token': token,
            'expires_at': expires_at,
            'ip_address': ip_address,
            'user_agent': user_agent
        }
        
        result = execute_query(query, params)
        return result[0] if result else None

    @staticmethod
    def validate(token):
        """Validate a session token and return the associated user_id if valid"""
        query = """
            SELECT s.id, s.user_id, s.expires_at, u.username, u.email
            FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.session_token = %(token)s AND s.expires_at > %(now)s
        """
        now = datetime.now(timezone.utc)
        result = execute_query(query, {'token': token, 'now': now})
        
        return result[0] if result else None

    @staticmethod
    def invalidate(token):
        """Invalidate a session by deleting it"""
        query = """
            DELETE FROM sessions
            WHERE session_token = %(token)s
        """
        execute_query(query, {'token': token}, fetch=False)
        
    @staticmethod
    def clean_expired():
        """Remove all expired sessions"""
        query = """
            DELETE FROM sessions
            WHERE expires_at < %(now)s
        """
        execute_query(query, {'now': datetime.now(timezone.utc)}, fetch=False)