from models.user import User
from models.session import Session
from utils.security import create_access_token, create_refresh_token

class AuthService:
    @staticmethod
    def register_user(username, email, password):
        """Register a new user"""
        # Check if username or email already exists
        if User.find_by_username(username):
            return {'success': False, 'message': 'Username already exists'}
        
        if User.find_by_email(email):
            return {'success': False, 'message': 'Email already exists'}
        
        # Create new user
        user = User.create(username, email, password)
        if not user:
            return {'success': False, 'message': 'Failed to create user'}
        
        # Return user data without sensitive information
        return {
            'success': True,
            'user': {
                'id': user['id'],
                'username': user['username'],
                'email': user['email'],
                'created_at': user['created_at']
            }
        }
    
    @staticmethod
    def login_user(username_or_email, password, ip_address=None, user_agent=None):
        """Authenticate a user and create session"""
        user = User.authenticate(username_or_email, password)
        if not user:
            return {'success': False, 'message': 'Invalid credentials'}
        
        # Create session
        session = Session.create(user['id'], ip_address, user_agent)
        if not session:
            return {'success': False, 'message': 'Failed to create session'}
        
        # Create JWT tokens for API authentication
        access_token = create_access_token(user['id'])
        refresh_token = create_refresh_token(user['id'])
        
        return {
            'success': True,
            'user': {
                'id': user['id'],
                'username': user['username'],
                'email': user['email']
            },
            'session': {
                'token': session['session_token'],
                'expires_at': session['expires_at']
            },
            'tokens': {
                'access_token': access_token,
                'refresh_token': refresh_token
            }
        }
    
    @staticmethod
    def logout_user(token):
        """Logout a user by invalidating their session"""
        Session.invalidate(token)
        return {'success': True, 'message': 'Logged out successfully'}
    
    @staticmethod
    def validate_session(token):
        """Validate a session token"""
        session = Session.validate(token)
        if not session:
            return {'success': False, 'message': 'Invalid or expired session'}
        
        return {
            'success': True,
            'user': {
                'id': session['user_id'],
                'username': session['username'],
                'email': session['email']
            }
        }