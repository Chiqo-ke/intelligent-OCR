from flask import Blueprint, request, jsonify, session
from services.auth_service import AuthService

auth_bp = Blueprint('auth', __name__, url_prefix='/api/v1/auth')

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    
    # Validate required fields
    required_fields = ['username', 'email', 'password']
    if not all(field in data for field in required_fields):
        return jsonify({'success': False, 'message': 'Missing required fields'}), 400
    
    # Validate username and password format
    username = data['username']
    password = data['password']
    
    if len(username) < 3 or len(username) > 30:
        return jsonify({'success': False, 'message': 'Username must be between 3 and 30 characters'}), 400
    
    if len(password) < 8:
        return jsonify({'success': False, 'message': 'Password must be at least 8 characters'}), 400
    
    # Register user
    result = AuthService.register_user(
        username=data['username'],
        email=data['email'],
        password=data['password']
    )
    
    if not result['success']:
        return jsonify(result), 400
    
    return jsonify(result), 201

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    
    # Validate required fields
    if not ('username' in data or 'email' in data) or 'password' not in data:
        return jsonify({'success': False, 'message': 'Missing required fields'}), 400
    
    # Get username/email and password
    username_or_email = data.get('username', data.get('email'))
    password = data['password']
    
    # Get client information for session
    ip_address = request.remote_addr
    user_agent = request.headers.get('User-Agent')
    
    # Login user
    result = AuthService.login_user(
        username_or_email=username_or_email,
        password=password,
        ip_address=ip_address,
        user_agent=user_agent
    )
    
    if not result['success']:
        return jsonify(result), 401
    
    # Store session token in cookie
    session['token'] = result['session']['token']
    
    return jsonify(result), 200

@auth_bp.route('/logout', methods=['POST'])
def logout():
    # Get session token from cookie
    token = session.get('token')
    
    if not token:
        return jsonify({'success': False, 'message': 'Not logged in'}), 401
    
    # Logout user
    result = AuthService.logout_user(token)
    
    # Clear session
    session.clear()
    
    return jsonify(result), 200

@auth_bp.route('/session', methods=['GET'])
def validate_session():
    # Get session token from cookie
    token = session.get('token')
    
    if not token:
        return jsonify({'success': False, 'message': 'Not logged in'}), 401
    
    # Validate session
    result = AuthService.validate_session(token)
    
    if not result['success']:
        # Clear invalid session
        session.clear()
        return jsonify(result), 401
    
    return jsonify(result), 200
