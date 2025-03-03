mkdir -p backend/{config,models,routes,services,utils,templates} && \
echo "
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT TRUE
);

CREATE TABLE sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    session_token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(45),
    user_agent TEXT
);

CREATE INDEX idx_sessions_token ON sessions(session_token);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
" > backend/db_schema.sql && \
cat > backend/config/__init__.py << 'EOF'
# Config package
EOF
cat > backend/config/settings.py << 'EOF'
import os
from datetime import timedelta
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Database configuration
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "mydb")
DB_USER = os.getenv("DB_USER", "myuser")
DB_PASSWORD = os.getenv("DB_PASSWORD", "mypassword")

# Security
SECRET_KEY = os.getenv("SECRET_KEY", "generate-a-secure-secret-key-in-production")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "generate-another-secure-key-in-production")
JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
SESSION_TYPE = "filesystem"
SESSION_PERMANENT = False
SESSION_USE_SIGNER = True
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
PERMANENT_SESSION_LIFETIME = timedelta(hours=1)

# API settings
API_PREFIX = "/api/v1"
EOF
cat > backend/models/__init__.py << 'EOF'
# Models package
EOF
cat > backend/models/user.py << 'EOF'
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
EOF
cat > backend/models/session.py << 'EOF'
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
EOF
cat > backend/routes/__init__.py << 'EOF'
# Routes package
EOF
cat > backend/routes/auth.py << 'EOF'
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
EOF
cat > backend/services/__init__.py << 'EOF'
# Services package
EOF
cat > backend/services/db_service.py << 'EOF'
import psycopg2
from contextlib import contextmanager
from psycopg2.extras import RealDictCursor
from config.settings import DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD

def get_connection_string():
    return f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

@contextmanager
def get_db_connection():
    """Context manager for database connections"""
    conn = psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD
    )
    try:
        yield conn
    finally:
        conn.close()

@contextmanager
def get_db_cursor(commit=False):
    """Context manager for database cursors"""
    with get_db_connection() as conn:
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        try:
            yield cursor
            if commit:
                conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cursor.close()

def execute_query(query, params=None, fetch=True, commit=True):
    """Execute a database query and return results if needed"""
    with get_db_cursor(commit=commit) as cursor:
        cursor.execute(query, params or {})
        if fetch:
            return cursor.fetchall()
        return None
EOF
cat > backend/services/auth_service.py << 'EOF'
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
EOF
cat > backend/utils/__init__.py << 'EOF'
# Utils package
EOF
cat > backend/utils/security.py << 'EOF'
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
EOF
cat > backend/app.py << 'EOF'
from flask import Flask
from flask_session import Session
from routes.auth import auth_bp
from config.settings import SECRET_KEY, SESSION_TYPE, SESSION_PERMANENT, SESSION_USE_SIGNER
from config.settings import SESSION_COOKIE_SECURE, SESSION_COOKIE_HTTPONLY, SESSION_COOKIE_SAMESITE
from config.settings import PERMANENT_SESSION_LIFETIME

def create_app():
    app = Flask(__name__)
    
    # Configure the Flask app
    app.config['SECRET_KEY'] = SECRET_KEY
    app.config['SESSION_TYPE'] = SESSION_TYPE
    app.config['SESSION_PERMANENT'] = SESSION_PERMANENT
    app.config['SESSION_USE_SIGNER'] = SESSION_USE_SIGNER
    app.config['SESSION_COOKIE_SECURE'] = SESSION_COOKIE_SECURE
    app.config['SESSION_COOKIE_HTTPONLY'] = SESSION_COOKIE_HTTPONLY
    app.config['SESSION_COOKIE_SAMESITE'] = SESSION_COOKIE_SAMESITE
    app.config['PERMANENT_SESSION_LIFETIME'] = PERMANENT_SESSION_LIFETIME
    
    # Initialize Flask-Session
    Session(app)
    
    # Register blueprints
    app.register_blueprint(auth_bp)
    
    @app.route('/api/v1/health', methods=['GET'])
    def health_check():
        return {'status': 'healthy'}
    
    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)
EOF
cat > backend/requirements.txt << 'EOF'
flask==2.3.3
flask-restful==0.3.10
psycopg2-binary==2.9.7
passlib==1.7.4
pyjwt==2.8.0
python-dotenv==1.0.0
gunicorn==21.2.0
Flask-Session==0.5.0
cryptography==41.0.3
EOF
cat > backend/deploy.yml << 'EOF'
---
- name: Deploy Backend API
  hosts: app_servers
  become: true
  vars:
    app_name: backend-api
    app_directory: /opt/{{ app_name }}
    app_user: appuser
    app_group: appgroup
    venv_path: "{{ app_directory }}/venv"
    db_host: "{{ lookup('env', 'DB_HOST') | default('localhost', true) }}"
    db_port: "{{ lookup('env', 'DB_PORT') | default('5432', true) }}"
    db_name: "{{ lookup('env', 'DB_NAME') | default('mydb', true) }}"
    db_user: "{{ lookup('env', 'DB_USER') | default('myuser', true) }}"
    db_password: "{{ lookup('env', 'DB_PASSWORD') | default('mypassword', true) }}"
    secret_key: "{{ lookup('env', 'SECRET_KEY') | default(lookup('password', '/dev/null chars=ascii_letters,digits length=50'), true) }}"
    jwt_secret_key: "{{ lookup('env', 'JWT_SECRET_KEY') | default(lookup('password', '/dev/null chars=ascii_letters,digits length=50'), true) }}"

  tasks:
    - name: Install system dependencies
      apt:
        name:
          - python3
          - python3-pip
          - python3-venv
          - postgresql-client
          - nginx
        state: present
        update_cache: yes

    - name: Create app user
      user:
        name: "{{ app_user }}"
        group: "{{ app_group }}"
        system: yes
        create_home: no
        shell: /bin/false
      register: app_user_created

    - name: Create app group if not exists
      group:
        name: "{{ app_group }}"
        system: yes
        state: present
      when: app_user_created is failed

    - name: Create app directory
      file:
        path: "{{ app_directory }}"
        state: directory
        owner: "{{ app_user }}"
        group: "{{ app_group }}"
        mode: '0755'

    - name: Clone or update application repository
      git:
        repo: "{{ git_repo }}"
        dest: "{{ app_directory }}/src"
        version: "{{ git_branch | default('main') }}"
        update: yes
      become_user: "{{ app_user }}"
      register: git_clone

    - name: Create Python virtual environment
      command:
        cmd: python3 -m venv "{{ venv_path }}"
        creates: "{{ venv_path }}/bin/activate"
      become_user: "{{ app_user }}"

    - name: Install Python requirements
      pip:
        requirements: "{{ app_directory }}/src/requirements.txt"
        virtualenv: "{{ venv_path }}"
      become_user: "{{ app_user }}"
      register: pip_install

    - name: Create environment file
      template:
        src: templates/.env.j2
        dest: "{{ app_directory }}/src/.env"
        owner: "{{ app_user }}"
        group: "{{ app_group }}"
        mode: '0600'
      notify: Restart Gunicorn

    - name: Create Gunicorn systemd service
      template:
        src: templates/gunicorn.service.j2
        dest: /etc/systemd/system/{{ app_name }}.service
        owner: root
        group: root
        mode: '0644'
      notify: Restart Gunicorn

    - name: Create Nginx configuration
      template:
        src: templates/nginx.conf.j2
        dest: /etc/nginx/sites-available/{{ app_name }}
        owner: root
        group: root
        mode: '0644'
      notify: Restart Nginx

    - name: Enable Nginx site
      file:
        src: /etc/nginx/sites-available/{{ app_name }}
        dest: /etc/nginx/sites-enabled/{{ app_name }}
        state: link
      notify: Restart Nginx

    - name: Start and enable services
      systemd:
        name: "{{ item }}"
        state: started
        enabled: yes
      loop:
        - "{{ app_name }}"
        - nginx

  handlers:
    - name: Restart Gunicorn
      systemd:
        name: "{{ app_name }}"
        state: restarted
        daemon_reload: yes

    - name: Restart Nginx
      systemd:
        name: nginx
        state: restarted
EOF
cat > backend/templates/.env.j2 << 'EOF'
# Database configuration
DB_HOST={{ db_host }}
DB_PORT={{ db_port }}
DB_NAME={{ db_name }}
DB_USER={{ db_user }}
DB_PASSWORD={{ db_password }}

# Security
SECRET_KEY={{ secret_key }}
JWT_SECRET_KEY={{ jwt_secret_key }}
EOF
cat > backend/templates/gunicorn.service.j2 << 'EOF'
[Unit]
Description={{ app_name }} service
After=network.target

[Service]
User={{ app_user }}
Group={{ app_group }}
WorkingDirectory={{ app_directory }}/src
ExecStart={{ venv_path }}/bin/gunicorn --workers 3 --bind unix:{{ app_directory }}/{{ app_name }}.sock -m 007 "app:create_app()"
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF
cat > backend/templates/nginx.conf.j2 << 'EOF'
server {
    listen 80;
    server_name {{ server_name | default('_') }};

    location /api {
        include proxy_params;
        proxy_pass http://unix:{{ app_directory }}/{{ app_name }}.sock;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Add SSL configuration for production
    # listen 443 ssl;
    # ssl_certificate /path/to/cert.pem;
    # ssl_certificate_key /path/to/key.pem;
    # ssl_protocols TLSv1.2 TLSv1.3;
    # ssl_prefer_server_ciphers on;
}
EOF
cat > backend/inventory.ini << 'EOF'
[app_servers]
app1 ansible_host=your_server_ip ansible_user=ubuntu ansible_ssh_private_key_file=~/.ssh/id_rsa

[db_servers]
db1 ansible_host=your_db_server_ip ansible_user=ubuntu ansible_ssh_private_key_file=~/.ssh/id_rsa

[all:vars]
server_name=your-domain.com
git_repo=https://github.com/yourusername/backend-repo.git
git_branch=main
EOF
cat > backend/.env << 'EOF'
# Database configuration
DB_HOST=localhost
DB_PORT=5432
DB_NAME=mydb
DB_USER=myuser
DB_PASSWORD=mypassword

# Security - CHANGE THESE IN PRODUCTION
SECRET_KEY=development-secret-key
JWT_SECRET_KEY=development-jwt-secret-key
EOF
echo "All files created successfully in the backend folder"