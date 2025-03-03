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
    app.run(debug=True, port=8000)

