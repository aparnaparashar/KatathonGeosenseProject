"""
GeoSense Flask Application
Main entry point for the backend API
"""

from flask import Flask, jsonify
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from config import Config
from database.db import init_db, db

def create_app():
    """Create and configure Flask application"""
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # Enable CORS
    CORS(app, resources={r"/api/*": {"origins": "*"}})
    
    # Initialize extensions
    bcrypt = Bcrypt(app)
    jwt = JWTManager(app)
    
    # Initialize database
    init_db(app)
    
    # Register blueprints
    from routes.insights import insights_bp
    from routes.reports import reports_bp
    from routes.routing import routing_bp
    from routes.auth import auth_bp  # Add authentication routes
    
    app.register_blueprint(insights_bp, url_prefix='/api/insights')
    app.register_blueprint(reports_bp, url_prefix='/api/reports')
    app.register_blueprint(routing_bp, url_prefix='/api/routing')
    app.register_blueprint(auth_bp, url_prefix='/api/auth')  # Register auth routes
    
    @app.route('/api/health')
    def health():
        return {'status': 'healthy', 'service': 'GeoSense API'}
    
    # Test route for auth
    @app.route('/api/auth/test')
    def auth_test():
        return {'status': 'auth routes available', 'endpoints': ['/api/auth/login', '/api/auth/signup']}
    
    # Catch-all route to handle frontend routing
    @app.route('/', defaults={'path': ''})
    @app.route('/<path:path>')
    def catch_all(path):
        """
        Catch-all route to handle frontend routing
        Returns appropriate responses for different types of requests
        """
        # For API routes that don't exist, return 404
        if path.startswith('api/'):
            return jsonify({
                'success': False,
                'error': f'API endpoint not found: /{path}'
            }), 404
        
        # For frontend routes, return a message indicating they should be handled by React
        # In production, you would serve your React build files here
        frontend_routes = ['dashboard', 'signin', 'signup', 'profile', 'insights', 'smart-routes', 'pooling']
        
        if any(path.startswith(route) for route in frontend_routes) or path == '':
            return jsonify({
                'success': True,
                'message': 'Frontend route - should be handled by React app',
                'note': 'This is a backend API server. Frontend routes are handled by the React application.',
                'frontend_url': 'http://localhost:5173'  # Your Vite dev server
            }), 200
        
        # For any other unknown routes
        return jsonify({
            'success': False,
            'error': f'Route not found: /{path}',
            'available_routes': [
                '/api/health',
                '/api/auth/*',
                '/api/insights/*',
                '/api/reports/*',
                '/api/routing/*'
            ]
        }), 404
    
    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, host='0.0.0.0', port=5000)