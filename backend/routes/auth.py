"""
Authentication API endpoints - SIMPLIFIED
Works without MongoDB
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
import datetime
import hashlib

auth_bp = Blueprint('auth', __name__)

# Simple in-memory storage for demo
users_db = {}

@auth_bp.route('/login', methods=['POST'])
def login():
    """
    User login endpoint - SIMPLIFIED
    """
    try:
        data = request.get_json()
        
        if not data or not data.get('email') or not data.get('password'):
            return jsonify({
                'success': False,
                'error': 'Email and password are required'
            }), 400
        
        email = data['email']
        password = data['password']
        
        print(f"Login attempt for: {email}")  # Debug
        
        # For demo - accept any login
        if email and password:
            # Create access token
            access_token = create_access_token(
                identity=email,
                expires_delta=datetime.timedelta(days=7)
            )
            
            # Get user name from stored data or use email prefix
            user_name = users_db.get(email, {}).get('name', email.split('@')[0])
            
            print(f"Login successful for: {email}")  # Debug
            
            return jsonify({
                'success': True,
                'token': access_token,
                'user': {
                    'email': email,
                    'name': user_name
                }
            }), 200
        else:
            return jsonify({
                'success': False,
                'error': 'Invalid email or password'
            }), 401
        
    except Exception as e:
        print(f"Login error: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Login failed: {str(e)}'
        }), 500

@auth_bp.route('/signup', methods=['POST'])
def signup():
    """
    User registration endpoint - SIMPLIFIED
    """
    try:
        data = request.get_json()
        
        if not data or not data.get('email') or not data.get('password') or not data.get('name'):
            return jsonify({
                'success': False,
                'error': 'Name, email, and password are required'
            }), 400
        
        name = data['name']
        email = data['email']
        password = data['password']
        
        print(f"Signup attempt for: {email}")  # Debug
        
        # For demo - accept any registration
        # Store user in memory
        users_db[email] = {
            'name': name,
            'email': email,
            'password': password  # In production, hash this!
        }
        
        # Create access token
        access_token = create_access_token(
            identity=email,
            expires_delta=datetime.timedelta(days=7)
        )
        
        print(f"Signup successful for: {email}")  # Debug
        print(f"Total users: {len(users_db)}")  # Debug
        
        return jsonify({
            'success': True,
            'token': access_token,
            'user': {
                'email': email,
                'name': name
            }
        }), 201
        
    except Exception as e:
        print(f"Signup error: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Signup failed: {str(e)}'
        }), 500

@auth_bp.route('/me', methods=['GET'])
@jwt_required()
def get_current_user():
    """
    Get current user profile - SIMPLIFIED
    """
    try:
        current_user_email = get_jwt_identity()
        
        # Get user data from memory
        user_data = users_db.get(current_user_email, {})
        user_name = user_data.get('name', current_user_email.split('@')[0])
        
        return jsonify({
            'success': True,
            'user': {
                'email': current_user_email,
                'name': user_name
            }
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Failed to get user profile: {str(e)}'
        }), 500

@auth_bp.route('/test', methods=['GET'])
def test_auth():
    """Test endpoint"""
    return jsonify({
        'success': True,
        'message': 'Authentication service is operational',
        'database': 'in-memory (demo mode)',
        'total_users': len(users_db),
        'endpoints': [
            'POST /api/auth/login',
            'POST /api/auth/signup',
            'GET /api/auth/me'
        ]
    }), 200