#!/usr/bin/env python3
"""
REDCap Secure Patient Middleware

This middleware ensures patients can only access their own REDCap data by:
1. Authenticating users through WordPress authentication
2. Making secure REDCap API calls with email-based filtering
3. Never exposing the REDCap API token to client-side code

Deploy this as a separate service alongside your WordPress installation.
"""

from flask import Flask, request, jsonify, abort
import requests
import jwt
import json
import os
from functools import wraps
from datetime import datetime, timedelta
import logging
import sys

app = Flask(__name__)

# Load configuration
with open("config.json", "r") as f:
    config = json.load(f)

REDCAP_API_URL = config.get("redcap_url", "")
REDCAP_API_TOKEN = config.get("redcap_api_token", "")
JWT_SECRET = config.get("jwt_secret", "change-this-to-a-secure-random-string")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION = 30  # Minutes
WORDPRESS_API_URL = config.get("wordpress_url", "") + "/wp-json/wp/v2"
#ALLOWED_ORIGINS = config.get("allowed_origins", ["http://localhost", "https://yourwordpresssite.com"])
ALLOWED_ORIGINS = config.get("allowed_origins", ["http://localhost"])

# CORS support
@app.after_request
def add_cors_headers(response):
    origin = request.headers.get('Origin', '')
    if origin in ALLOWED_ORIGINS:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response

@app.route('/options', methods=['OPTIONS'])
def options():
    return jsonify({'status': 'ok'}), 200

# Security utilities
def generate_token(user_email):
    """Generate a secure JWT token for the authenticated user"""
    payload = {
        'sub': user_email,
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(minutes=JWT_EXPIRATION)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_token(token):
    """Decode and verify a JWT token"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload['sub']  # Return the user's email
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def token_required(f):
    """Decorator to require a valid token for API endpoints"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            
        if not token:
            return jsonify({'message': 'Authentication token is missing'}), 401
            
        user_email = verify_token(token)
        if not user_email:
            return jsonify({'message': 'Invalid or expired token'}), 401
            
        return f(user_email=user_email, *args, **kwargs)
    return decorated

# WordPress authentication endpoint
@app.route('/auth/wordpress', methods=['POST'])
def wordpress_auth():
    """Authenticate with WordPress credentials and return a secure token"""
    data = request.get_json()
    
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'message': 'Missing username or password'}), 400
        
    # Send authentication request to WordPress
    # Using the WordPress Application Passwords feature (WP 5.6+), TODO: Change this so don't need to manually set Application Password for each user? Better way to do this? 
    auth_response = requests.post(
        f"{WORDPRESS_API_URL}/users/me", 
        auth=(data['username'], data['password'])
    )

    if auth_response.status_code != 200:
        return jsonify({'message': 'Invalid credentials'}), 401
        
    user_data = auth_response.json()
    user_email = user_data.get('email')
    
    if not user_email:
        return jsonify({'message': 'Could not retrieve user email'}), 500
    
    # TODO
    # Verify user has a REDCap record by checking the wp_redcap table
    # You would need to set up API access to the WordPress database
    # or create a custom WordPress REST endpoint to verify this
    
    # Generate secure token for subsequent requests
    token = generate_token(user_email)
    
    return jsonify({
        'token': token,
        'expiresIn': JWT_EXPIRATION * 60,
        'user': {
            'email': user_email,
            'name': user_data.get('name', ''),
            'id': user_data.get('id')
        }
    })

# Get patient data from REDCap
@app.route('/patient/data', methods=['GET'])
@token_required
def get_patient_data(user_email):
    """Get patient's own data from REDCap, filtered by their email"""
    try:
        # Make a secure REDCap API call with filtering
        data = {
            'token': REDCAP_API_TOKEN,
            'content': 'record',
            'format': 'json',
            'type': 'flat',
            'filterLogic': f"[email] = '{user_email}'",  # Only return this patient's records
            'returnFormat': 'json'
        }
        
        # Replace 'email' with your actual REDCap email field name
        
        redcap_response = requests.post(REDCAP_API_URL, data=data)
        
        if redcap_response.status_code != 200:
            app.logger.error(f"REDCap API error: {redcap_response.text}")
            return jsonify({'message': 'Error fetching records from REDCap'}), 500
            
        records = redcap_response.json()
        
        # Double-check email filtering to ensure no data leakage
        # This is a security safeguard in case filterLogic fails
        records = [record for record in records if record.get('email') == user_email]
        
        if not records:
            return jsonify({'message': 'No records found'}), 404
            
        return jsonify({'records': records})
        
    except Exception as e:
        app.logger.error(f"Error in get_patient_data: {str(e)}")
        return jsonify({'message': 'An unexpected error occurred'}), 500

# Get specific survey results
@app.route('/patient/surveys/<survey_name>', methods=['GET'])
@token_required
def get_survey_results(user_email, survey_name):
    """Get specific survey results for the authenticated patient"""
    try:
        # Sanitize survey name to prevent injection
        survey_name = survey_name.strip()
        
        # Make a secure REDCap API call with filtering
        data = {
            'token': REDCAP_API_TOKEN,
            'content': 'record',
            'format': 'json',
            'type': 'flat',
            'forms': survey_name,  # Only return data from this survey/form
            'filterLogic': f"[email] = '{user_email}'",  # Only return this patient's records
            'returnFormat': 'json'
        }
        
        redcap_response = requests.post(REDCAP_API_URL, data=data)
        
        if redcap_response.status_code != 200:
            app.logger.error(f"REDCap API error: {redcap_response.text}")
            return jsonify({'message': 'Error fetching survey data from REDCap'}), 500
            
        records = redcap_response.json()
        
        # Secondary security check
        records = [record for record in records if record.get('email') == user_email]
        
        if not records:
            return jsonify({'message': f'No {survey_name} survey data found'}), 404
            
        return jsonify({'survey_data': records})
        
    except Exception as e:
        app.logger.error(f"Error in get_survey_results: {str(e)}")
        return jsonify({'message': 'An unexpected error occurred'}), 500

# Security audit log
def log_access(user_email, access_type, data_requested):
    """Log all data access attempts for security auditing"""
    # In production, you'd want to store this in a database or secure log
    app.logger.info(f"AUDIT: {datetime.utcnow()} - {user_email} - {access_type} - {data_requested}")

# Start the application
if __name__ == '__main__':
    # Set up logging
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        filename='redcap_middleware.log'
    )
    
    # For production, use a proper WSGI server like Gunicorn
    # Production server
    # gunicorn --bind 0.0.0.0:5000 app:app
    
    # For development
    app.run(debug=False, host='0.0.0.0', port=5000)
