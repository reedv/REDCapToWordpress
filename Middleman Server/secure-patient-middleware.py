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
import traceback
import requests
from flask import request, jsonify
import json
import sys

# Configure logging to output to stdout/stderr for Cloud Run logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [REDCap Auth] - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)
# Force logs to stderr which Cloud Run captures
handler = logging.StreamHandler(sys.stderr)
handler.setLevel(logging.DEBUG)
logger.addHandler(handler)


app = Flask(__name__)

# Load configuration
with open("config.json", "r") as f:
    config = json.load(f)

REDCAP_API_URL = config.get("redcap_url", "")
REDCAP_API_TOKEN = config.get("redcap_api_token", "")
JWT_SECRET = config.get("jwt_secret", "change-this-to-a-secure-random-string")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION = 30  # Minutes
WORDPRESS_URL = config.get("wordpress_url", "")
WORDPRESS_API_URL = WORDPRESS_URL + "/wp-json/wp/v2"
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
    # Log the start of the authentication attempt
    client_ip = request.remote_addr
    logger.info(f"Authentication attempt initiated")
    logger.info(f"Client IP: {client_ip}")

    try:
        # Extract request data
        data = request.get_json()
       
        # Validate request data
        if not data:
            logger.warning("No JSON data received in authentication request")
            return jsonify({
                'message': 'No authentication data provided',
                'error_type': 'invalid_request'
            }), 400

        # Log sanitized data (never log actual passwords)
        logger.info(f"Authentication attempt for username: {data.get('username', 'N/A')}")

        # Validate required fields
        if 'username' not in data or 'password' not in data:
            logger.warning("Missing username or password in authentication request")
            return jsonify({
                'message': 'Missing username or password',
                'error_type': 'incomplete_credentials'
            }), 400

        # Attempt WordPress authentication
        logger.info("Attempting to authenticate via WordPress REST API")
       
        # Additional logging for debugging network/request issues
        wordpress_auth_url = f"{WORDPRESS_URL}/wp-json/redcap-portal/v1/authenticate"
        logger.info(f"WordPress Authentication URL: {wordpress_auth_url}")

        try:
            # Log request details (without password)
            request_log = {
                'url': wordpress_auth_url,
                'method': 'POST',
                'headers': {'Content-Type': 'application/json'},
                'username': data['username']
            }
            logger.info(f"Sending authentication request: {json.dumps(request_log)}")

            # Make authentication request
            auth_response = requests.post(
                wordpress_auth_url,
                json={
                    'username': data['username'],
                    'password': data['password']
                },
                timeout=10  # Add timeout to prevent hanging
            )
            print(f"AUTH DEBUG: Status code: {auth_response.status_code}", file=sys.stderr)
            print(f"AUTH DEBUG: Response: {auth_response.text[:500]}", file=sys.stderr)

            # Log response status
            logger.info(f"WordPress Authentication Response Status: {auth_response.status_code}")
           
            # Log response content for debugging
            try:
                response_content = auth_response.json()
                # Sanitize response before logging
                sanitized_response = {k: v for k, v in response_content.items() if k != 'user'}
                logger.info(f"Authentication Response Content: {json.dumps(sanitized_response)}")
            except ValueError:
                logger.warning("Could not parse response JSON")
                logger.warning(f"Raw response content: {auth_response.text}")

            # Check authentication result
            if auth_response.status_code != 200:
                logger.warning(f"WordPress authentication failed. Status code: {auth_response.status_code}")
                return jsonify({
                    'message': 'WordPress authentication failed. Invalid credentials.',
                    'error_type': 'authentication_failed',
                    'status_code': auth_response.status_code
                }), 401

            # Extract user data
            auth_data = auth_response.json()
            user_email = auth_data.get('user', {}).get('email')

            if not user_email:
                logger.error("No email found in authentication response")
                return jsonify({
                    'message': 'Invalid user data',
                    'error_type': 'missing_email'
                }), 401

            # Log successful authentication
            logger.info(f"Successful authentication for email: {user_email}")

            # Generate JWT token
            token = generate_token(user_email)
           
            # Log token generation (without revealing the token)
            logger.info(f"JWT token generated for user: {user_email}")

            return jsonify({
                'token': token,
                'expiresIn': JWT_EXPIRATION * 60,
                'user': {
                    'email': user_email
                }
            }), 200

        except requests.exceptions.RequestException as req_err:
            # Log network-related errors
            logger.error(f"Request to WordPress failed: {str(req_err)}")
            logger.error(traceback.format_exc())
            return jsonify({
                'message': 'Authentication service error',
                'error_type': 'network_error',
                'details': str(req_err)
            }), 500

    except Exception as e:
        # Catch-all for any unexpected errors
        logger.error(f"Unexpected error during authentication: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            'message': 'Internal authentication error',
            'error_type': 'unexpected_error'
        }), 500

# Get patient data from REDCap
@app.route('/patient/data', methods=['GET'])
@token_required
def get_patient_data(user_email):
    """Get patient's own data from REDCap, filtered by their email"""
    try:
        # Make a secure REDCap API call with filtering, see https://redcap.uhphawaii.org/api/help/?content=exp_records 
        data = {
            'token': REDCAP_API_TOKEN,
            'content': 'record',
            'format': 'json',
            'type': 'flat',
            'filterLogic': f"[email] = '{user_email}'",  # Only return this patient's records
            'returnFormat': 'json'
        }
        
        # Replace 'email' with your actual REDCap email field name
        
        redcap_response = requests.post(REDCAP_API_URL, data=data)  ## If having SSL cert issues with redcap_url, can add arg verify=False to this call for debugging.
        app.logger.info(f"REDCap raw response: {redcap_response.text[:200]}...")  # Log first 200 chars
        
        if redcap_response.status_code != 200:
            app.logger.error(f"REDCap API error: {redcap_response.text}")
            return jsonify({'message': 'Error fetching records from REDCap'}), 500
            
        records = redcap_response.json()
        app.logger.info(f"Records before filtering: {len(records)}")
        app.logger.info(f"Looking for email: {user_email}")
        if records:
            app.logger.info(f"Sample record keys: {list(records[0].keys())}")
            app.logger.info(f"Email field values: {[r.get('email') for r in records[:5]]}")
        
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
    
    # For production, use a proper WSGI server like Gunicorn
    # Production server
    # gunicorn --bind 0.0.0.0:5000 app:app
    
    # For development
    app.run(debug=True, host='0.0.0.0', port=5000)
