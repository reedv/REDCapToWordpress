#!/usr/bin/env python3
"""
REDCap Secure Patient Middleware

This middleware ensures patients can only access their own REDCap data by:
1. Authenticating users through WordPress authentication
2. Making secure REDCap API calls with email-based filtering
3. Never exposing the REDCap API token to client-side code

Deploy this as a separate service alongside your WordPress installation.
"""

from flask import Flask, request, jsonify, abort, make_response
import jwt
import json
from functools import wraps
from datetime import datetime, timedelta, timezone
import logging
import traceback
import requests
import re
import json
import sys
import os
import hashlib
import uuid

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


WORDPRESS_API_KEY = os.environ.get("WORDPRESS_API_KEY")  # this will mostly be used to determine if a request (w/ included X-API-KEY header) to middleware url is allowed to ask for/generate jwt tokens
REDCAP_API_URL = config.get("redcap_url", "")
# get REDCAP API token and JWT_SECRET from env variable rather than config file for better security
REDCAP_API_TOKEN = os.environ.get("REDCAP_API_TOKEN", "")
JWT_SECRET = os.environ.get("JWT_SECRET", "default-only-for-development")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION = 15  # Minutes
WORDPRESS_URL = config.get("wordpress_url", "")
WORDPRESS_API_URL = WORDPRESS_URL + "/wp-json/wp/v2"
#ALLOWED_ORIGINS = config.get("allowed_origins", ["http://localhost", "https://yourwordpresssite.com"])
ALLOWED_ORIGINS = config.get("allowed_origins", ["http://localhost"])
ALLOWED_SURVEYS = config.get("allowed_surveys", [])

# Verify secrets are properly set
if WORDPRESS_API_KEY is None and os.environ.get('WP2REDCAP_ENVIRONMENT') != 'development':
    logger.error("Production environment detected but WORDPRESS_API_KEY not configured properly!")
    sys.exit(1)
if REDCAP_API_TOKEN == "" and os.environ.get('WP2REDCAP_ENVIRONMENT') != 'development':
    logger.error("Production environment detected but REDCAP_API_TOKEN not configured properly!")
    sys.exit(1)  # Fail to start if not properly configured
if JWT_SECRET == 'default-only-for-development' and os.environ.get('WP2REDCAP_ENVIRONMENT') != 'development':
    logger.error("Production environment detected but JWT_SECRET not configured properly!")
    sys.exit(1)  # Fail to start if not properly configured

def sanitize_for_redcap(value):
    """Escape special characters for REDCap filterLogic"""
    if value is None:
        return ""
    # Replace single quotes with double quotes to prevent SQL injection
    # and escape other special characters
        
    # Convert to string and trim whitespace
    value = str(value).strip()
    # Escape single quotes (SQL-style escaping)
    value = value.replace("'", "''")
    # Remove or escape other potentially problematic characters
    value = re.sub(r'[\\";=<>()]', '', value)
    
    return value

# CORS support
@app.after_request
def add_cors_headers(response):
    origin = request.headers.get('Origin', '')
    if origin in ALLOWED_ORIGINS:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Original-Client-IP, X-Original-User-Agent'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        # This is important for cookie-based auth with different domains
        # However, credentials will be sent from WordPress server to middleware, not directly from browser
    return response

@app.route('/options', methods=['OPTIONS'])
def options():
    return jsonify({'status': 'ok'}), 200

# Security utilities
def get_client_fingerprint(override_ip=None, override_user_agent=None):
    """Generate a fingerprint from client details, allowing override values from WordPress"""
    # Using this to create a fingerprint claim in the token, 
    # then even if an attacker somehow obtains one's token (through XSS attacks, browser storage access, network sniffing, etc.), 
    # they still can't use it because:
    # They would need to precisely mimic your User-Agent string
    # They would need to access the API from your exact IP address
    # Both conditions must be met simultaneously

    # Use overrides if provided, otherwise use direct request headers
    user_agent = override_user_agent or request.headers.get('User-Agent', '')
    
    # Get client IP, considering potential proxies
    if override_ip:
        ip = override_ip
    else:
        ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        if ip and ',' in ip:
            # Get the leftmost IP in case of multiple proxies
            ip = ip.split(',')[0].strip()
    
    # Create a fingerprint hash
    fingerprint = hashlib.sha256(f"{user_agent}|{ip}".encode()).hexdigest()
    logger.debug(f"Creating fingerprint with UA: {user_agent[:30]}... and IP: {ip}")
    return fingerprint

def generate_token(user_email):
    """Generate a secure JWT token with enhanced security features"""
    # Generate a unique ID for this token
    token_id = str(uuid.uuid4())

    # Extract forwarded client details if present
    forwarded_ip = request.headers.get('X-Original-Client-IP')
    forwarded_ua = request.headers.get('X-Original-User-Agent')
    
    # Get client fingerprint using forwarded details when available for binding token to client
    # This will be used to bind a token to the specific device and network that originally requested it. 
    # This creates a defense against token theft attacks.
    fingerprint = get_client_fingerprint(
        override_ip=forwarded_ip,
        override_user_agent=forwarded_ua
    )
    
    # Create enhanced payload
    payload = {
        'sub': user_email,                  # Subject (email)
        'jti': token_id,                    # JWT ID (unique)
        'iat': datetime.now(timezone.utc),           # Issued at
        'exp': datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRATION),  # Expiration
        'iss': WORDPRESS_URL,               # Issuer
        'aud': 'redcap-patient-data-api',   # Audience, without audience setting/checking token could be used in "token confusion" or "cross-service token replay" down the road if services have same JWT_SECRET
        'fgp': fingerprint                  # Fingerprint
    }
    
    # (optional implementation) Store token in redis/database for potential revocation
    # redis_client.setex(f"token:{token_id}", JWT_EXPIRATION * 60, "active")
    
    logger.info(f"Token generated for {user_email} with ID {token_id}")
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_token(token, forwarded_ip=None, forwarded_ua=None):
    """Decode and verify a JWT token with enhanced security checks"""
    try:
        # Decode the token
        payload = jwt.decode(
            token, 
            JWT_SECRET, 
            algorithms=[JWT_ALGORITHM],
            audience="redcap-patient-data-api",
            issuer=WORDPRESS_URL
        )
        
        # (optional implementation) Check for token in blacklist 
        # token_status = redis_client.get(f"token:{payload['jti']}")
        # if token_status is None or token_status.decode() != "active":
        #     return None  # Token has been revoked or doesn't exist

        # Verify the fingerprint if present
        if 'fgp' in payload:
            current_fingerprint = get_client_fingerprint(
                override_ip=forwarded_ip,
                override_user_agent=forwarded_ua
            )
            if payload['fgp'] != current_fingerprint:
                logger.warning(f"Token fingerprint mismatch: {payload['jti']}")
                logger.debug(f"Expected: {payload['fgp']}, Got: {current_fingerprint}")
                return None
                
        return payload['sub']  # Return the user's email
    except jwt.ExpiredSignatureError:
        logger.warning("Token expired")
        return None
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid token: {str(e)}")
        return None

def token_required(f):
    """Decorator to require a valid token for API endpoints with fingerprint verification"""
    @wraps(f)
    def decorated(*args, **kwargs):
        # Extract token from Authorization header
        token = None
        auth_header = request.headers.get('Authorization')
        
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            
        if not token:
            return jsonify({'message': 'Authentication token is missing'}), 401
        
        # Extract forwarded client context identifiers for fingerprint verification
        forwarded_ip = request.headers.get('X-Original-Client-IP')
        forwarded_ua = request.headers.get('X-Original-User-Agent')
        
        # Pass the forwarded client context to verify_token
        user_email = verify_token(token, forwarded_ip, forwarded_ua)
        
        if not user_email:
            logger.warning(f"Token verification failed for request to {request.path}")
            return jsonify({'message': 'Invalid or expired token'}), 401
            
        # Token verified successfully, proceed with endpoint execution
        return f(user_email=user_email, *args, **kwargs)
    
    return decorated

# participant self-registration validation endpoint
@app.route('/verify_participant', methods=['POST'])
def verify_participant():
    """
    Verify if a user exists in REDCap with the provided email, first name, and last name.
    This endpoint is used during self-registration to confirm study participation.
    """
    try:
        # Extract request data
        data = request.get_json()
        if not data:
            logger.warning("No JSON data received in verification request")
            return jsonify({
                'message': 'No verification data provided',
                'verified': False
            }), 400

        # Validate email format
        email = data.get('email', '')
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            return jsonify({
                'message': 'Invalid email format',
                'verified': False
            }), 400

        # Validate name format (allow letters, spaces, hyphens)
        first_name = data.get('first_name', '')
        last_name = data.get('last_name', '')
        if not re.match(r'^[a-zA-Z\s\-]+$', first_name) or not re.match(r'^[a-zA-Z\s\-]+$', last_name):
            return jsonify({
                'message': 'Invalid name format. For security purposes, only letters, spaces, and hyphens are allowed.',
                'verified': False
            }), 400

        # Log sanitized data
        logger.info(f"Verification attempt for email: {data.get('email', 'N/A')}")

        # Validate required fields
        required_fields = ['email', 'first_name', 'last_name']
        for field in required_fields:
            if field not in data or not data[field]:
                logger.warning(f"Missing {field} in verification request")
                return jsonify({
                    'message': f'Missing {field}',
                    'verified': False
                }), 400

        # Query REDCap to check if the participant exists
        redcap_data = {
            'token': REDCAP_API_TOKEN,
            'content': 'record',
            'format': 'json',
            'type': 'flat',
            'filterLogic': f"[email] = '{sanitize_for_redcap(data['email'])}' AND [self_consent_first_name] = '{sanitize_for_redcap(data['first_name'])}' AND [self_consent_last_name] = '{sanitize_for_redcap(data['last_name'])}'",
            'returnFormat': 'json'
        }
        
        redcap_response = requests.post(REDCAP_API_URL, data=redcap_data, verify=True)  ## Including arg verify=False for debugging/dev runs if redcap_url having SSL issues
        
        if redcap_response.status_code != 200:
            logger.error(f"REDCap API error: {redcap_response.text}")
            return jsonify({
                'message': 'Error checking REDCap records',
                'verified': False
            }), 500
            
        records = redcap_response.json()
        
        # Double-check that the record matches our criteria
        # This is an extra security measure
        verified_records = []
        for record in records:
            if (record.get('email') == data['email'] and 
                record.get('self_consent_first_name') == data['first_name'] and 
                record.get('self_consent_last_name') == data['last_name']):
                verified_records.append(record)
        
        if not verified_records:
            logger.info(f"No matching records found for {data['email']}")
            return jsonify({
                'verified': False,
                'message': 'No matching participant record found'
            }), 200
            
        # Return success with record ID
        record_id = verified_records[0].get('record_id')
        logger.info(f"Participant verified: {data['email']} with record ID {record_id}")
        return jsonify({
            'verified': True,
            'record_id': record_id,
            'message': 'Participant verified successfully'
        }), 200
        
    except Exception as e:
        logger.error(f"Unexpected error during verification: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            'verified': False,
            'message': 'Internal verification error'
        }), 500
    
@app.route('/auth/generate_token', methods=['POST'])
def generate_token_endpoint():
    """Generate a token for an already authenticated WordPress user"""
    try:
        # Extract request data
        data = request.get_json()
        if not data:
            logger.warning("No JSON data received in token generation request")
            return jsonify({
                'message': 'No data provided',
                'error_type': 'invalid_request'
            }), 400
            
        # Verify API key (in HTTP header)
        api_key = request.headers.get('X-API-KEY')
        if api_key != WORDPRESS_API_KEY and os.environ.get('WP2REDCAP_ENVIRONMENT') != 'development':
            logger.warning("Invalid API key used in token generation request")
            return jsonify({
                'message': 'Unauthorized',
                'error_type': 'unauthorized'
            }), 401

        # Log forwarded client details if present
        forwarded_ip = request.headers.get('X-Original-Client-IP')
        forwarded_ua = request.headers.get('X-Original-User-Agent')
        
        if forwarded_ip and forwarded_ua:
            logger.info(f"Received forwarded client details: IP={forwarded_ip}, UA={forwarded_ua[:30]}...")
        else:
            logger.warning("No forwarded client details received, fingerprinting may fail later")

        # Log sanitized data
        logger.info(f"Token generation requested for email: {data.get('email', 'N/A')}")

        # Validate required fields
        if 'email' not in data or not data['email']:
            logger.warning("Missing email in token generation request")
            return jsonify({
                'message': 'Missing email',
                'error_type': 'incomplete_data'
            }), 400

        user_email = data['email']

        # Verify email exists in redcap records
        redcap_data = {
            'token': REDCAP_API_TOKEN,
            'content': 'record',
            'format': 'json',
            'filterLogic': f"[email] = '{sanitize_for_redcap(user_email)}'",
            'returnFormat': 'json'
        }
        redcap_response = requests.post(REDCAP_API_URL, data=redcap_data, verify=True)
        records = redcap_response.json()
        if not records:
            return jsonify({
                'message': 'User email not found in records', 
                'error_type': 'user_not_found'
            }), 404
        
        # Generate the token
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

    except Exception as e:
        # Catch-all for any unexpected errors
        logger.error(f"Unexpected error during token generation: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            'message': 'Internal token generation error',
            'error_type': 'unexpected_error'
        }), 500

@app.route('/auth/verify', methods=['POST', 'OPTIONS'])
def auth_verify():
    """Verify a JWT token and return user data if valid"""
    # Handle OPTIONS requests for CORS preflight
    if request.method == 'OPTIONS':
        return '', 204
    
    # Handle POST requests
    try:
        data = request.get_json()
        
        if not data or 'token' not in data:
            logger.warning("Token verification attempt with missing token")
            return jsonify({
                'success': False,
                'message': 'No token provided',
                'error': 'missing_token'
            }), 400
        
        # Extract forwarded client details
        forwarded_ip = request.headers.get('X-Original-Client-IP')
        forwarded_ua = request.headers.get('X-Original-User-Agent')
        
        # Get and verify the token
        token = data.get('token')
        user_email = verify_token(token, forwarded_ip, forwarded_ua)
        
        if not user_email:
            logger.warning("Invalid or expired token verification attempt")
            return jsonify({
                'success': False,
                'message': 'Invalid or expired token',
                'error': 'invalid_token'
            }), 401
        
        # Token is valid, return success with user info
        logger.info(f"Token successfully verified for user: {user_email}")
        return jsonify({
            'success': True,
            'user': {
                'email': user_email
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error in token verification: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            'success': False,
            'message': 'An unexpected error occurred',
            'error': 'server_error'
        }), 500

# Get patient data from REDCap
@app.route('/patient/data', methods=['GET'])
@token_required
def get_patient_data(user_email):
    """Get patient's own data from REDCap, filtered by their email"""
    # Return error or restricted access message
    return jsonify({'message': 'Full record access is disabled for security reasons. Please access specific surveys instead.'}), 403
    try:
        # Make a secure REDCap API call with filtering, see https://<your redcap_url>/api/help/?content=exp_records 
        data = {
            'token': REDCAP_API_TOKEN,
            'content': 'record',
            'format': 'json',
            'type': 'flat',
            'filterLogic': f"[email] = '{sanitize_for_redcap(user_email)}'",  # Only return this patient's records
            'returnFormat': 'json'
        }
        
        # Replace 'email' with your actual REDCap email field name
        
        redcap_response = requests.post(REDCAP_API_URL, data=data, verify=True)  ## If having SSL cert issues with redcap_url, can add arg verify=False to this call for debugging.
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
    """Get specific survey results for the authenticated patient using record-based access"""
    try:
        # Sanitize survey name to prevent injection
        survey_name = survey_name.strip()
        # Validate against allowed surveys
        if survey_name not in ALLOWED_SURVEYS:
            return jsonify({'message': 'Access to this survey is not permitted or survey does not exist'}), 403
        
        # Step 1: Get the user's record_id by finding their email in the project
        # This verifies the user exists and gets their record identifier
        user_lookup_data = {
            'token': REDCAP_API_TOKEN,
            'content': 'record',
            'format': 'json',
            'type': 'flat',
            'filterLogic': f"[email] = '{sanitize_for_redcap(user_email)}'",
            'fields': 'record_id,email',  # Only get essential fields for lookup
            'returnFormat': 'json'
        }
        
        logger.debug(f"Looking up record_id for user: {user_email}")
        user_lookup_response = requests.post(REDCAP_API_URL, data=user_lookup_data, verify=True)
        
        if user_lookup_response.status_code != 200:
            logger.error(f"REDCap API error during user lookup: {user_lookup_response.text}")
            return jsonify({'message': 'Error verifying user access'}), 500
            
        user_records = user_lookup_response.json()
        
        if not user_records:
            logger.warning(f"No records found for user {user_email}")
            return jsonify({'message': 'User not found in study records'}), 404
        
        # Extract record_id from the user lookup
        record_id = user_records[0].get('record_id')
        if not record_id:
            logger.error(f"No record_id found for user {user_email}")
            return jsonify({'message': 'User record ID not found'}), 500
        
        logger.info(f"Found record_id {record_id} for user {user_email}")
        
        # Step 2: Get the specific survey data using record_id (not email filtering)
        # This allows access to surveys that don't contain email fields
        survey_data = {
            'token': REDCAP_API_TOKEN,
            'content': 'record',
            'format': 'json',
            'type': 'flat',
            'forms': survey_name,
            'records': record_id,  # Use record_id instead of filterLogic
            'returnFormat': 'json'
        }
        
        logger.debug(f"Fetching survey {survey_name} data for record_id: {record_id}")
        survey_response = requests.post(REDCAP_API_URL, data=survey_data, verify=True)
        
        if survey_response.status_code != 200:
            logger.error(f"REDCap API error: {survey_response.text}")
            return jsonify({'message': 'Error fetching survey data from REDCap'}), 500
            
        records = survey_response.json()
        
        # No secondary email filtering needed since we used record_id filtering
        # The user was already validated in step 1
        
        if not records:
            logger.info(f"No {survey_name} survey data found for record_id {record_id}")
            return jsonify({'message': f'No {survey_name} survey data found'}), 404
            
        logger.info(f"Successfully retrieved {len(records)} records for survey {survey_name}")
        return jsonify({'survey_data': records})
        
    except Exception as e:
        logger.error(f"Error in get_survey_results: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({'message': 'An unexpected error occurred'}), 500

@app.route('/patient/survey_metadata/<survey_name>', methods=['GET'])
@token_required
def get_survey_metadata(user_email, survey_name):
    """Get comprehensive metadata for a specific survey - no user-specific filtering needed"""
    
    # Validate requested survey
    if survey_name not in ALLOWED_SURVEYS:
        return jsonify({'message': 'Access to this survey is not permitted or survey does not exist'}), 403
    
    try:
        # Sanitize survey name
        survey_name = survey_name.strip()
        
        # For metadata, we don't need user-specific filtering since it's just field definitions
        # But we still verify the user has access by checking their existence in the project
        user_verification_data = {
            'token': REDCAP_API_TOKEN,
            'content': 'record',
            'format': 'json',
            'type': 'flat',
            'filterLogic': f"[email] = '{sanitize_for_redcap(user_email)}'",
            'fields': 'record_id',  # Minimal field to verify existence
            'returnFormat': 'json'
        }
        
        verification_response = requests.post(REDCAP_API_URL, data=user_verification_data, verify=True)
        
        if verification_response.status_code != 200:
            logger.error(f"REDCap API error (verification): {verification_response.text}")
            return jsonify({'message': 'Error verifying user access'}), 500
            
        user_records = verification_response.json()
        if not user_records:
            return jsonify({'message': 'User not found in study records'}), 404
        
        # Get metadata (field definitions)
        metadata_data = {
            'token': REDCAP_API_TOKEN,
            'content': 'metadata',
            'format': 'json',
            'forms[0]': survey_name,
            'returnFormat': 'json'
        }
        
        metadata_response = requests.post(REDCAP_API_URL, data=metadata_data, verify=True)
        
        if metadata_response.status_code != 200:
            logger.error(f"REDCap API error (metadata): {metadata_response.text}")
            return jsonify({'message': 'Error fetching survey metadata'}), 500
            
        metadata = metadata_response.json()
        
        # Get form/instrument information (for matrix grouping)
        instrument_data = {
            'token': REDCAP_API_TOKEN,
            'content': 'instrument',
            'format': 'json',
            'returnFormat': 'json'
        }
        
        instrument_response = requests.post(REDCAP_API_URL, data=instrument_data, verify=True)
        
        if instrument_response.status_code != 200:
            logger.error(f"REDCap API error (instrument): {instrument_response.text}")
            return jsonify({'message': 'Error fetching instrument data'}), 500
            
        instruments = instrument_response.json()
        
        # Get field mapping for matrices
        formEventMapping = None
        if any(field.get('grid_name') for field in metadata):
            mapping_data = {
                'token': REDCAP_API_TOKEN,
                'content': 'formEventMapping',
                'format': 'json',
                'returnFormat': 'json'
            }
            
            mapping_response = requests.post(REDCAP_API_URL, data=mapping_data, verify=True)
            
            if mapping_response.status_code == 200:
                formEventMapping = mapping_response.json()
        
        # Get file repository info if there are file upload fields
        fileFields = [field for field in metadata if field.get('field_type') == 'file']
        
        return jsonify({
            'metadata': metadata,
            'instruments': instruments,
            'formEventMapping': formEventMapping,
            'hasFileFields': bool(fileFields)
        })
        
    except Exception as e:
        logger.error(f"Error in get_survey_metadata: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({'message': 'An unexpected error occurred'}), 500

# Helper function to get user's record_id (can be reused across functions)
def get_user_record_id(user_email):
    """Get the record_id for a validated user"""
    user_lookup_data = {
        'token': REDCAP_API_TOKEN,
        'content': 'record',
        'format': 'json',
        'type': 'flat',
        'filterLogic': f"[email] = '{sanitize_for_redcap(user_email)}'",
        'fields': 'record_id,email',
        'returnFormat': 'json'
    }
    
    response = requests.post(REDCAP_API_URL, data=user_lookup_data, verify=True)
    
    if response.status_code != 200:
        logger.error(f"REDCap API error during record_id lookup: {response.text}")
        return None
        
    records = response.json()
    
    if not records:
        logger.warning(f"No records found for user {user_email}")
        return None
        
    return records[0].get('record_id')
    
# File download endpoint
@app.route('/patient/file/<record_id>/<field_name>', methods=['GET'])
@token_required
def get_file(user_email, record_id, field_name):
    """Download files securely for authenticated patients"""
    try:
        # Validate record_id format (assuming it's numeric)
        if not record_id.isdigit():
            return jsonify({'message': 'Invalid record ID format'}), 400
        
        # Validate field_name format (only allow alphanumeric and underscores)
        if not re.match(r'^[a-zA-Z0-9_]+$', field_name):
            return jsonify({'message': 'Invalid field name format'}), 400
        
        # Verify this user has access to this record
        verification_data = {
            'token': REDCAP_API_TOKEN,
            'content': 'record',
            'format': 'json',
            'type': 'flat',
            'records[0]': record_id,
            'fields[0]': 'email',
            'returnFormat': 'json'
        }
        verification_response = requests.post(REDCAP_API_URL, data=verification_data, verify=True)
        if verification_response.status_code != 200:
            return jsonify({'message': 'Error verifying record access'}), 500
            
        records = verification_response.json()
        
        if not records or records[0].get('email') != user_email:
            return jsonify({'message': 'Access denied to this record'}), 403
        
        # Get file data
        file_data = {
            'token': REDCAP_API_TOKEN,
            'content': 'file',
            'action': 'export',
            'record': record_id,
            'field': field_name,
            'returnFormat': 'json'
        }
        
        file_response = requests.post(REDCAP_API_URL, data=file_data, verify=True)
        
        if file_response.status_code != 200:
            return jsonify({'message': 'Error retrieving file'}), 500
        
        # Create response with appropriate content type
        response = make_response(file_response.content)
        response.headers.set('Content-Type', file_response.headers.get('Content-Type', 'application/octet-stream'))
        response.headers.set('Content-Disposition', file_response.headers.get('Content-Disposition', f'attachment; filename="{field_name}_file"'))
        
        return response
        
    except Exception as e:
        logger.error(f"Error in get_file: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({'message': 'An unexpected error occurred'}), 500

# Security audit log
def log_access(user_email, access_type, data_requested):
    """Log all data access attempts for security auditing"""
    # In production, you'd want to store this in a database or secure log
    app.logger.info(f"AUDIT: {datetime.now(timezone.utc)} - {user_email} - {access_type} - {data_requested}")

# Start the application
if __name__ == '__main__':
    
    # For production, use a proper WSGI server like Gunicorn
    # Production server
    # gunicorn --bind 0.0.0.0:5000 app:app
    
    # For development
    app.run(debug=True, host='0.0.0.0', port=5000)
