# Secure REDCap Patient Portal: Implementation Guide

This guide provides detailed instructions for implementing a HIPAA-compliant patient portal that integrates WordPress with REDCap, ensuring patients can only access their own health data.

## System Architecture

The architecture consists of three main components:

1. **WordPress with Plugin** - Handles user authentication and displays patient data
2. **Security Middleware** - Acts as a secure gateway between WordPress and REDCap
3. **REDCap** - Stores all patient data with a single API token

This architecture ensures the REDCap API token is never exposed to the client browser, and all data access is strictly filtered by email address.

## Setup Instructions

### 1. Set Up Security Middleware

The middleware is a Python Flask application that enforces patient-level access controls.

#### Prerequisites:
- Python 3.6+
- Flask
- Requests
- PyJWT

#### Installation:

```bash
# Clone repository or copy the middleware code
mkdir redcap-middleware
cd redcap-middleware

# Install dependencies
pip install flask requests pyjwt

# Create config.json file with your settings
cat > config.json << EOL
{
  "redcap_url": "https://your-redcap-instance.org/api/",
  "redcap_api_token": "YOUR_REDCAP_API_TOKEN",
  "jwt_secret": "GENERATE_A_SECURE_RANDOM_STRING",
  "wordpress_url": "https://your-wordpress-site.com",
  "allowed_origins": ["https://your-wordpress-site.com"]
}
EOL

# Start the middleware (for development)
python secure-patient-middleware.py

# For production, use Gunicorn
# gunicorn --bind 0.0.0.0:5000 secure-patient-middleware:app
```

### 2. Configure Your REDCap Project

1. Ensure each record in your REDCap project has an email field
2. This email field will be used for patient-level filtering
3. Generate an API token with appropriate permissions:
   - Export Records
   - Export Reports

### 3. WordPress Plugin Installation

1. Install the REDCap Patient Portal Connector plugin
   - Upload the plugin files to `/wp-content/plugins/redcap-patient-portal/`
   - Activate the plugin through the WordPress admin panel

2. Configure the plugin:
   - Go to Settings > REDCap Portal
   - Enter the URL of your middleware server

3. Create the necessary pages for your patient portal:
   - Login Page: Add `[redcap_login redirect_url="/my-data"]` shortcode
   - Data Page: Add `[redcap_portal]` shortcode
   - For specific surveys: `[redcap_portal survey="medication_survey"]`

### 4. Secure Your Installation

1. Set up HTTPS for both WordPress and the middleware
2. Configure secure cookies for both applications
3. Set appropriate file permissions on the middleware server
4. Ensure the `config.json` file with the REDCap API token is not web-accessible

## Common Configuration Issues

1. **CORS Problems**: If you encounter CORS issues, verify your allowed origins in the middleware config.

2. **Authentication Failures**: Make sure JWT_SECRET is the same in your middleware and that it is sufficiently complex.

3. **No Data Showing**: Check that the email field name matches what's used in your REDCap project.

4. **Custom REDCap Fields**: If your REDCap project uses different field names, modify the middleware filtering logic accordingly.

## REDCap Record-to-User Mapping

The wp_redcap table maps WordPress user emails to REDCap record IDs:

```
+------------------+-------------+
| email            | record_id   |
+------------------+-------------+
| patient1@test.com| RECORD-001  |
| patient2@test.com| RECORD-002  |
+------------------+-------------+
```

To manually add mappings:

```sql
INSERT INTO wp_redcap (email, record_id) VALUES ('patient@example.com', 'RECORD-123');
```

## Security Best Practices

1. Use a separate middleware server from your WordPress installation
2. Apply IP restrictions to the middleware server to only accept connections from your WordPress server
3. Regularly audit access logs
4. Use strong passwords for all systems
5. Keep all software updated
6. Consider implementing rate limiting on authentication endpoints
7. Run periodic security scans of all components

## Testing Your Setup

1. **Email-Based Security Test**: Try accessing data with different user accounts to verify each user only sees their own data.

2. **API Token Exposure Test**: Use browser developer tools to confirm the REDCap API token is never exposed to the client.

3. **Authentication Test**: Verify expired or tampered tokens are rejected.

## HIPAA Compliance Notes

This architecture helps with HIPAA compliance by:

- Keeping PHI access restricted to authenticated users
- Enforcing technical controls to limit data access to only the patient's own data
- Keeping sensitive credentials out of client-side code
- Providing audit logging of all data access

Remember that HIPAA compliance involves many other factors beyond this technical implementation, including administrative and physical safeguards.

## Troubleshooting

### Patient Can't Access Their Data

1. Verify the email in WordPress matches the one in REDCap
2. Check the `wp_redcap` table mapping
3. Test middleware access directly with the patient's email

### Error Contacting Middleware Server

1. Check if middleware server is running
2. Verify network connectivity and firewall settings
3. Check middleware logs for errors

### Performance Issues

1. Add caching for frequently accessed data
2. Consider adding indexes to your REDCap project
3. Optimize your WordPress installation

## Maintenance

1. Regularly back up your WordPress database
2. Keep all components updated
3. Review security logs periodically
4. Test the entire system after any significant update

## Support

If you need additional assistance, please contact your REDCap administrator or refer to the documentation provided with the code.
