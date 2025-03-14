# REDCapToWordPress WordPress plugin

## Description
This plugin is designed to create a patient portal for medical or other research studies
that are patient-driven, meaning that the study participant needs to enter data but also needs
access to the data they input as well as study results that pertain to them. This links REDCap projects 
to WordPress websites, giving patients access to their personal data that they share with research projects.

### Pre-requisite plugins:
    
This plugin requires the [Native PHP Sessions for WordPress plugin](https://wordpress.org/plugins/wp-native-php-sessions/).
Be sure to install this before installing REDCapToWordPress.

## Setting up the Plugin
Download the REDCapToWordPress repository.

In the **config.json** file within the Middleware Server folder, add your REDCap API token and configure the middleware settings. More details on this are below.
 
Once all the changes are made, add the REDCapToWordPress folder to the plugins
folder in WordPress. You can either directly upload the folder to your hosting server to 
/htdocs/wp_content/plugins, or you can zip the folder and upload it through the admin backend
view of WordPress.

### Creating landing pages

#### Login Page

This is the page where patients can login to access their data.

Create a page on your site with a URL like **yoursite.com/login**.

On this page, add the shortcode **[redcap_login redirect_url="/my-data"]**.

#### Patient Data Page

This is where patients can view their REDCap data. The current system is designed to
filter data by email address, ensuring patients can only see their own information.

Create a page on your site with a URL that matches your redirect_url (e.g., **yoursite.com/my-data**).

On this page, add the shortcode **[redcap_portal]**.

To display specific survey results, use **[redcap_portal survey="survey_name"]**.

## Building the Security Middleware

### Description and Rationale

Since this plugin is designed to work with REDCap, which is generally used to store 
Personal Health Information (PHI), we've implemented a robust security architecture.

Your REDCap study project will have an API you can activate to programmatically
access your study data. The issue is that REDCap only gives you one security token per user of 
your project that can be used to access your entire project. If a bad actor were to compromise your site and get a hold of your
token, they would have complete access to all your REDCap data.

Our solution uses a secure middleware server with:
1. Email-based filtering that ensures patients can only access their own data
2. JWT token authentication for secure sessions
3. Multiple layers of verification
4. The REDCap API token is never exposed to the client

A diagram of the information flow is shown below:

![security overview](images/security_overview.png)
![architecture overview](images/architecture_overview.png)

### Configuration

The Middleware Server code is located in the **Secure Middleware** folder (or **Middleman Server** folder if using original naming).

In the **config.json** file, add your institution's REDCap URL and 
add your study project's API token, along with other required settings:

```json
{
  "redcap_url": "https://your-redcap-instance.org/api/",
  "redcap_api_token": "YOUR_REDCAP_API_TOKEN",
  "jwt_secret": "GENERATE_A_SECURE_RANDOM_STRING",
  "wordpress_url": "https://your-wordpress-site.com",
  "allowed_origins": ["https://your-wordpress-site.com"]
}
```

The middleware is designed to filter data by email address. Make sure your REDCap project has an email field that can be used to identify patients.

### Activating the middleware server

Upload the **Secure Middleware** folder to a server with appropriate security settings. It's recommended to:
1. Use IP restrictions to only accept connections from your WordPress server
2. Use HTTPS for all connections
3. Keep your config.json file secure and not web-accessible

To start the middleware:

```bash
# Install dependencies
pip install flask requests pyjwt

# For development
python secure-patient-middleware.py

# For production
gunicorn --bind 0.0.0.0:5000 secure-patient-middleware:app
```

## Security Model

The security model ensures patients can only access their own data through:

1. **Authentication**: Patients log in through WordPress
2. **Token-Based Sessions**: Secure JWT tokens manage sessions
3. **Email Filtering**: All REDCap queries are filtered by the patient's email
4. **Secondary Verification**: All returned data is double-checked to verify it belongs to the patient

## Data Mapping

The wp_redcap table maps WordPress user emails to REDCap record IDs:

```
+------------------+-------------+
| email            | record_id   |
+------------------+-------------+
| patient1@test.com| RECORD-001  |
| patient2@test.com| RECORD-002  |
+------------------+-------------+
```

## Troubleshooting

If patients cannot access their data:
1. Verify their WordPress email matches their REDCap email
2. Check the wp_redcap table mapping
3. Check middleware logs for errors
4. Verify your REDCap project has the necessary email field

For more detailed debugging:
1. In the WordPress admin, go to Settings > REDCap Portal
2. Enable "Show Debug Info" for administrators
3. Check the debug section when viewing the portal

## Security Best Practices

1. Use HTTPS for all connections
2. Regularly update both WordPress and the middleware
3. Use strong passwords and consider two-factor authentication
4. Regularly audit access logs
5. Consider IP restrictions for the middleware server

For any questions, please contact your REDCap administrator or refer to the detailed implementation guide.
