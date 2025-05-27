<?php
/**
 * Plugin Name: REDCap Patient Portal Connector
 * Description: Securely connects WordPress users to their REDCap data through a middleware service
 * Version: 1.1.0
 * Author: Your Name
 * Text Domain: redcap-patient-portal
 */

// If this file is called directly, abort.
if (!defined('WPINC')) {
    die;
}

// Define plugin constants
define('REDCAP_PORTAL_VERSION', '1.1.0');
define('REDCAP_PORTAL_PATH', plugin_dir_path(__FILE__));
define('REDCAP_PORTAL_URL', plugin_dir_url(__FILE__));

class REDCap_Patient_Portal {
    /**
     * Middleware server URL
     */
    private $middleware_url;
    
    /**
     * Plugin initialization
     */
    public function __construct() {
        // Force HTTPS for all requests
        if (!is_ssl() && !WP_DEBUG) {
            if (isset($_SERVER['HTTP_HOST']) && isset($_SERVER['REQUEST_URI'])) {
                wp_redirect('https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'], 301);
                exit;
            }
        }

        // Load settings
        $this->load_settings();
        
        // Register activation/deactivation hooks
        register_activation_hook(__FILE__, array($this, 'activate'));
        register_deactivation_hook(__FILE__, array($this, 'deactivate'));
        
        // Add shortcodes
        add_shortcode('redcap_portal', array($this, 'portal_shortcode'));
        add_shortcode('redcap_login', array($this, 'login_shortcode'));
        add_shortcode('redcap_registration', array($this, 'registration_shortcode'));
        
        // Enqueue scripts and styles
        add_action('wp_enqueue_scripts', array($this, 'enqueue_scripts'));
        
        // Add settings page
        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('admin_init', array($this, 'register_settings'));

        // // Add AJAX handlers for verifying middleware access token
        // add_action('wp_ajax_redcap_verify_token', array($this, 'ajax_verify_token'));
        // add_action('wp_ajax_nopriv_redcap_verify_token', array($this, 'ajax_verify_token'));

        // Add AJAX handler for middlware token verification
        add_action('wp_ajax_redcap_verify_token_with_fingerprint', array($this, 'ajax_verify_token_with_fingerprint'));
        add_action('wp_ajax_nopriv_redcap_verify_token_with_fingerprint', array($this, 'ajax_verify_token_with_fingerprint'));

        add_action('wp_ajax_redcap_check_token_cookie', array($this, 'ajax_check_token_cookie'));
        add_action('wp_ajax_nopriv_redcap_check_token_cookie', array($this, 'ajax_check_token_cookie'));
        add_action('wp_ajax_redcap_clear_token_cookie', array($this, 'ajax_clear_token_cookie'));
        add_action('wp_ajax_nopriv_redcap_clear_token_cookie', array($this, 'ajax_clear_token_cookie'));

        // Add the AJAX handler for user self-registration
        add_action('wp_ajax_nopriv_redcap_verify_and_register', array($this, 'ajax_verify_and_register'));
        add_action('wp_ajax_redcap_verify_and_register', array($this, 'ajax_verify_and_register'));

        // Add AJAX handler for WordPress session verification
        add_action('wp_ajax_redcap_verify_wp_session', array($this, 'ajax_verify_wp_session'));
        add_action('wp_ajax_nopriv_redcap_verify_wp_session', array($this, 'ajax_verify_wp_session'));

        add_action('wp_ajax_redcap_get_survey_metadata', array($this, 'ajax_get_survey_metadata'));
        add_action('wp_ajax_redcap_get_survey_results', array($this, 'ajax_get_survey_results'));
        add_action('wp_ajax_redcap_get_patient_data', array($this, 'ajax_get_patient_data'));

        // Add AJAX handler for file downloads
        // Disabled for security purposes, see issue #50
        // add_action('wp_ajax_redcap_get_file_download', array($this, 'ajax_get_file_download'));

    }

    /**
     * Diagnostic function to log all available IP headers
     */
    private function log_ip_diagnostics($context = '') {
        $ip_headers = [
            'REMOTE_ADDR' => $_SERVER['REMOTE_ADDR'] ?? 'not set',
            'HTTP_CF_CONNECTING_IP' => $_SERVER['HTTP_CF_CONNECTING_IP'] ?? 'not set',
            'HTTP_X_FORWARDED_FOR' => $_SERVER['HTTP_X_FORWARDED_FOR'] ?? 'not set',
            'HTTP_X_REAL_IP' => $_SERVER['HTTP_X_REAL_IP'] ?? 'not set',
            'HTTP_CLIENT_IP' => $_SERVER['HTTP_CLIENT_IP'] ?? 'not set',
            'HTTP_X_FORWARDED' => $_SERVER['HTTP_X_FORWARDED'] ?? 'not set',
            'HTTP_FORWARDED_FOR' => $_SERVER['HTTP_FORWARDED_FOR'] ?? 'not set',
            'HTTP_FORWARDED' => $_SERVER['HTTP_FORWARDED'] ?? 'not set'
        ];
        
        error_log("REDCap Portal IP Diagnostics - Context: $context");
        foreach ($ip_headers as $header => $value) {
            error_log("  $header: $value");
        }
        error_log("  User-Agent: " . ($_SERVER['HTTP_USER_AGENT'] ?? 'not set'));
        error_log("---");
    }

    /**
     * Get the real client IP address, accounting for Cloudflare proxy
     * 
     * @return string The real client IP address
     */
    private function get_real_client_ip() {
        // Cloudflare always provides the original client IP in this header
        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            // Validate it's a valid IP address
            $cf_ip = $_SERVER['HTTP_CF_CONNECTING_IP'];
            if (filter_var($cf_ip, FILTER_VALIDATE_IP)) {
                return $cf_ip;
            }
        }
        
        // Fallback to REMOTE_ADDR if CF header missing (should not happen with Cloudflare)
        return $_SERVER['REMOTE_ADDR'];
    }

    /**
     * Handle middleware response consistently
     */
    private function handle_middleware_response($response) {
        if (is_wp_error($response)) {
            wp_send_json_error(array(
                'message' => 'Error contacting middleware server',
                'error' => 'server_connection'
            ));
            return;
        }
        
        $status_code = wp_remote_retrieve_response_code($response);
        $body = wp_remote_retrieve_body($response);
        
        if ($status_code === 200) {
            wp_send_json_success(json_decode($body, true));
        } else {
            $error_data = json_decode($body, true);
            wp_send_json_error(array(
                'message' => $error_data['message'] ?? 'Error accessing data',
                'error' => $error_data['error'] ?? 'api_error'
            ));
        }
    }
    
    /**
     * Load plugin settings
     */
    private function load_settings() {
        $options = get_option('redcap_portal_settings');
        $this->middleware_url = isset($options['middleware_url']) ? 
                                 esc_url_raw($options['middleware_url']) : 
                                 'http://localhost:5000';
        $this->middleware_api_key = isset($options['middleware_api_key']) ?
                                $options['middleware_api_key'] :
                                '';
    }
    
    /**
     * Plugin activation
     */
    public function activate() {
        // Check for existing wp_redcap table (from original plugin)
        global $wpdb;
        $table_name = $wpdb->prefix . "redcap";
        
        if($wpdb->get_var("SHOW TABLES LIKE '$table_name'") != $table_name) {
            // Create the table if it doesn't exist
            $charset_collate = $wpdb->get_charset_collate();
            
            $sql = "CREATE TABLE `$table_name` (
                `email` VARCHAR(200) NOT NULL,
                `record_id` TEXT NOT NULL,
                PRIMARY KEY (`email`)
            ) $charset_collate;";
            
            require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
            dbDelta($sql);
        }
        
        // Create default settings
        $default_settings = array(
            'middleware_url' => 'http://localhost:5000',
            'middleware_api_key' => '',  // Add default for API key
            'show_debug_info' => 'no'
        );
        
        add_option('redcap_portal_settings', $default_settings);
    }
    
    /**
     * Plugin deactivation
     */
    public function deactivate() {
        // Don't delete the table on deactivation - keep the data
    }
    
    /**
     * Enqueue necessary scripts and styles
     */
    public function enqueue_scripts() {
        // Only enqueue on pages that use our shortcodes (shortcodes not enqueued here will have "jQuery not defined" issues)
        global $post;
        if (is_a($post, 'WP_Post') && 
            (has_shortcode($post->post_content, 'redcap_portal') || 
             has_shortcode($post->post_content, 'redcap_login') ||
             has_shortcode($post->post_content, 'redcap_registration'))) {
            
            // Enqueue the auth and data-access JS
            wp_enqueue_script(
                'redcap-auth',
                REDCAP_PORTAL_URL . 'js/auth.js',
                array('jquery'),
                REDCAP_PORTAL_VERSION . '.' . time(), // Force cache refresh with timestamp, wp site was caching this in internal asset cache and not using updated versions even after installing new plugin zip or clearing browser cache
                true
            );
            
            wp_enqueue_script(
                'redcap-data',
                REDCAP_PORTAL_URL . 'js/data-access.js',
                array('jquery', 'redcap-auth'),
                REDCAP_PORTAL_VERSION . '.' . time(), // Force cache refresh with timestamp, wp site was caching this in internal asset cache and not using updated versions even after installing new plugin zip or clearing browser cache
                true
            );
            
            // Localize for JavaScript use
            wp_localize_script('redcap-auth', 'redcapPortal', array(
                'ajaxUrl' => admin_url('admin-ajax.php'),
                'middlewareUrl' => $this->middleware_url,
                'nonce' => wp_create_nonce('redcap_portal_nonce'),
            ));
            
            // Enqueue our styles
            wp_enqueue_style(
                'redcap-portal-styles',
                REDCAP_PORTAL_URL . 'css/redcap-portal.css',
                array(),
                REDCAP_PORTAL_VERSION . '.' . time(), // Force cache refresh with timestamp, wp site was caching this in internal asset cache and not using updated versions even after installing new plugin zip or clearing browser cache
            );
        }
    }

    /**
     * AJAX handler to verify self-registering participant and register them in the wp site
     */
    public function ajax_verify_and_register() {
        check_ajax_referer('redcap_participant_registration_nonce', 'nonce');

        $this->log_ip_diagnostics('verify_and_register');
        
        // Validate input fields
        $email = isset($_POST['email']) ? sanitize_email($_POST['email']) : '';
        $first_name = isset($_POST['first_name']) ? sanitize_text_field($_POST['first_name']) : '';
        $last_name = isset($_POST['last_name']) ? sanitize_text_field($_POST['last_name']) : '';
        $username = isset($_POST['username']) ? sanitize_user($_POST['username']) : '';
        $redirect_url = isset($_POST['redirect_url']) ? esc_url_raw($_POST['redirect_url']) : '';
        
        // Check for required fields
        if (empty($email) || empty($first_name) || empty($last_name) || empty($username)) {
            wp_send_json_error(array(
                'message' => __('All fields are required.', 'redcap-patient-portal')
            ));
            return;
        }
        
        // Check if username is valid
        if (!validate_username($username)) {
            wp_send_json_error(array(
                'message' => __('Invalid username. Please choose a different one.', 'redcap-patient-portal')
            ));
            return;
        }
        
        // Check if username already exists
        if (username_exists($username)) {
            wp_send_json_error(array(
                'message' => __('This username is already taken. Please choose a different one.', 'redcap-patient-portal')
            ));
            return;
        }
        
        // Check if email already exists in WordPress
        if (email_exists($email)) {
            wp_send_json_error(array(
                'message' => __('An account with this email already exists. Please log in or reset your password.', 'redcap-patient-portal')
            ));
            return;
        }

        // Validate email format (defense in depth beyond sanitize_email)
        if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 254) {
            wp_send_json_error(array(
                'message' => __('Please enter a valid email address.', 'redcap-patient-portal')
            ));
            return;
        }
        
        // Validate name fields - only letters, spaces, hyphens, apostrophes
        if (!preg_match('/^[a-zA-Z\s\-\']{1,50}$/', $first_name) || 
            !preg_match('/^[a-zA-Z\s\-\']{1,50}$/', $last_name)) {
            wp_send_json_error(array(
                'message' => __('Names can only contain letters, spaces, hyphens, and apostrophes (max 50 characters).', 'redcap-patient-portal')
            ));
            return;
        }
        
        // Username additional validation (WordPress sanitize_user is permissive)
        if (strlen($username) < 3 || strlen($username) > 20 || 
            !preg_match('/^[a-zA-Z0-9._-]+$/', $username)) {
            wp_send_json_error(array(
                'message' => __('Username must be 3-20 characters and contain only letters, numbers, periods, underscores, and hyphens.', 'redcap-patient-portal')
            ));
            return;
        }
        
        // Validate redirect URL is internal to prevent open redirects
        if (!empty($redirect_url)) {
            $parsed_url = parse_url($redirect_url);
            $site_url = parse_url(home_url());
            
            if (isset($parsed_url['host']) && $parsed_url['host'] !== $site_url['host']) {
                wp_send_json_error(array(
                    'message' => __('Invalid redirect URL.', 'redcap-patient-portal')
                ));
                return;
            }
        }
        
        // Include the middleware client function
        require_once(REDCAP_PORTAL_PATH . 'includes/redcap_api_to_flask.php');
        
        // Verify against REDCap via middleware
        $verification = verify_participant($email, $first_name, $last_name);
        
        if (!$verification['verified']) {
            wp_send_json_error(array(
                'message' => __('We could not verify your information against our study records. Please check that you entered the exact name and email used in the study.', 'redcap-patient-portal')
            ));
            return;
        }
        
        // At this point, the participant is verified!
        // Extract record_id from verification response
        $record_id = isset($verification['record_id']) ? sanitize_text_field($verification['record_id']) : '';
        
        if (empty($record_id)) {
            wp_send_json_error(array(
                'message' => __('Record ID is missing. Please contact support.', 'redcap-patient-portal')
            ));
            return;
        }
        
        // Generate random password
        $user_pass = wp_generate_password();
        
        // Create the user account
        $new_user_id = wp_insert_user(array(
            'user_login' => $username,
            'user_pass' => $user_pass,
            'user_email' => $email,
            'first_name' => $first_name,
            'last_name' => $last_name,
            'user_registered' => date('Y-m-d H:i:s'),
            'role' => 'subscriber'
        ));
        
        if (is_wp_error($new_user_id)) {
            wp_send_json_error(array(
                'message' => __('Error creating user account: ', 'redcap-patient-portal') . $new_user_id->get_error_message()
            ));
            return;
        }
        
        // Add user to the wp_redcap table
        insert_data_redcap($email, $record_id);
        
        // Send password setup email
        $user = get_user_by('id', $new_user_id);
        
        // Send verification email for password setup
        wp_new_user_notification($new_user_id, null, 'user');
        
        // Return success
        wp_send_json_success(array(
            'message' => __('Registration successful! Please check your email for instructions to set your password.', 'redcap-patient-portal'),
            'redirect' => $redirect_url
        ));
    }

    /**
     * AJAX handler to verify WordPress session and generate middleware token
     */
    public function ajax_verify_wp_session() {
        check_ajax_referer('redcap_verify_wp_session', 'nonce');

        $this->log_ip_diagnostics('verify_wp_session');
    
        // Check if user is logged in
        if (!is_user_logged_in()) {
            wp_send_json_error(array('message' => 'Not logged in'));
            return;
        }
        
        // Get current user
        $current_user = wp_get_current_user();
        $user_email = $current_user->user_email;
        
        if (empty($user_email)) {
            wp_send_json_error(array('message' => 'User has no email'));
            return;
        }
        
        // Verify REDCap record exists
        global $wpdb;
        $table_name = $wpdb->prefix . "redcap";
        
        $record = $wpdb->get_row($wpdb->prepare(
            "SELECT record_id FROM $table_name WHERE email = %s",
            $user_email
        ));
        
        if (!$record) {
            wp_send_json_error(array('message' => 'No associated REDCap record found'));
            return;
        }

        // Get API key from WordPress options
        $options = get_option('redcap_portal_settings');
        $api_key = isset($options['middleware_api_key']) && !empty($options['middleware_api_key']) 
            ? $options['middleware_api_key'] 
            : '';
        
        // If API key is not in WordPress options, fall back to config.ini
        if (empty($api_key)) {
            $config_path = REDCAP_PORTAL_PATH . 'config.ini';
            if (file_exists($config_path)) {
                $configs = parse_ini_file($config_path);
                $api_key = isset($configs['middleman_api_key']) ? $configs['middleman_api_key'] : '';
            }
        }
        
        // Capture client details for fingerprinting
        $client_ip = $this->get_real_client_ip();
        $client_ua = $_SERVER['HTTP_USER_AGENT'];
        
        // Generate token via middleware
        $response = wp_remote_post($this->middleware_url . '/auth/generate_token', array(
            'body' => json_encode(array('email' => $user_email)),
            'headers' => array(
                'Content-Type' => 'application/json',
                'X-API-KEY' => $api_key,
                'X-Original-Client-IP' => $client_ip,
                'X-Original-User-Agent' => $client_ua
            ),
            'timeout' => 15
        ));
        
        if (is_wp_error($response)) {
            $error_message = $response->get_error_message();
            error_log('Middleware connection error: ' . $error_message);
            wp_send_json_error(array(
                'message' => 'Error contacting middleware server: ' . $error_message,
                'error' => 'server_connection'
            ));
            return;
        }
        
        $status_code = wp_remote_retrieve_response_code($response);
        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);
        
        if ($status_code === 200 && isset($data['token'])) {
            // Set secure HttpOnly cookie with token
            $cookie_expiry = time() + ($data['expiresIn'] ?? 1800); // 30 minutes default
            $cookie_secure = is_ssl(); // Only send over HTTPS
            $cookie_domain = parse_url(home_url(), PHP_URL_HOST);
            $cookie_path = '/';
            $cookie_httponly = true;
            $cookie_samesite = 'Strict'; // Prevent CSRF attacks
            
            // Set the token cookie
            setcookie(
                'redcap_token',
                $data['token'],
                [
                    'expires' => $cookie_expiry,
                    'path' => $cookie_path,
                    'domain' => $cookie_domain,
                    'secure' => $cookie_secure,
                    'httponly' => $cookie_httponly,
                    'samesite' => $cookie_samesite
                ]
            );
            
            // Set a separate cookie for expiry time that JavaScript can access
            setcookie(
                'redcap_token_expiry',
                $cookie_expiry,
                [
                    'expires' => $cookie_expiry,
                    'path' => $cookie_path,
                    'domain' => $cookie_domain,
                    'secure' => $cookie_secure,
                    'httponly' => false, // JavaScript needs to check this
                    'samesite' => $cookie_samesite
                ]
            );
            
            wp_send_json_success(array(
                'message' => 'Authentication successful',
                'expiresIn' => $data['expiresIn'] ?? 1800
            ));
        } else {
            wp_send_json_error(array(
                'message' => isset($data['message']) ? $data['message'] : 'Error generating token',
                'error' => isset($data['error']) ? $data['error'] : 'unknown'
            ));
        }
    }

    /**
     * AJAX handler to verify token with original fingerprint and get patient user info
     */
    public function ajax_verify_token_with_fingerprint() {
        check_ajax_referer('redcap_portal_nonce', 'nonce');

        $this->log_ip_diagnostics('verify_token_with_fingerprint');
        
        $token = isset($_POST['token']) ? sanitize_text_field($_POST['token']) : '';
        
        if (empty($token)) {
            wp_send_json_error(array('message' => 'No token provided', 'error' => 'missing_token'));
            return;
        }
        
        // Capture client details for fingerprinting (same as in token generation)
        $client_ip = $this->get_real_client_ip();
        $client_ua = $_SERVER['HTTP_USER_AGENT'];
        
        // Verify token with middleware
        $response = wp_remote_post($this->middleware_url . '/auth/verify', array(
            'body' => json_encode(array('token' => $token)),
            'headers' => array(
                'Content-Type' => 'application/json',
                'X-Original-Client-IP' => $client_ip,
                'X-Original-User-Agent' => $client_ua
            ),
            'timeout' => 15
        ));
        
        if (is_wp_error($response)) {
            $error_message = $response->get_error_message();
            error_log('Middleware connection error: ' . $error_message);
            wp_send_json_error(array(
                'message' => 'Error contacting middleware server: ' . $error_message,
                'error' => 'server_connection'
            ));
            return;
        }
        
        $status_code = wp_remote_retrieve_response_code($response);
        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);
        
        if ($status_code === 200 && isset($data['success']) && $data['success'] === true) {
            wp_send_json_success($data);
        } else {
            // Pass along the specific error type from middleware
            $error_type = isset($data['error']) ? $data['error'] : 'invalid_token';
            $message = isset($data['message']) ? $data['message'] : 'Invalid token';
            
            wp_send_json_error(array(
                'message' => $message,
                'error' => $error_type
            ));
        }
    }

    /**
     * AJAX handler to check if token cookie exists and is valid
     */
    public function ajax_check_token_cookie() {
        check_ajax_referer('redcap_portal_nonce', 'nonce');

        $this->log_ip_diagnostics('check_token_cookie');
        
        // Check if token cookie exists
        if (!isset($_COOKIE['redcap_token']) || !isset($_COOKIE['redcap_token_expiry'])) {
            wp_send_json_error(array('message' => 'No token cookie found', 'error' => 'no_token'));
            return;
        }
        
        // Check if token is expired
        $expiry = intval($_COOKIE['redcap_token_expiry']);
        if ($expiry < time()) {
            wp_send_json_error(array('message' => 'Token expired', 'error' => 'token_expired'));
            return;
        }
        
        // Token exists and is not expired
        wp_send_json_success(array('valid' => true));
    }

    /**
     * AJAX handler to log out (clear the token cookie)
     */
    public function ajax_clear_token_cookie() {
        check_ajax_referer('redcap_portal_nonce', 'nonce');

        $this->log_ip_diagnostics('clear_token_cookie');
        
        
        $cookie_domain = parse_url(home_url(), PHP_URL_HOST);
        $cookie_path = '/';
        
        // Clear the token cookie
        setcookie('redcap_token', '', [
            'expires' => time() - 3600,
            'path' => $cookie_path,
            'domain' => $cookie_domain,
            'secure' => is_ssl(),
            'httponly' => true,
            'samesite' => 'Strict'
        ]);
        
        // Clear the expiry cookie
        setcookie('redcap_token_expiry', '', [
            'expires' => time() - 3600,
            'path' => $cookie_path,
            'domain' => $cookie_domain,
            'secure' => is_ssl(),
            'httponly' => false,
            'samesite' => 'Strict'
        ]);
        
        wp_send_json_success(array('message' => 'Logged out successfully'));
    }

    /**
     * AJAX handler to get survey metadata
     */
    public function ajax_get_survey_metadata() {
        check_ajax_referer('redcap_portal_nonce', 'nonce');

        $this->log_ip_diagnostics('get_survey_metadata');
        
        // Require authentication
        if (!is_user_logged_in()) {
            wp_send_json_error(array('message' => 'Not authenticated', 'error' => 'auth_required'));
            return;
        }
        
        $survey_name = isset($_POST['survey_name']) ? sanitize_text_field($_POST['survey_name']) : '';
        
        if (empty($survey_name)) {
            wp_send_json_error(array('message' => 'Missing required parameters', 'error' => 'invalid_request'));
            return;
        }
        
        // Check if token cookie exists
        if (!isset($_COOKIE['redcap_token'])) {
            wp_send_json_error(array('message' => 'Authentication required', 'error' => 'auth_required'));
            return;
        }
        
        // Capture client details for fingerprinting
        $client_ip = $this->get_real_client_ip();
        $client_ua = $_SERVER['HTTP_USER_AGENT'];
        
        // Forward request to middleware with token from cookie
        $response = wp_remote_get($this->middleware_url . '/patient/survey_metadata/' . $survey_name, array(
            'headers' => array(
                'Authorization' => 'Bearer ' . $_COOKIE['redcap_token'],
                'Content-Type' => 'application/json',
                'X-Original-Client-IP' => $client_ip,
                'X-Original-User-Agent' => $client_ua
            ),
            'timeout' => 15
        ));
        
        $this->handle_middleware_response($response);
    }

    /**
     * AJAX handler to get survey results
     */
    public function ajax_get_survey_results() {
        check_ajax_referer('redcap_portal_nonce', 'nonce');

        $this->log_ip_diagnostics('get_survey_results');
        
        
        // Require authentication
        if (!is_user_logged_in()) {
            wp_send_json_error(array('message' => 'Not authenticated', 'error' => 'auth_required'));
            return;
        }
        
        $survey_name = isset($_POST['survey_name']) ? sanitize_text_field($_POST['survey_name']) : '';
        
        if (empty($survey_name)) {
            wp_send_json_error(array('message' => 'Missing required parameters', 'error' => 'invalid_request'));
            return;
        }
        
        // Check if token cookie exists
        if (!isset($_COOKIE['redcap_token'])) {
            wp_send_json_error(array('message' => 'Authentication required', 'error' => 'auth_required'));
            return;
        }
        
        // Capture client details for fingerprinting
        $client_ip = $this->get_real_client_ip();
        $client_ua = $_SERVER['HTTP_USER_AGENT'];
        
        // Forward request to middleware with token from cookie
        $response = wp_remote_get($this->middleware_url . '/patient/surveys/' . $survey_name, array(
            'headers' => array(
                'Authorization' => 'Bearer ' . $_COOKIE['redcap_token'],
                'Content-Type' => 'application/json',
                'X-Original-Client-IP' => $client_ip,
                'X-Original-User-Agent' => $client_ua
            ),
            'timeout' => 15
        ));
        
        $this->handle_middleware_response($response);
    }

    /**
     * AJAX handler to get patient data
     */
    public function ajax_get_patient_data() {
        check_ajax_referer('redcap_portal_nonce', 'nonce');

        $this->log_ip_diagnostics('get_patient_data');
        
        
        // Verify user authentication status within WordPress
        if (!is_user_logged_in()) {
            wp_send_json_error(array('message' => 'Not authenticated', 'error' => 'auth_required'));
            return;
        }
        
        // Check if token cookie exists
        if (!isset($_COOKIE['redcap_token'])) {
            wp_send_json_error(array('message' => 'Authentication required', 'error' => 'auth_required'));
            return;
        }
        
        // Capture original client context for fingerprint verification
        $client_ip = $this->get_real_client_ip();
        $client_ua = $_SERVER['HTTP_USER_AGENT'];
        
        // Forward request to middleware with preserved client context
        $response = wp_remote_get($this->middleware_url . '/patient/data', array(
            'headers' => array(
                'Authorization' => 'Bearer ' . $_COOKIE['redcap_token'],
                'Content-Type' => 'application/json',
                'X-Original-Client-IP' => $client_ip,
                'X-Original-User-Agent' => $client_ua
            ),
            'timeout' => 15
        ));
        
        // Process the middleware response through the shared handler
        $this->handle_middleware_response($response);
    }

    /**
     * AJAX handler to proxy file downloads from middleware
     */
    // Disabled for security purposes, see issue #50
    // public function ajax_get_file_download() {
    //     check_ajax_referer('redcap_portal_nonce', 'nonce');
        
    //     // Require authentication
    //     if (!is_user_logged_in()) {
    //         wp_send_json_error(array('message' => 'Not authenticated', 'error' => 'auth_required'));
    //         return;
    //     }
        
    //     $record_id = isset($_GET['record_id']) ? sanitize_text_field($_GET['record_id']) : '';
    //     $field_name = isset($_GET['field_name']) ? sanitize_text_field($_GET['field_name']) : '';
        
    //     if (empty($record_id) || empty($field_name)) {
    //         wp_send_json_error(array('message' => 'Missing required parameters', 'error' => 'invalid_request'));
    //         return;
    //     }
        
    //     // Validate record_id format (assuming numeric)
    //     if (!preg_match('/^[a-zA-Z0-9_-]+$/', $record_id)) {
    //         wp_send_json_error(array('message' => 'Invalid record ID format', 'error' => 'invalid_request'));
    //         return;
    //     }
        
    //     // Validate field_name format
    //     if (!preg_match('/^[a-zA-Z0-9_]+$/', $field_name)) {
    //         wp_send_json_error(array('message' => 'Invalid field name format', 'error' => 'invalid_request'));
    //         return;
    //     }
        
    //     // Check if token cookie exists
    //     if (!isset($_COOKIE['redcap_token'])) {
    //         wp_send_json_error(array('message' => 'Authentication required', 'error' => 'auth_required'));
    //         return;
    //     }
        
    //     // Capture client details for fingerprinting
    //     $client_ip = $this->get_real_client_ip();
    //     $client_ua = $_SERVER['HTTP_USER_AGENT'];
        
    //     // Forward request to middleware with token from cookie
    //     $response = wp_remote_get($this->middleware_url . '/patient/file/' . $record_id . '/' . $field_name, array(
    //         'headers' => array(
    //             'Authorization' => 'Bearer ' . $_COOKIE['redcap_token'],
    //             'Content-Type' => 'application/json',
    //             'X-Original-Client-IP' => $client_ip,
    //             'X-Original-User-Agent' => $client_ua
    //         ),
    //         'timeout' => 30, // Longer timeout for file downloads
    //         'sslverify' => true
    //     ));
        
    //     if (is_wp_error($response)) {
    //         wp_send_json_error(array(
    //             'message' => 'Error contacting middleware server',
    //             'error' => 'server_connection'
    //         ));
    //         return;
    //     }
        
    //     $status_code = wp_remote_retrieve_response_code($response);
    //     $body = wp_remote_retrieve_body($response);
        
    //     if ($status_code === 200) {
    //         // Get content type and filename from middleware response
    //         $content_type = wp_remote_retrieve_header($response, 'Content-Type') ?: 'application/octet-stream';
    //         $content_disposition = wp_remote_retrieve_header($response, 'Content-Disposition');
            
    //         // Set appropriate headers for file download
    //         header('Content-Type: ' . $content_type);
    //         if ($content_disposition) {
    //             header('Content-Disposition: ' . $content_disposition);
    //         } else {
    //             header('Content-Disposition: attachment; filename="' . $field_name . '_file"');
    //         }
    //         header('Content-Length: ' . strlen($body));
            
    //         // Output the file content
    //         echo $body;
    //         exit; // Important: prevent WordPress from adding any additional output
    //     } else {
    //         $error_data = json_decode($body, true);
    //         wp_send_json_error(array(
    //             'message' => $error_data['message'] ?? 'Error downloading file',
    //             'error' => $error_data['error'] ?? 'download_error'
    //         ));
    //     }
    // }

    /**
     * Shortcode to display self-registration form
     * Usage: [redcap_registration redirect="/my-data"]
     */
    public function registration_shortcode($atts) {
        $atts = shortcode_atts(array(
            'redirect' => '',
        ), $atts, 'redcap_registration');
        
        ob_start();
        include(REDCAP_PORTAL_PATH . 'templates/participant-registration.php');
        return ob_get_clean();
    }
    
    /**
     * Login shortcode to display login form
     * Usage: [redcap_login redirect_url="/my-data"]
     */
    public function login_shortcode($atts) {
        $atts = shortcode_atts(array(
            'redirect_url' => '',
        ), $atts, 'redcap_login');
        
        ob_start();
        include(REDCAP_PORTAL_PATH . 'templates/login-form.php');
        return ob_get_clean();
    }
    
    /**
     * Portal shortcode to display patient data
     * Usage: [redcap_portal survey="medication_survey"]
     */
    public function portal_shortcode($atts) {
        $atts = shortcode_atts(array(
            'survey' => '',
            'show_profile' => 'yes',
        ), $atts, 'redcap_portal');
        
        // Check for URL parameter override
        if (isset($_GET['survey']) && !empty($_GET['survey'])) {
            $atts['survey'] = sanitize_text_field($_GET['survey']);
        }
        
        ob_start();
        include(REDCAP_PORTAL_PATH . 'templates/portal.php');
        return ob_get_clean();
    }
    
    /**
     * Add admin menu for settings
     */
    public function add_admin_menu() {
        add_options_page(
            'REDCap Patient Portal Settings',
            'REDCap Portal',
            'manage_options',
            'redcap-patient-portal',
            array($this, 'settings_page')
        );
    }
    
    /**
     * Register settings
     */
    public function register_settings() {
        register_setting('redcap_portal_settings_group', 'redcap_portal_settings');
        
        add_settings_section(
            'redcap_portal_main_section',
            'Connection Settings',
            array($this, 'settings_section_callback'),
            'redcap-patient-portal'
        );
        
        add_settings_field(
            'middleware_url',
            'Middleware URL',
            array($this, 'middleware_url_render'),
            'redcap-patient-portal',
            'redcap_portal_main_section'
        );

        add_settings_field(
            'middleman_api_key',
            'Middleware API key',
            array($this, 'middleware_api_key_render'),
            'redcap-patient-portal',
            'redcap_portal_main_section'
        );
        
        add_settings_field(
            'show_debug_info',
            'Show Debug Info',
            array($this, 'show_debug_info_render'),
            'redcap-patient-portal',
            'redcap_portal_main_section'
        );
    }
    
    /**
     * Settings section callback
     */
    public function settings_section_callback() {
        echo '<p>Configure the connection to your REDCap middleware server.</p>';
    }
    
    /**
     * Middleware URL setting field
     */
    public function middleware_url_render() {
        $options = get_option('redcap_portal_settings');
        $url = isset($options['middleware_url']) ? $options['middleware_url'] : '';
        ?>
        <input type='text' name='redcap_portal_settings[middleware_url]' 
               value='<?php echo esc_url($url); ?>' class="regular-text" 
               placeholder="http://localhost:5000">
        <p class="description">Enter the URL of your REDCap security middleware server</p>
        <?php
    }

    /**
     * Middleware API key setting field
     */
    public function middleware_api_key_render() {
        $options = get_option('redcap_portal_settings');
        $api_key = isset($options['middleware_api_key']) ? $options['middleware_api_key'] : '';
        ?>
        <input type='text' name='redcap_portal_settings[middleware_api_key]' 
               value='<?php echo esc_attr($api_key); ?>' class="regular-text">
        <p class="description">Enter the API key for your REDCap security middleware server (matches middleware WORDPRESS_API_KEY environment variable)</p>
        <?php
    }
    
    /**
     * Debug info setting field
     */
    public function show_debug_info_render() {
        $options = get_option('redcap_portal_settings');
        $show_debug = isset($options['show_debug_info']) ? $options['show_debug_info'] : 'no';
        ?>
        <select name='redcap_portal_settings[show_debug_info]'>
            <option value='no' <?php selected($show_debug, 'no'); ?>>No</option>
            <option value='yes' <?php selected($show_debug, 'yes'); ?>>Yes</option>
        </select>
        <p class="description">Show debugging information for administrators (not recommended for production)</p>
        <?php
    }
    
    /**
     * Settings page content
     */
    public function settings_page() {
        ?>
        <div class="wrap">
            <h1>REDCap Patient Portal Settings</h1>
            <form action='options.php' method='post'>
                <?php
                settings_fields('redcap_portal_settings_group');
                do_settings_sections('redcap-patient-portal');
                submit_button();
                ?>
            </form>
            
            <div class="card">
                <h2>Shortcode Usage</h2>
                <p><strong>[redcap_registration redirect="/my-data"]</strong> - Shortcode to display self-registration form</p>
                <p><strong>[redcap_login redirect_url="/my-data"]</strong> - Displays login form with optional redirect</p>
                <p><strong>[redcap_portal survey="medication_survey"]</strong> - Displays patient data with optional survey filter</p>
            </div>
            
            <div class="card">
                <h2>Security Information</h2>
                <p>This plugin connects to your REDCap data through a secure middleware server that enforces patient-level access controls.</p>
                <p>The REDCap API token is <strong>never</strong> exposed to the client browser.</p>
                <p>Each patient can only view their own data, filtered by their email address.</p>
            </div>
        </div>
        <?php
    }
}

// Initialize the plugin
$redcap_patient_portal = new REDCap_Patient_Portal();
