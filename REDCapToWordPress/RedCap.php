<?php
/**
 * Plugin Name: REDCap Patient Portal Connector
 * Description: Securely connects WordPress users to their REDCap data through a middleware service
 * Version: 1.0.0
 * Author: Your Name
 * Text Domain: redcap-patient-portal
 */

// If this file is called directly, abort.
if (!defined('WPINC')) {
    die;
}

// Define plugin constants
define('REDCAP_PORTAL_VERSION', '1.0.0');
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
        // Load settings
        $this->load_settings();
        
        // Register activation/deactivation hooks
        register_activation_hook(__FILE__, array($this, 'activate'));
        register_deactivation_hook(__FILE__, array($this, 'deactivate'));
        
        // Add shortcodes
        add_shortcode('redcap_portal', array($this, 'portal_shortcode'));
        add_shortcode('redcap_login', array($this, 'login_shortcode'));
        
        // Enqueue scripts and styles
        add_action('wp_enqueue_scripts', array($this, 'enqueue_scripts'));
        
        // Add AJAX handlers
        add_action('wp_ajax_redcap_verify_token', array($this, 'ajax_verify_token'));
        add_action('wp_ajax_nopriv_redcap_verify_token', array($this, 'ajax_verify_token'));
        
        // Add settings page
        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('admin_init', array($this, 'register_settings'));
    }
    
    /**
     * Load plugin settings
     */
    private function load_settings() {
        $options = get_option('redcap_portal_settings');
        $this->middleware_url = isset($options['middleware_url']) ? 
                                 esc_url_raw($options['middleware_url']) : 
                                 'http://localhost:5000';
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
        // Only enqueue on pages that use our shortcodes
        global $post;
        if (is_a($post, 'WP_Post') && 
            (has_shortcode($post->post_content, 'redcap_portal') || 
             has_shortcode($post->post_content, 'redcap_login'))) {
            
            // Enqueue the auth and data-access JS
            wp_enqueue_script(
                'redcap-auth',
                REDCAP_PORTAL_URL . 'js/auth.js',
                array('jquery'),
                REDCAP_PORTAL_VERSION,
                true
            );
            
            wp_enqueue_script(
                'redcap-data',
                REDCAP_PORTAL_URL . 'js/data-access.js',
                array('jquery', 'redcap-auth'),
                REDCAP_PORTAL_VERSION,
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
                REDCAP_PORTAL_VERSION
            );
        }
    }
    
    /**
     * AJAX handler to verify token and get patient info
     */
    public function ajax_verify_token() {
        check_ajax_referer('redcap_portal_nonce', 'nonce');
        
        $token = isset($_POST['token']) ? sanitize_text_field($_POST['token']) : '';
        
        if (empty($token)) {
            wp_send_json_error(array('message' => 'No token provided'));
            return;
        }
        
        // Verify token with middleware
        $response = wp_remote_post($this->middleware_url . '/auth/verify', array(
            'body' => json_encode(array('token' => $token)),
            'headers' => array('Content-Type' => 'application/json'),
            'timeout' => 15
        ));
        
        if (is_wp_error($response)) {
            wp_send_json_error(array('message' => 'Error contacting middleware server'));
            return;
        }
        
        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);
        
        if (isset($data['success']) && $data['success'] === true) {
            wp_send_json_success($data);
        } else {
            wp_send_json_error(array('message' => 'Invalid token'));
        }
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
