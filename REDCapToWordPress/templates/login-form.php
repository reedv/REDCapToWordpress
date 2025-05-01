<?php
/**
 * REDCap Patient Portal Login Form Template
 * 
 * Redirects to WordPress login and then back to portal with verification
 */

// Prevent direct access
if (!defined('WPINC')) {
    die;
}

// Get redirect URL from shortcode attributes
$redirect_url = !empty($atts['redirect_url']) ? esc_url($atts['redirect_url']) : '';
$current_url = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http") . "://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]";  // TODO: Force to https protocol prefix?

// Check if user is already logged in to WordPress
if (is_user_logged_in()) {
    // User is logged in, check for REDCap verification endpoint
    $verification_nonce = wp_create_nonce('redcap_verify_wp_session');
    
    // Redirect to portal if already logged in to WP
    if (!empty($redirect_url)) {
        ?>
        <div class="redcap-portal-container">
            <div id="redcap-login-container">
                <div class="redcap-success-message">
                    <?php echo esc_html__('You are already logged in. Verifying your REDCap access...', 'redcap-patient-portal'); ?>
                </div>
            </div>
        </div>
        
        <script type="text/javascript">
        jQuery(document).ready(function($) {
            // Verify this WordPress session has REDCap access
            $.ajax({
                url: redcapPortal.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'redcap_verify_wp_session',
                    nonce: '<?php echo $verification_nonce; ?>'
                },
                success: function(response) {
                    if (response.success) {
                        // Initialize auth object with the token
                        const redcapAuth = new REDCapAuth(redcapPortal.middlewareUrl);
                        redcapAuth.saveSession(response.data.token, response.data.expiresIn);
                        window.location.href = '<?php echo $redirect_url; ?>';
                    } else {
                        $('#redcap-login-container').html(
                            '<div class="redcap-error-message">' + 
                            (response.data.message || '<?php echo esc_js(__('Unable to verify REDCap access', 'redcap-patient-portal')); ?>') +
                            '</div>'
                        );
                    }
                },
                error: function() {
                    $('#redcap-login-container').html(
                        '<div class="redcap-error-message">' + 
                        '<?php echo esc_js(__('Error verifying REDCap access', 'redcap-patient-portal')); ?>' +
                        '</div>'
                    );
                }
            });
        });
        </script>
        <?php
    }
} else {
    // User is not logged in, redirect to WordPress login
    $login_url = wp_login_url($current_url);
    ?>
    <div class="redcap-portal-container">
        <div id="redcap-login-container">
            <h2 class="redcap-form-title"><?php echo esc_html__('Access Your Health Data', 'redcap-patient-portal'); ?></h2>
            
            <div class="redcap-login-instructions">
                <p><?php echo esc_html__('You need to log in to access your secure health data portal.', 'redcap-patient-portal'); ?></p>
            </div>
            
            <div class="redcap-form-actions">
                <a href="<?php echo esc_url($login_url); ?>" class="redcap-button redcap-primary-button">
                    <?php echo esc_html__('Log In with WordPress', 'redcap-patient-portal'); ?>
                </a>
                
                <?php if (get_option('users_can_register')): ?>
                <a href="<?php echo esc_url(wp_registration_url()); ?>" class="redcap-register-link">
                    <?php echo esc_html__('Register', 'redcap-patient-portal'); ?>
                </a>
                <?php endif; ?>
            </div>
        </div>
    </div>
    <?php
}
?>
