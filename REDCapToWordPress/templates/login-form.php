<?php
/**
 * REDCap Patient Portal Login Form Template
 * 
 * Displays a login form that authenticates through WordPress
 * but securely connects to REDCap data.
 */

// Prevent direct access
if (!defined('WPINC')) {
    die;
}

// Get redirect URL from shortcode attributes
$redirect_url = !empty($atts['redirect_url']) ? esc_url($atts['redirect_url']) : '';
?>

<div class="redcap-portal-container">
    <div id="redcap-login-container">
        <h2 class="redcap-form-title"><?php echo esc_html__('Access Your Health Data', 'redcap-patient-portal'); ?></h2>
        
        <div id="redcap-login-error" class="redcap-error-message" style="display: none;"></div>
        <div id="redcap-session-expired-alert" class="redcap-warning-message" style="display: none;">
            <?php echo esc_html__('Your session has expired. Please log in again.', 'redcap-patient-portal'); ?>
        </div>
        
        <form id="redcap-login-form" class="redcap-form">
            <div class="redcap-form-group">
                <label for="redcap-username"><?php echo esc_html__('Username', 'redcap-patient-portal'); ?></label>
                <input type="text" id="redcap-username" name="username" required>
            </div>
            
            <div class="redcap-form-group">
                <label for="redcap-password"><?php echo esc_html__('Password', 'redcap-patient-portal'); ?></label>
                <input type="password" id="redcap-password" name="password" required>
            </div>
            
            <div class="redcap-form-actions">
                <button type="submit" class="redcap-button redcap-primary-button">
                    <?php echo esc_html__('Log In', 'redcap-patient-portal'); ?>
                </button>
                
                <?php if (get_option('users_can_register')): ?>
                <a href="<?php echo esc_url(wp_registration_url()); ?>" class="redcap-register-link">
                    <?php echo esc_html__('Register', 'redcap-patient-portal'); ?>
                </a>
                <?php endif; ?>
                
                <a href="<?php echo esc_url(wp_lostpassword_url()); ?>" class="redcap-forgot-password-link">
                    <?php echo esc_html__('Forgot Password?', 'redcap-patient-portal'); ?>
                </a>
            </div>
            
            <?php if (!empty($redirect_url)): ?>
            <input type="hidden" name="redirect_url" value="<?php echo esc_attr($redirect_url); ?>">
            <?php endif; ?>
            
            <?php wp_nonce_field('redcap_portal_login_nonce', 'redcap_login_nonce'); ?>
        </form>
        
        <div class="redcap-login-loading" style="display: none;">
            <div class="redcap-spinner"></div>
            <p><?php echo esc_html__('Logging in...', 'redcap-patient-portal'); ?></p>
        </div>
    </div>
</div>

<script type="text/javascript">
jQuery(document).ready(function($) {
    // Check if already authenticated
    const redcapAuth = new REDCapAuth(redcapPortal.middlewareUrl);
    
    if (redcapAuth.isAuthenticated()) {
        // If already logged in and there's a redirect URL, go there
        const redirectUrl = $('input[name="redirect_url"]').val();
        if (redirectUrl) {
            window.location.href = redirectUrl;
        } else {
            // Otherwise show a logged-in message
            $('#redcap-login-container').html(
                '<div class="redcap-success-message">' + 
                '<?php echo esc_js(__('You are already logged in.', 'redcap-patient-portal')); ?>' +
                '</div>'
            );
        }
    }
    
    // Login form submission
    $('#redcap-login-form').on('submit', async function(e) {
        e.preventDefault();
        
        // Show loading state
        $('.redcap-login-loading').show();
        $('#redcap-login-form').hide();
        $('#redcap-login-error').hide();
        
        const username = $('#redcap-username').val();
        const password = $('#redcap-password').val();
        
        try {
            const result = await redcapAuth.login(username, password);
            
            if (result.success) {
                // Successful login
                const redirectUrl = $('input[name="redirect_url"]').val();
                if (redirectUrl) {
                    window.location.href = redirectUrl;
                } else {
                    // Show success message if no redirect
                    $('#redcap-login-container').html(
                        '<div class="redcap-success-message">' +
                        '<?php echo esc_js(__('Login successful! You can now access your data.', 'redcap-patient-portal')); ?>' +
                        '</div>'
                    );
                }
            } else {
                // Failed login with specific error handling
                $('.redcap-login-loading').hide();
                $('#redcap-login-form').show();
                
                let errorMessage = result.error || '<?php echo esc_js(__('Login failed. Please check your credentials.', 'redcap-patient-portal')); ?>';
                
                // Custom error messages for specific error types
                if (result.errorType === 'network') {
                    errorMessage = '<?php echo esc_js(__('Connection error. Please check your internet connection and try again.', 'redcap-patient-portal')); ?>';
                }
                
                $('#redcap-login-error').show().text(errorMessage);
            }
        } catch (error) {
            // Error during login
            $('.redcap-login-loading').hide();
            $('#redcap-login-form').show();
            $('#redcap-login-error').show().text(error.message || '<?php echo esc_js(__('An error occurred during login. Please try again.', 'redcap-patient-portal')); ?>');
        }
    });
});
</script>
