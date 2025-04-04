<?php
/**
 * REDCap Patient Portal Self-Registration Form Template
 * 
 * Allows study participants to register for a WordPress account
 * after verification against REDCap records
 */

// Prevent direct access
if (!defined('WPINC')) {
    die;
}

// Shortcode attributes
$redirect_after_registration = !empty($atts['redirect']) ? esc_url($atts['redirect']) : '';
?>

<div class="redcap-portal-container">
    <div id="redcap-registration-container">
        <h2 class="redcap-form-title"><?php echo esc_html__('Study Participant Registration', 'redcap-patient-portal'); ?></h2>
        
        <div class="redcap-registration-instructions">
            <p><?php echo esc_html__('Please enter the email address and name you provided when participating in our study. This information will be verified before your account is created.', 'redcap-patient-portal'); ?></p>
        </div>
        
        <div id="redcap-registration-error" class="redcap-error-message" style="display: none;"></div>
        <div id="redcap-registration-success" class="redcap-success-message" style="display: none;"></div>
        
        <form id="redcap-participant-registration-form" class="redcap-form">
            <div class="redcap-form-group">
                <label for="redcap-reg-email"><?php echo esc_html__('Email Address', 'redcap-patient-portal'); ?></label>
                <input type="email" id="redcap-reg-email" name="email" required>
                <small><?php echo esc_html__('The email you used in the study', 'redcap-patient-portal'); ?></small>
            </div>
            
            <div class="redcap-form-group">
                <label for="redcap-reg-first-name"><?php echo esc_html__('Participant First Name', 'redcap-patient-portal'); ?></label>
                <input type="text" id="redcap-reg-first-name" name="first_name" required>
                <small><?php echo esc_html__('As provided in the study', 'redcap-patient-portal'); ?></small>
            </div>
            
            <div class="redcap-form-group">
                <label for="redcap-reg-last-name"><?php echo esc_html__('Participant Last Name', 'redcap-patient-portal'); ?></label>
                <input type="text" id="redcap-reg-last-name" name="last_name" required>
                <small><?php echo esc_html__('As provided in the study', 'redcap-patient-portal'); ?></small>
            </div>
            
            <div class="redcap-form-group">
                <label for="redcap-reg-username"><?php echo esc_html__('Username', 'redcap-patient-portal'); ?></label>
                <input type="text" id="redcap-reg-username" name="username" required>
                <small><?php echo esc_html__('Choose a username for this site', 'redcap-patient-portal'); ?></small>
            </div>
            
            <div class="redcap-form-actions">
                <button type="submit" class="redcap-button redcap-primary-button">
                    <?php echo esc_html__('Register', 'redcap-patient-portal'); ?>
                </button>
                
                <a href="<?php echo esc_url(wp_login_url()); ?>" class="redcap-login-link">
                    <?php echo esc_html__('Already registered? Log In', 'redcap-patient-portal'); ?>
                </a>
            </div>
            
            <?php if (!empty($redirect_after_registration)): ?>
            <input type="hidden" name="redirect_url" value="<?php echo esc_attr($redirect_after_registration); ?>">
            <?php endif; ?>
            
            <?php wp_nonce_field('redcap_participant_registration_nonce', 'redcap_reg_nonce'); ?>
        </form>
        
        <div class="redcap-registration-loading" style="display: none;">
            <div class="redcap-spinner"></div>
            <p><?php echo esc_html__('Verifying your information...', 'redcap-patient-portal'); ?></p>
        </div>
    </div>
</div>

<script type="text/javascript">
jQuery(document).ready(function($) {
    $('#redcap-participant-registration-form').on('submit', async function(e) {
        e.preventDefault();
        
        // Show loading state
        $('.redcap-registration-loading').show();
        $('#redcap-participant-registration-form').hide();
        $('#redcap-registration-error').hide();
        $('#redcap-registration-success').hide();
        
        const formData = {
            email: $('#redcap-reg-email').val().trim(),
            first_name: $('#redcap-reg-first-name').val().trim(),
            last_name: $('#redcap-reg-last-name').val().trim(),
            username: $('#redcap-reg-username').val().trim(),
            nonce: $('#redcap_reg_nonce').val(),
            action: 'redcap_verify_and_register',
            redirect_url: $('input[name="redirect_url"]').val() || ''
        };
        
        try {
            const response = await $.ajax({
                url: redcapPortal.ajaxUrl,
                type: 'POST',
                data: formData
            });
            
            $('.redcap-registration-loading').hide();
            
            if (response.success) {
                // Registration successful
                $('#redcap-registration-success').html(response.data.message).show();
                
                // Redirect if specified
                if (response.data.redirect) {
                    setTimeout(function() {
                        window.location.href = response.data.redirect;
                    }, 3000); // Redirect after 3 seconds
                }
            } else {
                // Registration failed
                $('#redcap-participant-registration-form').show();
                $('#redcap-registration-error').html(response.data.message).show();
            }
        } catch (error) {
            $('.redcap-registration-loading').hide();
            $('#redcap-participant-registration-form').show();
            $('#redcap-registration-error').html('An error occurred during registration. Please try again.').show();
            console.error('Registration error:', error);
        }
    });
});
</script>