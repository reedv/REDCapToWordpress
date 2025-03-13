<?php
/**
 * REDCap Patient Portal Display Template
 * 
 * Displays patient data from REDCap in a secure manner,
 * ensuring patients only see their own data.
 */

// Prevent direct access
if (!defined('WPINC')) {
    die;
}

// Get attributes from shortcode
$survey = !empty($atts['survey']) ? sanitize_text_field($atts['survey']) : '';
$show_profile = !empty($atts['show_profile']) && $atts['show_profile'] === 'yes';

// Get settings
$options = get_option('redcap_portal_settings');
$show_debug = isset($options['show_debug_info']) && $options['show_debug_info'] === 'yes' && current_user_can('manage_options');
?>

<div class="redcap-portal-container">
    <div id="redcap-portal-content">
        <!-- Authentication check message will appear here if not logged in -->
    </div>
    
    <?php if ($show_profile): ?>
    <div id="redcap-patient-profile" class="redcap-portal-section" style="display: none;">
        <h2 class="redcap-section-title"><?php echo esc_html__('Your Profile', 'redcap-patient-portal'); ?></h2>
        <div class="redcap-profile-content">
            <!-- Profile content will be loaded here -->
            <div class="redcap-loading">
                <div class="redcap-spinner"></div>
                <p><?php echo esc_html__('Loading your profile...', 'redcap-patient-portal'); ?></p>
            </div>
        </div>
    </div>
    <?php endif; ?>
    
    <?php if (!empty($survey)): ?>
    <div id="redcap-survey-results" class="redcap-portal-section" style="display: none;">
        <h2 class="redcap-section-title"><?php echo esc_html(sprintf(__('%s Results', 'redcap-patient-portal'), ucwords(str_replace('_', ' ', $survey)))); ?></h2>
        <div class="redcap-survey-content">
            <!-- Survey content will be loaded here -->
            <div class="redcap-loading">
                <div class="redcap-spinner"></div>
                <p><?php echo esc_html__('Loading your data...', 'redcap-patient-portal'); ?></p>
            </div>
        </div>
    </div>
    <?php endif; ?>
    
    <div id="redcap-all-data" class="redcap-portal-section" style="display: none;">
        <h2 class="redcap-section-title"><?php echo esc_html__('Your Health Data', 'redcap-patient-portal'); ?></h2>
        <div class="redcap-data-content">
            <!-- All patient data will be loaded here -->
            <div class="redcap-loading">
                <div class="redcap-spinner"></div>
                <p><?php echo esc_html__('Loading your data...', 'redcap-patient-portal'); ?></p>
            </div>
        </div>
    </div>
    
    <div id="redcap-portal-actions" class="redcap-portal-section" style="display: none;">
        <button id="redcap-logout-button" class="redcap-button redcap-secondary-button">
            <?php echo esc_html__('Log Out', 'redcap-patient-portal'); ?>
        </button>
    </div>
    
    <?php if ($show_debug): ?>
    <div id="redcap-debug-info" class="redcap-portal-section redcap-debug-section">
        <h3 class="redcap-section-title"><?php echo esc_html__('Debug Information (Admin Only)', 'redcap-patient-portal'); ?></h3>
        <div class="redcap-debug-content">
            <p><strong>Shortcode Attributes:</strong></p>
            <ul>
                <li>Survey: <?php echo esc_html($survey ?: 'none'); ?></li>
                <li>Show Profile: <?php echo esc_html($show_profile ? 'yes' : 'no'); ?></li>
            </ul>
            <p><strong>Middleware URL:</strong> <?php echo esc_html($options['middleware_url'] ?? 'not set'); ?></p>
            <div id="redcap-debug-log"></div>
        </div>
    </div>
    <?php endif; ?>
</div>

<script type="text/javascript">
jQuery(document).ready(function($) {
    // Initialize authentication and data classes
    const redcapAuth = new REDCapAuth(redcapPortal.middlewareUrl);
    const redcapData = new REDCapPatientData(redcapAuth, redcapPortal.middlewareUrl);
    
    function debugLog(message) {
        <?php if ($show_debug): ?>
        $('#redcap-debug-log').append('<div class="debug-item">' + message + '</div>');
        console.log('REDCap Portal:', message);
        <?php endif; ?>
    }
    
    // Check authentication
    if (!redcapAuth.isAuthenticated()) {
        $('#redcap-portal-content').html(
            '<div class="redcap-error-message">' +
            '<?php echo esc_js(__('You need to log in to view your health data.', 'redcap-patient-portal')); ?>' +
            '</div>' +
            '<p><a href="<?php echo esc_js(site_url('/login')); ?>" class="redcap-button redcap-primary-button">' +
            '<?php echo esc_js(__('Log In', 'redcap-patient-portal')); ?>' +
            '</a></p>'
        );
        return;
    }
    
    // User is authenticated, show the portal sections
    $('#redcap-portal-content').html(
        '<div class="redcap-welcome-message">' +
        '<?php echo esc_js(__('Welcome to your secure health data portal.', 'redcap-patient-portal')); ?>' +
        '</div>'
    );
    
    <?php if ($show_profile): ?>
    $('#redcap-patient-profile').show();
    <?php endif; ?>
    
    <?php if (!empty($survey)): ?>
    $('#redcap-survey-results').show();
    <?php endif; ?>
    
    $('#redcap-all-data').show();
    $('#redcap-portal-actions').show();
    
    // Load patient profile if enabled
    <?php if ($show_profile): ?>
    (async function loadProfile() {
        try {
            debugLog('Loading patient profile...');
            const result = await redcapData.getPatientData();
            
            if (result.success && result.data && result.data.length > 0) {
                const profileData = result.data[0]; // First record contains basic info
                
                // Build profile HTML
                let profileHtml = '<div class="redcap-profile-details">';
                
                // Add name if available
                if (profileData.name_first || profileData.name_last) {
                    profileHtml += '<div class="redcap-profile-name">' + 
                        (profileData.name_first || '') + ' ' + (profileData.name_last || '') + 
                        '</div>';
                }
                
                // Add email
                if (profileData.email) {
                    profileHtml += '<div class="redcap-profile-field"><strong><?php echo esc_js(__('Email:', 'redcap-patient-portal')); ?></strong> ' + 
                        profileData.email + '</div>';
                }
                
                // Add other basic fields
                const basicFields = ['phone', 'dob', 'address', 'city', 'state', 'zip'];
                basicFields.forEach(field => {
                    if (profileData[field]) {
                        profileHtml += '<div class="redcap-profile-field"><strong>' + 
                            field.charAt(0).toUpperCase() + field.slice(1) + ':</strong> ' + 
                            profileData[field] + '</div>';
                    }
                });
                
                profileHtml += '</div>';
                
                // Update profile section
                $('.redcap-profile-content').html(profileHtml);
                debugLog('Profile loaded successfully');
            } else {
                // No data or error
                $('.redcap-profile-content').html(
                    '<div class="redcap-message">' +
                    (result.error || '<?php echo esc_js(__('No profile data available.', 'redcap-patient-portal')); ?>') +
                    '</div>'
                );
                debugLog('Profile load error: ' + (result.error || 'No data'));
            }
        } catch (error) {
            $('.redcap-profile-content').html(
                '<div class="redcap-error-message">' +
                '<?php echo esc_js(__('Error loading profile:', 'redcap-patient-portal')); ?> ' + 
                (error.message || 'Unknown error') +
                '</div>'
            );
            debugLog('Profile load exception: ' + error.message);
        }
    })();
    <?php endif; ?>
    
    // Load specific survey data if specified
    <?php if (!empty($survey)): ?>
    (async function loadSurvey() {
        try {
            debugLog('Loading survey: <?php echo esc_js($survey); ?>');
            const result = await redcapData.getSurveyResults('<?php echo esc_js($survey); ?>');
            
            if (result.success && result.data && result.data.length > 0) {
                let surveyHtml = '<div class="redcap-survey-results">';
                
                // Process survey data
                result.data.forEach(record => {
                    surveyHtml += '<div class="redcap-survey-record">';
                    
                    // Add survey completion date if available
                    if (record.survey_date || record.survey_timestamp || record.date) {
                        const dateField = record.survey_date || record.survey_timestamp || record.date;
                        surveyHtml += '<div class="redcap-record-date">' + 
                            '<?php echo esc_js(__('Date:', 'redcap-patient-portal')); ?> ' + dateField + 
                            '</div>';
                    }
                    
                    // Add survey fields (excluding system fields)
                    const systemFields = ['record_id', 'name_first', 'name_last', 'email', 'survey_date', 'survey_timestamp', 'date'];
                    
                    Object.entries(record).forEach(([key, value]) => {
                        if (!systemFields.includes(key) && value !== null && value !== '') {
                            // Format the field name for display
                            const fieldName = key.replace(/_/g, ' ')
                                .replace(/\b\w/g, letter => letter.toUpperCase());
                            
                            surveyHtml += '<div class="redcap-survey-field">' +
                                '<span class="redcap-field-name">' + fieldName + ':</span> ' +
                                '<span class="redcap-field-value">' + value + '</span>' +
                                '</div>';
                        }
                    });
                    
                    surveyHtml += '</div>';
                });
                
                surveyHtml += '</div>';
                
                // Update survey content
                $('.redcap-survey-content').html(surveyHtml);
                debugLog('Survey data loaded successfully');
            } else {
                // No data or error
                $('.redcap-survey-content').html(
                    '<div class="redcap-message">' +
                    (result.error || '<?php echo esc_js(__('No survey data available.', 'redcap-patient-portal')); ?>') +
                    '</div>'
                );
                debugLog('Survey load error: ' + (result.error || 'No data'));
            }
        } catch (error) {
            $('.redcap-survey-content').html(
                '<div class="redcap-error-message">' +
                '<?php echo esc_js(__('Error loading survey data:', 'redcap-patient-portal')); ?> ' + 
                (error.message || 'Unknown error') +
                '</div>'
            );
            debugLog('Survey load exception: ' + error.message);
        }
    })();
    <?php endif; ?>
    
    // Load all patient data
    (async function loadAllData() {
        try {
            debugLog('Loading all patient data...');
            const result = await redcapData.getPatientData();
            
            if (result.success && result.data && result.data.length > 0) {
                let dataHtml = '<div class="redcap-all-data-container">';
                
                // Group data by record/event if multiple records
                if (result.data.length > 1) {
                    dataHtml += '<div class="redcap-data-summary">' +
                        '<?php echo esc_js(__('Found', 'redcap-patient-portal')); ?> ' + 
                        result.data.length + ' <?php echo esc_js(__('records', 'redcap-patient-portal')); ?>' +
                        '</div>';
                    
                    // Create a table of records
                    dataHtml += '<table class="redcap-data-table">' +
                        '<thead><tr>' +
                        '<th><?php echo esc_js(__('Record', 'redcap-patient-portal')); ?></th>' +
                        '<th><?php echo esc_js(__('Date', 'redcap-patient-portal')); ?></th>' +
                        '<th><?php echo esc_js(__('Type', 'redcap-patient-portal')); ?></th>' +
                        '<th><?php echo esc_js(__('Details', 'redcap-patient-portal')); ?></th>' +
                        '</tr></thead><tbody>';
                    
                    result.data.forEach((record, index) => {
                        // Determine record type
                        let recordType = '<?php echo esc_js(__('Data', 'redcap-patient-portal')); ?>';
                        if (record.redcap_event_name) {
                            recordType = record.redcap_event_name.replace(/_/g, ' ');
                        } else if (record.survey_name || record.form_name) {
                            recordType = (record.survey_name || record.form_name).replace(/_/g, ' ');
                        }
                        
                        // Determine date
                        const dateField = record.date || record.survey_date || record.timestamp || '';
                        
                        dataHtml += '<tr class="redcap-data-row">' +
                            '<td>' + (record.record_id || (index + 1)) + '</td>' +
                            '<td>' + dateField + '</td>' +
                            '<td>' + recordType + '</td>' +
                            '<td><button class="redcap-view-details" data-record="' + index + '">' +
                            '<?php echo esc_js(__('View', 'redcap-patient-portal')); ?></button></td>' +
                            '</tr>';
                    });
                    
                    dataHtml += '</tbody></table>';
                    
                    // Add hidden detail views for each record
                    result.data.forEach((record, index) => {
                        dataHtml += '<div class="redcap-record-details" id="record-details-' + index + '" style="display:none;">' +
                            '<h3><?php echo esc_js(__('Record Details', 'redcap-patient-portal')); ?></h3>' +
                            '<div class="redcap-details-content">';
                        
                        // Format the record data
                        const systemFields = ['record_id', 'redcap_event_name', 'survey_name', 'form_name'];
                        
                        Object.entries(record).forEach(([key, value]) => {
                            if (!systemFields.includes(key) && value !== null && value !== '') {
                                // Format the field name for display
                                const fieldName = key.replace(/_/g, ' ')
                                    .replace(/\b\w/g, letter => letter.toUpperCase());
                                
                                dataHtml += '<div class="redcap-detail-field">' +
                                    '<span class="redcap-field-name">' + fieldName + ':</span> ' +
                                    '<span class="redcap-field-value">' + value + '</span>' +
                                    '</div>';
                            }
                        });
                        
                        dataHtml += '</div>' +
                            '<button class="redcap-close-details"><?php echo esc_js(__('Close', 'redcap-patient-portal')); ?></button>' +
                            '</div>';
                    });
                } else {
                    // Single record - show all fields directly
                    const record = result.data[0];
                    
                    dataHtml += '<div class="redcap-single-record">';
                    
                    // Format the record data
                    const systemFields = ['record_id', 'redcap_event_name', 'name_first', 'name_last', 'email'];
                    
                    Object.entries(record).forEach(([key, value]) => {
                        if (!systemFields.includes(key) && value !== null && value !== '') {
                            // Format the field name for display
                            const fieldName = key.replace(/_/g, ' ')
                                .replace(/\b\w/g, letter => letter.toUpperCase());
                            
                            dataHtml += '<div class="redcap-data-field">' +
                                '<span class="redcap-field-name">' + fieldName + ':</span> ' +
                                '<span class="redcap-field-value">' + value + '</span>' +
                                '</div>';
                        }
                    });
                    
                    dataHtml += '</div>';
                }
                
                dataHtml += '</div>';
                
                // Update data section
                $('.redcap-data-content').html(dataHtml);
                debugLog('All data loaded successfully');
                
                // Add event handlers for record details
                $('.redcap-view-details').on('click', function() {
                    const recordIndex = $(this).data('record');
                    $('#record-details-' + recordIndex).show();
                });
                
                $('.redcap-close-details').on('click', function() {
                    $(this).closest('.redcap-record-details').hide();
                });
            } else {
                // No data or error
                $('.redcap-data-content').html(
                    '<div class="redcap-message">' +
                    (result.error || '<?php echo esc_js(__('No data available.', 'redcap-patient-portal')); ?>') +
                    '</div>'
                );
                debugLog('Data load error: ' + (result.error || 'No data'));
            }
        } catch (error) {
            $('.redcap-data-content').html(
                '<div class="redcap-error-message">' +
                '<?php echo esc_js(__('Error loading data:', 'redcap-patient-portal')); ?> ' + 
                (error.message || 'Unknown error') +
                '</div>'
            );
            debugLog('Data load exception: ' + error.message);
        }
    })();
    
    // Logout button
    $('#redcap-logout-button').on('click', function() {
        redcapAuth.logout();
        window.location.href = '<?php echo esc_js(site_url('/login')); ?>';
    });
});
</script>
