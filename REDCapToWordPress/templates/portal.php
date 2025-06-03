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

// Check WordPress login status first
if (!is_user_logged_in()) {
    // Redirect to login page
    wp_redirect(site_url('/login'));
    exit;
}

// Extract shortcode attributes with safe defaults
$survey_name = isset($atts['survey']) ? $atts['survey'] : '';
$show_profile = isset($atts['show_profile']) && $atts['show_profile'] === 'yes';
$allowed_surveys = isset($atts['allowed_surveys']) && is_array($atts['allowed_surveys']) ? $atts['allowed_surveys'] : array();
$show_invalid_survey = isset($atts['invalid_survey']) && $atts['invalid_survey'] === true;

// Get settings
$options = get_option('redcap_portal_settings');
$show_debug = isset($options['show_debug_info']) && $options['show_debug_info'] === 'yes' && current_user_can('manage_options');
?>
<div class="redcap-portal-container">
    <div id="redcap-portal-content">
        <!-- Authentication check message will appear here if not logged in -->
    </div>
    
    <?php if (!empty($allowed_surveys)): ?>
    <div class="redcap-portal-nav" style="display: none;">
        <ul>
            <?php foreach ($allowed_surveys as $nav_survey): ?>
                <?php if (isset($nav_survey['name'])): ?>
                <li><a href="?survey=<?php echo esc_attr($nav_survey['name']); ?>">
                    <?php echo esc_html(!empty($nav_survey['label']) ? $nav_survey['label'] : ucwords(str_replace('_', ' ', $nav_survey['name']))); ?>
                </a></li>
                <?php endif; ?>
            <?php endforeach; ?>
        </ul>
    </div>
    <?php endif; ?>
    
    <?php if ($show_invalid_survey): ?>
    <div class="redcap-error-message">
        <?php echo esc_html__('The requested survey is not available or does not exist.', 'redcap-patient-portal'); ?>
    </div>
    <?php endif; ?>

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
    
    <?php if (!empty($survey_name)): ?>
    <div id="redcap-survey-results" class="redcap-portal-section" style="display: none;">
        <h2 class="redcap-section-title"><?php echo esc_html(sprintf(__('%s Results', 'redcap-patient-portal'), ucwords(str_replace('_', ' ', $survey_name)))); ?></h2>
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
                <li>Survey: <?php echo esc_html($survey_name ?: 'none'); ?></li>
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

    function escapeHtml(str) {
        if (str === null || str === undefined) {
            return '';
        }
        
        return String(str)
            .replace(/&/g, '&amp;')   // Must be first to avoid double-escaping
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#x27;');
    }

    // Extract logged-out state display logic for reuse
    function showPortalLoggedOutState(reason = 'logged_out') {
        // Hide all portal sections
        $('.redcap-portal-nav').hide();
        <?php if ($show_profile): ?>
        $('#redcap-patient-profile').hide();
        <?php endif; ?>
        <?php if (!empty($survey_name)): ?>
        $('#redcap-survey-results').hide();
        <?php endif; ?>
        $('#redcap-all-data').hide();
        $('#redcap-portal-actions').hide();
        
        // Determine appropriate message based on reason
        let message, submessage;
        switch(reason) {
            case 'logged_out':
                message = '<?php echo esc_js(__('You have been logged out of the health data portal.', 'redcap-patient-portal')); ?>';
                submessage = '<?php echo esc_js(__('Portal session ended.', 'redcap-patient-portal')); ?>';
                break;
            case 'expired':
                message = '<?php echo esc_js(__('Your portal session has expired.', 'redcap-patient-portal')); ?>';
                submessage = '<?php echo esc_js(__('Please log in again to access your health data.', 'redcap-patient-portal')); ?>';
                break;
            default:
                message = '<?php echo esc_js(__('Portal authentication required.', 'redcap-patient-portal')); ?>';
                submessage = '<?php echo esc_js(__('Please log in to access your health data.', 'redcap-patient-portal')); ?>';
        }
        
        // Show logged-out message with login option
        $('#redcap-portal-content').html(
            '<div class="redcap-message">' + message + '</div>' +
            '<div class="redcap-error-message">' + submessage + '</div>' +
            '<p><a href="<?php echo esc_js(site_url('/login')); ?>" class="redcap-button redcap-primary-button">' +
            '<?php echo esc_js(__('Access Health Data Portal', 'redcap-patient-portal')); ?>' +
            '</a></p>' +
            '<div style="margin-top: 15px; padding: 10px; background-color: #f0f8ff; border-left: 4px solid #2271b1; font-size: 14px;">' +
            '<strong><?php echo esc_js(__('Note:', 'redcap-patient-portal')); ?></strong> ' +
            '<?php echo esc_js(__('You remain logged into the main website and can access other areas.', 'redcap-patient-portal')); ?>' +
            '</div>'
        );
        
        debugLog('Portal logged out state displayed (reason: ' + reason + ')');
    }

    // Check authentication and initialize the page
    (async function initializePortal() {
        // Verify token with the server rather than relying on client-side check
        const verificationResult = await redcapAuth.verifyToken();
        
        if (!verificationResult.valid) {
            // Not authenticated or token expired - show login message
            $('#redcap-portal-content').html(
                '<div class="redcap-error-message">' +
                (verificationResult.errorType === 'expired' ? 
                    '<?php echo esc_js(__('Your session has expired. Please log in again.', 'redcap-patient-portal')); ?>' : 
                    '<?php echo esc_js(__('Authentication error. Please log in again.', 'redcap-patient-portal')); ?>') +
                '</div>' +
                '<p><a href="<?php echo esc_js(site_url('/login')); ?>" class="redcap-button redcap-primary-button">' +
                '<?php echo esc_js(__('Log In', 'redcap-patient-portal')); ?>' +
                '</a></p>'
            );
            return; // Exit the function - don't proceed with loading data
        }
        
        // User is authenticated, show the portal sections
        $('#redcap-portal-content').html(
            '<div class="redcap-welcome-message">' +
            '<?php echo esc_js(__('Welcome to your secure health data portal.', 'redcap-patient-portal')); ?>' +
            '</div>'
        );

        $('.redcap-portal-nav').show();
        
        <?php if ($show_profile): ?>
        $('#redcap-patient-profile').show();
        <?php endif; ?>
        
        <?php if (!empty($survey_name)): ?>
        $('#redcap-survey-results').show();
        <?php endif; ?>
        
        $('#redcap-all-data').show();
        $('#redcap-portal-actions').show();
        
        // Load patient profile if enabled
        <?php if ($show_profile): ?>
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
                        escapeHtml(profileData.name_first || '') + ' ' + escapeHtml(profileData.name_last || '') + 
                        '</div>';
                }
                
                // Add email
                if (profileData.email) {
                    profileHtml += '<div class="redcap-profile-field"><strong><?php echo esc_js(__('Email:', 'redcap-patient-portal')); ?></strong> ' + 
                        escapeHtml(profileData.email) + '</div>';
                }
                
                // Add other basic fields
                const basicFields = ['phone', 'dob', 'address', 'city', 'state', 'zip'];
                basicFields.forEach(field => {
                    if (profileData[field]) {
                        profileHtml += '<div class="redcap-profile-field"><strong>' + 
                            field.charAt(0).toUpperCase() + field.slice(1) + ':</strong> ' + 
                            escapeHtml(profileData[field]) + '</div>';
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
        <?php endif; ?>
        
        // Load specific survey data if specified
        <?php if (!empty($survey_name)): ?>
        try {
            debugLog('Loading survey: <?php echo esc_js($survey_name); ?>');
            
            // First fetch the metadata to understand the structure
            const metadataResult = await redcapData.getSurveyMetadata('<?php echo esc_js($survey_name); ?>');
            if (!metadataResult.success) {
                throw new Error(metadataResult.error || 'Failed to load survey metadata');
            }
            
            // Now fetch the actual survey data
            const dataResult = await redcapData.getSurveyResults('<?php echo esc_js($survey_name); ?>');
            if (!dataResult.success) {
                throw new Error(dataResult.error || 'Failed to load survey data');
            }
            
            if (dataResult.data && dataResult.data.length > 0 && metadataResult.metadata) {
                // Process and display the data with metadata context
                let surveyHtml = '<div class="redcap-survey-results">';
                
                // Create a metadata lookup by field name
                const metadataByField = {};
                metadataResult.metadata.forEach(field => {
                    metadataByField[field.field_name] = field;
                });
                
                // Group matrix fields for easier rendering
                const matrixGroups = {};
                metadataResult.metadata.forEach(field => {
                    if (field.grid_name) {
                        if (!matrixGroups[field.grid_name]) {
                            matrixGroups[field.grid_name] = {
                                fields: [],
                                header: field.grid_name.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
                            };
                        }
                        matrixGroups[field.grid_name].fields.push(field);
                    }
                });
                
                // Identify sections for better organization
                const sections = [];
                let currentSection = { title: 'General Information', fields: [] };
                sections.push(currentSection);
                
                metadataResult.metadata.forEach(field => {
                    if (field.field_type === 'section_header') {
                        currentSection = { title: field.field_label, fields: [] };
                        sections.push(currentSection);
                    } else if (!field.grid_name) { // Matrix fields handled separately
                        currentSection.fields.push(field);
                    }
                });
                
                // Track which fields have been rendered already (to avoid duplicates from matrices)
                const renderedFields = new Set();
                
                // Process each record
                dataResult.data.forEach((record, recordIndex) => {
                    // Add record header if multiple records
                    if (dataResult.data.length > 1) {
                        const dateField = record.survey_date || record.survey_timestamp || record.date || '';
                        surveyHtml += `<div class="redcap-record-header">
                            <h3><?php echo esc_js(__('Response', 'redcap-patient-portal')); ?> ${recordIndex + 1}</h3>
                            <div class="redcap-record-date">${dateField ? '<?php echo esc_js(__('Date:', 'redcap-patient-portal')); ?> ' + dateField : ''}</div>
                        </div>`;
                    }
                    
                    // Render each section
                    sections.forEach(section => {
                        // Skip empty sections
                        let hasContent = false;
                        for (const field of section.fields) {
                            const fieldName = field.field_name;
                            if (record[fieldName] !== null && record[fieldName] !== '' && 
                                !renderedFields.has(fieldName) && field.field_type !== 'section_header') {
                                hasContent = true;
                                break;
                            }
                        }
                        
                        if (!hasContent) return;
                        
                        surveyHtml += `<div class="redcap-section">
                            <h4 class="redcap-section-title">${section.title}</h4>
                            <table class="redcap-survey-table">
                                <colgroup>
                                    <col style="width:50%">
                                    <col style="width:50%">
                                </colgroup>
                                <thead>
                                    <tr>
                                        <th scope="col"><?php echo esc_js(__('Question', 'redcap-patient-portal')); ?></th>
                                        <th scope="col"><?php echo esc_js(__('Response', 'redcap-patient-portal')); ?></th>
                                    </tr>
                                </thead>
                                <tbody>`;
                        
                        // Render regular fields in this section
                        section.fields.forEach(field => {
                            const fieldName = field.field_name;
                            
                            // Skip if already rendered or if it's a section header
                            if (renderedFields.has(fieldName) || field.field_type === 'section_header') {
                                return;
                            }
                            
                            // Skip system fields and empty values
                            const systemFields = ['record_id', 'name_first', 'name_last', 'email', 
                                                'survey_date', 'survey_timestamp', 'date'];
                            if (systemFields.includes(fieldName) || 
                                record[fieldName] === null || 
                                record[fieldName] === '') {
                                return;
                            }
                            
                            renderedFields.add(fieldName);
                            
                            // Get field information
                            const questionText = field.field_label || fieldName;
                            let rawFieldValue = record[fieldName];
                            let fieldValue = escapeHtml(rawFieldValue);
                            let fieldNote = field.field_note ? `<div class="redcap-field-note">${field.field_note}</div>` : '';
                            
                            // null/undefined handling
                            if (fieldValue === null || fieldValue === undefined) {
                                fieldValue = '';  // Replace with empty string instead of showing "undefined"
                            }

                            // Process based on field type
                            switch (field.field_type) {
                                case 'yesno':
                                    fieldValue = fieldValue === '1' ? 'Yes' : 'No';
                                    break;
                                    
                                case 'truefalse':
                                    fieldValue = fieldValue === '1' ? 'True' : 'False';
                                    break;
                                    
                                case 'radio':
                                case 'dropdown':
                                    if (field.select_choices_or_calculations) {
                                        const choices = field.select_choices_or_calculations.split('|')
                                            .map(choice => {
                                                const parts = choice.trim().split(',', 2);
                                                return {
                                                    value: parts[0].trim(),
                                                    label: parts.length > 1 ? parts[1].trim() : parts[0].trim()
                                                };
                                            });
                                        
                                        const matchingChoice = choices.find(choice => choice.value === fieldValue);
                                        if (matchingChoice) {
                                            fieldValue = matchingChoice.label;
                                        }
                                    }
                                    break;
                                    
                                case 'checkbox':
                                    if (field.select_choices_or_calculations) {
                                        const choices = field.select_choices_or_calculations.split('|')
                                            .map(choice => {
                                                const parts = choice.trim().split(',', 2);
                                                return {
                                                    value: parts[0].trim(),
                                                    label: parts.length > 1 ? parts[1].trim() : parts[0].trim()
                                                };
                                            });
                                        
                                        const selectedValues = [];
                                        choices.forEach(choice => {
                                            const checkboxVarName = `${fieldName}___${choice.value}`;
                                            if (record[checkboxVarName] === '1') {
                                                selectedValues.push(choice.label);
                                            }
                                        });
                                        fieldValue = selectedValues.join(', ');
                                    }
                                    break;
                                    
                                case 'file':
                                    if (rawFieldValue) {
                                        // Construct HTML with escaped filename only
                                        fieldValue = `<div class="redcap-file-info">
                                            <i class="fas fa-file"></i> 
                                            <span class="redcap-file-name">File: ${escapeHtml(rawFieldValue)}</span>
                                            <div class="redcap-file-note">File downloads are disabled for security reasons. Contact study coordinator for file access.</div>
                                        </div>`;
                                    } else {
                                        fieldValue = '<span class="redcap-no-file">No file uploaded</span>';
                                    }
                                    break;
                                    
                                case 'calc':
                                    // Show both formula and result for calculated fields
                                    fieldNote += field.select_choices_or_calculations ? 
                                        `<div class="redcap-calc-formula">Formula: ${field.select_choices_or_calculations}</div>` : '';
                                    break;
                            }
                            
                            // Add to the table
                            surveyHtml += `<tr class="redcap-survey-field redcap-field-type-${field.field_type}">
                                <td class="redcap-field-name">
                                    ${questionText}
                                    ${field.required_field === 'y' ? '<span class="redcap-required">*</span>' : ''}
                                    ${fieldNote}
                                </td>
                                <td class="redcap-field-value">${fieldValue}</td>
                            </tr>`;
                            
                            // If this field has branching logic, show it
                            if (field.branching_logic) {
                                surveyHtml += `<tr class="redcap-branching-logic">
                                    <td colspan="2" class="redcap-branching-note">
                                        <i>This question is shown based on previous answers</i>
                                    </td>
                                </tr>`;
                            }
                        });
                        
                        surveyHtml += `</tbody></table></div>`;
                    });
                    
                    // Process matrix groups
                    Object.keys(matrixGroups).forEach(groupName => {
                        const group = matrixGroups[groupName];
                        const groupFields = group.fields;
                        
                        // Skip if already rendered or no content
                        if (groupFields.every(field => renderedFields.has(field.field_name))) {
                            return;
                        }
                        
                        // Check if any field in the matrix has a value
                        let hasContent = false;
                        for (const field of groupFields) {
                            if (record[field.field_name] !== null && record[field.field_name] !== '') {
                                hasContent = true;
                                break;
                            }
                        }
                        
                        if (!hasContent) return;
                        
                        // Sort fields to ensure consistent order
                        groupFields.sort((a, b) => a.field_order - b.field_order);
                        
                        // Determine the matrix structure
                        const matrixHeaders = [];
                        const matrixRowFields = {};
                        
                        groupFields.forEach(field => {
                            // Mark as rendered
                            renderedFields.add(field.field_name);
                            
                            // Parse the matrix structure from the field name
                            // Assuming format like matrix_group_name_row_col
                            const nameParts = field.field_name.split('_');
                            const lastPart = nameParts[nameParts.length - 1];
                            
                            // Extract row identifier (everything except the last part)
                            const rowId = nameParts.slice(0, -1).join('_');
                            
                            if (!matrixRowFields[rowId]) {
                                matrixRowFields[rowId] = {
                                    label: field.field_label.split(' - ')[0], // Assumes label format "Row Label - Column Label"
                                    fields: []
                                };
                            }
                            
                            // Add to matrix structure
                            matrixRowFields[rowId].fields.push(field);
                            
                            // Extract column header if not already present
                            const colHeader = field.field_label.split(' - ')[1] || lastPart;
                            if (!matrixHeaders.includes(colHeader)) {
                                matrixHeaders.push(colHeader);
                            }
                        });
                        
                        // Create matrix table
                        surveyHtml += `<div class="redcap-matrix-group">
                            <h4 class="redcap-matrix-title">${group.header}</h4>
                            <table class="redcap-matrix-table">
                                <thead>
                                    <tr>
                                        <th></th>`;
                        
                        // Add column headers
                        matrixHeaders.forEach(header => {
                            surveyHtml += `<th>${header}</th>`;
                        });
                        
                        surveyHtml += `</tr></thead><tbody>`;
                        
                        // Add matrix rows
                        Object.keys(matrixRowFields).forEach(rowId => {
                            const rowData = matrixRowFields[rowId];
                            
                            surveyHtml += `<tr><td class="redcap-matrix-row-label">${rowData.label}</td>`;
                            
                            // Add cells
                            matrixHeaders.forEach(header => {
                                // Find the field for this cell
                                const cell = rowData.fields.find(field => field.field_label.includes(header));
                                
                                if (cell) {
                                    let rawCellValue = record[cell.field_name] || '';
                                    let cellValue = escapeHtml(rawCellValue);
                                    
                                    // Process value based on field type (similar to above but simplified)
                                    if (cell.field_type === 'radio' && cell.select_choices_or_calculations) {
                                        const choices = cell.select_choices_or_calculations.split('|')
                                            .map(choice => {
                                                const parts = choice.trim().split(',', 2);
                                                return {
                                                    value: parts[0].trim(),
                                                    label: parts.length > 1 ? parts[1].trim() : parts[0].trim()
                                                };
                                            });
                                        
                                        const matchingChoice = choices.find(choice => choice.value === cellValue);
                                        if (matchingChoice) {
                                            cellValue = matchingChoice.label;
                                        }
                                    }
                                    
                                    surveyHtml += `<td class="redcap-matrix-cell">${cellValue}</td>`;
                                } else {
                                    surveyHtml += `<td class="redcap-matrix-cell"></td>`;
                                }
                            });
                            
                            surveyHtml += `</tr>`;
                        });
                        
                        surveyHtml += `</tbody></table></div>`;
                    });
                });
                
                surveyHtml += '</div>';
                
                // Update survey content
                $('.redcap-survey-content').html(surveyHtml);
                debugLog('Survey data loaded and displayed successfully');
            } else {
                // No data or error
                $('.redcap-survey-content').html(
                    '<div class="redcap-message">' +
                    (dataResult.error || '<?php echo esc_js(__('No survey data available.', 'redcap-patient-portal')); ?>') +
                    '</div>'
                );
                debugLog('Survey load error: ' + (dataResult.error || 'No data'));
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
        <?php endif; ?>
        
        // Load all patient data
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
    
    function debugLog(message) {
        <?php if ($show_debug): ?>
        $('#redcap-debug-log').append('<div class="debug-item">' + message + '</div>');
        console.log('REDCap Portal:', message);
        <?php endif; ?>
    }
    
    // Logout button
    $('#redcap-logout-button').on('click', async function() {
        debugLog('User initiated portal logout');
        
        try {
            // Clear REDCap middleware tokens
            await redcapAuth.logout();
            debugLog('REDCap tokens cleared successfully');
        } catch (error) {
            debugLog('REDCap token clearing failed: ' + error.message);
            // Continue with logout process even if token clearing fails
        }
        
        // Show logged-out state without redirecting (preserves WordPress session)
        showPortalLoggedOutState('logged_out');
        
        debugLog('Portal logout complete - WordPress session maintained');
    });
});
</script>
