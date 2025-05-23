/**
 * Handles secure data access to patient REDCap data through middleware
 */
class REDCapPatientData {
  constructor(auth, middlewareUrl) {
    // console.log('REDCapPatientData initializing with:', { auth: !!auth, middlewareUrl })
    console.log('REDCapPatientData initializing with:', { auth: !!auth })  // log with middleware url hidden from client
    this.auth = auth;
    this.middlewareUrl = middlewareUrl;
    this.patientDataEndpoint = `${middlewareUrl}/patient/data`;
    this.surveysEndpoint = `${middlewareUrl}/patient/surveys`;
    this.metadataEndpoint = `${middlewareUrl}/patient/survey_metadata`;
    this.fileEndpoint = `${middlewareUrl}/patient/file`;
    console.log('REDCapPatientData initialized successfully');
  }
  
  /**
   * Get all patient data
   */
  async getPatientData() {
    try {
        if (!this.auth.isAuthenticated()) {
            // Verify token with server for extra security
            const verificationResult = await this.auth.verifyToken();
            if (!verificationResult.valid) {
                return {
                    success: false,
                    error: verificationResult.error || 'User is not authenticated',
                    errorType: verificationResult.errorType || 'auth'
                };
            }
        }
        return {
          success: false,
          error: 'Full record access is disabled for security reasons. Please access specific surveys instead.',
          errorType: 'access_restricted'
        };
        
        // Use WordPress AJAX endpoint to contact middleware from WP server rather than client browser
        const response = await fetch(redcapPortal.ajaxUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: new URLSearchParams({
                action: 'redcap_get_patient_data',
                nonce: redcapPortal.nonce
                // Token is sent automatically via HTTP-only cookie
            }),
            credentials: 'same-origin'
        });
        
        const data = await response.json();
        
        if (!data.success) {
            // Handle specific error types
            if (data.data && data.data.error === 'auth_required') {
                this.auth.logout(); // Session expired or invalid
                return {
                    success: false,
                    error: data.data.message || 'Authentication failed',
                    errorType: data.data.error || 'auth'
                };
            }
            
            return {
                success: false,
                error: data.data?.message || 'Failed to fetch patient data',
                errorType: data.data?.error || 'api'
            };
        }
        
        return {
            success: true,
            data: data.data.records
        };
    } catch (error) {
        console.error('Error fetching patient data:', error);
        return {
            success: false,
            error: error.message || 'Failed to fetch patient data',
            errorType: 'network'
        };
    }
  }
  
  async getSurveyResults(surveyName) {
    try {
        if (!this.auth.isAuthenticated()) {
            const verificationResult = await this.auth.verifyToken();
            if (!verificationResult.valid) {
                return {
                    success: false,
                    error: verificationResult.error || 'User is not authenticated',
                    errorType: verificationResult.errorType || 'auth'
                };
            }
        }
        
        // Sanitize survey name to prevent injection
        surveyName = surveyName.trim();
        
        // Use WordPress AJAX endpoint to contact middleware from WP server rather than client browser
        const response = await fetch(redcapPortal.ajaxUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: new URLSearchParams({
                action: 'redcap_get_survey_results',
                nonce: redcapPortal.nonce,
                // Token is sent automatically via HTTP-only cookie
                survey_name: surveyName
            }),
            credentials: 'same-origin'
        });
        
        const data = await response.json();
        
        if (!data.success) {
            // Handle authentication errors specially to trigger logout
            if (data.data && data.data.error === 'auth_required') {
                this.auth.logout();
            }
            
            return {
                success: false,
                error: data.data?.message || `Failed to fetch ${surveyName} survey data`,
                errorType: data.data?.error || 'api'
            };
        }
        
        return {
            success: true,
            data: data.data.survey_data
        };
    } catch (error) {
        console.error(`Error fetching ${surveyName} survey:`, error);
        return {
            success: false,
            error: error.message || `Failed to fetch ${surveyName} survey data`,
            errorType: 'network'
        };
    }
  }

  async getSurveyMetadata(surveyName) {
    try {
        if (!this.auth.isAuthenticated()) {
            const verificationResult = await this.auth.verifyToken();
            if (!verificationResult.valid) {
                return {
                    success: false,
                    error: verificationResult.error || 'User is not authenticated',
                    errorType: verificationResult.errorType || 'auth'
                };
            }
        }
        
        // Use WordPress AJAX endpoint to contact middleware from WP server rather than client browser
        const response = await fetch(redcapPortal.ajaxUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: new URLSearchParams({
                action: 'redcap_get_survey_metadata',
                nonce: redcapPortal.nonce,
                // Token is sent automatically via HTTP-only cookie
                survey_name: surveyName
            }),
            credentials: 'same-origin'
        });
        
        const data = await response.json();
        
        if (!data.success) {
            if (data.data && data.data.error === 'auth_required') {
                this.auth.logout();
                return {
                    success: false,
                    error: data.data.message || 'Authentication required',
                    errorType: 'auth'
                };
            }
            
            return {
                success: false,
                error: data.data.message || 'Failed to fetch survey metadata',
                errorType: data.data.error || 'api'
            };
        }
        
        return {
            success: true,
            metadata: data.data.metadata,
            instruments: data.data.instruments,
            formEventMapping: data.data.formEventMapping,
            hasFileFields: data.data.hasFileFields
        };
    } catch (error) {
        console.error('Error fetching survey metadata:', error);
        return {
            success: false,
            error: error.message || 'Failed to fetch survey metadata',
            errorType: 'network'
        };
    }
  }

  // Helper method to download files
  getFileDownloadUrl(recordId, fieldName) {
    if (!this.auth.isAuthenticated()) {
        return null;
    }
    
    // Use WordPress AJAX endpoint instead of direct call to middleware URL
    const params = new URLSearchParams({
        action: 'redcap_get_file_download',
        record_id: recordId,
        field_name: fieldName,
        nonce: redcapPortal.nonce
    });
    
    return `${redcapPortal.ajaxUrl}?${params.toString()}`;
  }
  
  /**
   * Render patient data to a DOM element
   */
  renderPatientData(targetElementId) {
    const targetElement = document.getElementById(targetElementId);
    if (!targetElement) {
      console.error(`Target element #${targetElementId} not found`);
      return false;
    }
    
    // Show loading state
    targetElement.innerHTML = '<div class="redcap-loading">Loading your data...</div>';
    
    this.getPatientData()
      .then(result => {
        if (!result.success) {
          targetElement.innerHTML = `<div class="redcap-error">${result.error}</div>`;
          return;
        }
        
        if (!result.data || result.data.length === 0) {
          targetElement.innerHTML = '<div class="redcap-empty">No data found</div>';
          return;
        }
        
        // Render the data
        const records = result.data;
        let html = '<div class="redcap-patient-data">';
        
        // Personal info
        html += '<h3>Your Information</h3>';
        html += '<div class="redcap-info-section">';
        
        // Get the first record for basic info
        const basicInfo = records[0];
        
        // Customize these fields based on your REDCap project
        if (basicInfo.name_first) {
          html += `<div><strong>Name:</strong> ${basicInfo.name_first} ${basicInfo.name_last || ''}</div>`;
        }
        
        if (basicInfo.email) {
          html += `<div><strong>Email:</strong> ${basicInfo.email}</div>`;
        }
        
        if (basicInfo.phone) {
          html += `<div><strong>Phone:</strong> ${basicInfo.phone}</div>`;
        }
        
        html += '</div>';
        
        // Survey results
        html += '<h3>Your Survey Results</h3>';
        
        records.forEach(record => {
          html += `<div class="redcap-record">`;
          html += `<h4>Record: ${record.record_id}</h4>`;
          
          // Skip system fields and display the rest
          Object.keys(record).forEach(key => {
            if (!['record_id', 'name_first', 'name_last', 'email', 'phone'].includes(key) && record[key]) {
              html += `<div><strong>${key}:</strong> ${record[key]}</div>`;
            }
          });
          
          html += '</div>';
        });
        
        html += '</div>';
        targetElement.innerHTML = html;
      })
      .catch(error => {
        console.error('Error rendering patient data:', error);
        targetElement.innerHTML = `<div class="redcap-error">Error loading data: ${error.message}</div>`;
      });
  }
}
