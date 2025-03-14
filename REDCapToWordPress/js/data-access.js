/**
 * Handles secure data access to patient REDCap data through middleware
 */
class REDCapPatientData {
  constructor(auth, middlewareUrl) {
    this.auth = auth;
    this.middlewareUrl = middlewareUrl;
    this.patientDataEndpoint = `${middlewareUrl}/patient/data`;
    this.surveysEndpoint = `${middlewareUrl}/patient/surveys`;
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
      
      const response = await fetch(this.patientDataEndpoint, {
        method: 'GET',
        headers: this.auth.getAuthHeaders(),
        credentials: 'include'
      });
      
      const data = await response.json();
      
      if (!response.ok) {
        // Handle specific error types
        if (response.status === 401) {
          this.auth.logout(); // Session expired or invalid
          return {
            success: false,
            error: data.message || 'Authentication failed',
            errorType: data.error || 'auth'
          };
        }
        
        return {
          success: false,
          error: data.message || 'Failed to fetch patient data',
          errorType: 'api'
        };
      }
      
      return {
        success: true,
        data: data.records
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
  
  /**
   * Get specific survey results
   */
  async getSurveyResults(surveyName) {
    try {
      if (!this.auth.isAuthenticated()) {
        throw new Error('User is not authenticated');
      }
      
      // Sanitize survey name
      surveyName = surveyName.trim();
      
      const response = await fetch(`${this.surveysEndpoint}/${surveyName}`, {
        method: 'GET',
        headers: this.auth.getAuthHeaders(),
        credentials: 'include'
      });
      
      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.message || `Failed to fetch ${surveyName} survey data`);
      }
      
      const data = await response.json();
      return {
        success: true,
        data: data.survey_data
      };
    } catch (error) {
      console.error(`Error fetching ${surveyName} survey:`, error);
      return {
        success: false,
        error: error.message || `Failed to fetch ${surveyName} survey data`
      };
    }
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
