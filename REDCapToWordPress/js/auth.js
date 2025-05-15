/**
 * Handles secure authentication between WordPress and the middleware
 * Using HttpOnly cookies for token storage
 */
class REDCapAuth {
  constructor(middlewareUrl) {
    this.middlewareUrl = middlewareUrl;
    this.tokenExpiryTime = null;
    
    // Get expiry time from the non-HttpOnly cookie
    this.checkTokenExpiry();
    
    // Set up token refresh interval
    setInterval(() => this.checkTokenExpiry(), 60000); // Check every minute
  }
  
  /**
   * Get token expiry from cookie
   */
  getTokenExpiry() {
    const cookieValue = this.getCookie('redcap_token_expiry');
    return cookieValue ? parseInt(cookieValue) : null;
  }
  
  /**
   * Helper to get cookie by name
   */
  getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
    return null;
  }
  
  /**
   * Check if authentication cookies exist
   */
  isAuthenticated() {
    // Check for expiry cookie (the HttpOnly token cookie can't be checked via JS)
    const expiryTime = this.getTokenExpiry();
    if (!expiryTime) return false;
    
    // Check if it's expired
    return expiryTime * 1000 > Date.now();
  }

  /**
   * Verify token with server
   */
  async verifyToken() {
    try {
      // Ask the server to check if the HttpOnly cookie is valid
      const response = await fetch(redcapPortal.ajaxUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
          action: 'redcap_check_token_cookie',
          nonce: redcapPortal.nonce
        }),
        credentials: 'same-origin' // Include cookies
      });
      
      const data = await response.json();
      
      if (!data.success) {
        // Handle different error types
        return { 
          valid: false, 
          error: data.data?.message || 'Invalid session', 
          errorType: data.data?.error || 'invalid' 
        };
      }
      
      return { valid: true };
    } catch (error) {
      console.error('Token verification error:', error);
      return { valid: false, error: 'Verification failed', errorType: 'network' };
    }
  }
  
  /**
   * Check token expiry and handle refresh if needed
   */
  async checkTokenExpiry() {
    // Get expiry from cookie
    const expiryTime = this.getTokenExpiry();
    if (!expiryTime) return false;
    
    // If token expires in less than 5 minutes, verify with server
    if (expiryTime * 1000 - Date.now() < 300000) {
      const verificationResult = await this.verifyToken();
      
      if (!verificationResult.valid) {
        // Clear cookies via server action
        await this.logout();
        
        // Notify the user they need to log in again
        if (document.getElementById('redcap-session-expired-alert')) {
          document.getElementById('redcap-session-expired-alert').style.display = 'block';
        } else {
          console.warn('Your session has expired. Please log in again.');
        }
        
        return false;
      }
    }
    
    return true;
  }
  
  /**
   * Log out - clear cookies through server action
   */
  async logout() {
    try {
      await fetch(redcapPortal.ajaxUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
          action: 'redcap_clear_token_cookie',
          nonce: redcapPortal.nonce
        }),
        credentials: 'same-origin' // Include cookies
      });
      return true;
    } catch (error) {
      console.error('Logout error:', error);
      return false;
    }
  }
  
  /**
   * Get auth headers for API calls - not needed for direct token access
   * Instead, cookies will be sent automatically
   */
  getAuthHeaders() {
    if (!this.isAuthenticated()) {
      throw new Error('User is not authenticated');
    }
    
    return {
      'Content-Type': 'application/json'
    };
  }
}