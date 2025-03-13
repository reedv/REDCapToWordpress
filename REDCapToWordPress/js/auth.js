/**
 * Handles secure authentication between WordPress and the middleware
 */
class REDCapAuth {
  constructor(middlewareUrl) {
    this.middlewareUrl = middlewareUrl;
    this.authEndpoint = `${middlewareUrl}/auth/wordpress`;
    this.token = null;
    this.tokenExpiry = null;
    
    // Try to restore token from sessionStorage
    this.restoreSession();
    
    // Set up token refresh interval
    setInterval(() => this.checkTokenExpiry(), 60000); // Check every minute
  }
  
  /**
   * Restore session from storage if available
   */
  restoreSession() {
    const savedToken = sessionStorage.getItem('redcap_token');
    const savedExpiry = sessionStorage.getItem('redcap_token_expiry');
    
    if (savedToken && savedExpiry) {
      // Check if token is still valid
      const expiryDate = new Date(parseInt(savedExpiry));
      if (expiryDate > new Date()) {
        this.token = savedToken;
        this.tokenExpiry = expiryDate;
        return true;
      }
    }
    
    return false;
  }
  
  /**
   * Save auth session to storage
   */
  saveSession(token, expiresIn) {
    const expiryTime = Date.now() + (expiresIn * 1000);
    this.token = token;
    this.tokenExpiry = new Date(expiryTime);
    
    sessionStorage.setItem('redcap_token', token);
    sessionStorage.setItem('redcap_token_expiry', expiryTime.toString());
  }
  
  /**
   * Log in with WordPress credentials via middleware
   */
  async login(username, password) {
    try {
      const response = await fetch(this.authEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ username, password }),
        credentials: 'include'
      });
      
      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.message || 'Authentication failed');
      }
      
      const data = await response.json();
      this.saveSession(data.token, data.expiresIn);
      
      return {
        success: true,
        user: data.user
      };
    } catch (error) {
      console.error('Login error:', error);
      return {
        success: false,
        error: error.message || 'Authentication failed'
      };
    }
  }
  
  /**
   * Log out - clear token and storage
   */
  logout() {
    this.token = null;
    this.tokenExpiry = null;
    sessionStorage.removeItem('redcap_token');
    sessionStorage.removeItem('redcap_token_expiry');
    return true;
  }
  
  /**
   * Check if user is authenticated
   */
  isAuthenticated() {
    return this.token !== null && this.tokenExpiry > new Date();
  }
  
  /**
   * Check token expiry and handle refresh if needed
   */
  checkTokenExpiry() {
    if (!this.token || !this.tokenExpiry) {
      return false;
    }
    
    // If token expires in less than 5 minutes, log out
    // In a production system, you'd implement token refresh instead
    if (this.tokenExpiry.getTime() - Date.now() < 300000) {
      this.logout();
      
      // Notify the user they need to log in again
      if (document.getElementById('redcap-session-expired-alert')) {
        document.getElementById('redcap-session-expired-alert').style.display = 'block';
      } else {
        console.warn('Your session has expired. Please log in again.');
      }
      
      return false;
    }
    
    return true;
  }
  
  /**
   * Get auth headers for API calls
   */
  getAuthHeaders() {
    if (!this.isAuthenticated()) {
      throw new Error('User is not authenticated');
    }
    
    return {
      'Authorization': `Bearer ${this.token}`,
      'Content-Type': 'application/json'
    };
  }
}
