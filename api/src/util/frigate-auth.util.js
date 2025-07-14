const axios = require('axios');
const { FRIGATE } = require('../constants')();

class FrigateAuth {
  constructor() {
    this.token = null;
    this.tokenExpiry = null;
    this.refreshPromise = null;
    this.baseURL = null;
  }

  /**
   * Extract token from Set-Cookie header
   * @param {string} setCookieHeader - The Set-Cookie header value
   * @returns {string|null} - The extracted token or null
   */
  extractTokenFromCookie(setCookieHeader) {
    if (!setCookieHeader) return null;
    
    const tokenMatch = setCookieHeader.match(/frigate_token=([^;]+)/);
    return tokenMatch ? tokenMatch[1] : null;
  }

  /**
   * Parse expiry time from Set-Cookie header
   * @param {string} setCookieHeader - The Set-Cookie header value
   * @returns {Date|null} - The expiry date or null
   */
  parseExpiryFromCookie(setCookieHeader) {
    if (!setCookieHeader) return null;
    
    const expiryMatch = setCookieHeader.match(/expires=([^;]+)/);
    if (!expiryMatch) return null;
    
    try {
      return new Date(expiryMatch[1]);
    } catch (error) {
      console.error('Error parsing cookie expiry:', error.message);
      return null;
    }
  }

  /**
   * Check if token is expired or will expire soon (within 5 minutes)
   * @returns {boolean} - True if token is expired or will expire soon
   */
  isTokenExpired() {
    if (!this.token || !this.tokenExpiry) return true;
    
    // Consider token expired if it expires within 5 minutes
    const bufferTime = 5 * 60 * 1000; // 5 minutes in milliseconds
    return Date.now() + bufferTime >= this.tokenExpiry.getTime();
  }

  /**
   * Login to Frigate and get authentication token
   * @param {string} baseURL - The Frigate base URL
   * @param {string} username - The username
   * @param {string} password - The password
   * @returns {Promise<Object>} - Object containing token and expiry
   */
  async login(baseURL, username, password) {
    try {
      if (!baseURL || !username || !password) {
        throw new Error('Base URL, username, and password are required');
      }

      this.baseURL = baseURL.endsWith('/') ? baseURL.slice(0, -1) : baseURL;
      
      const response = await axios({
        method: 'post',
        url: `${this.baseURL}/api/login`,
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        data: {
          user: username,
          password: password
        },
        timeout: 10000
      });

      const setCookieHeader = response.headers['set-cookie'];
      if (!setCookieHeader) {
        throw new Error('No Set-Cookie header received from Frigate');
      }

      // Handle both array and string formats of Set-Cookie header
      const cookieHeader = Array.isArray(setCookieHeader) 
        ? setCookieHeader.find(cookie => cookie.includes('frigate_token='))
        : setCookieHeader;

      if (!cookieHeader) {
        throw new Error('No frigate_token found in Set-Cookie header');
      }

      this.token = this.extractTokenFromCookie(cookieHeader);
      this.tokenExpiry = this.parseExpiryFromCookie(cookieHeader);

      if (!this.token) {
        throw new Error('Failed to extract token from cookie');
      }

      console.verbose(`Successfully logged into Frigate at ${this.baseURL}`);
      
      return {
        token: this.token,
        expiry: this.tokenExpiry
      };
    } catch (error) {
      const errorMessage = error.response?.data?.message || error.message;
      throw new Error(`Frigate login failed: ${errorMessage}`);
    }
  }

  /**
   * Get a valid token, refreshing if necessary
   * @param {string} baseURL - The Frigate base URL
   * @param {string} username - The username
   * @param {string} password - The password
   * @returns {Promise<string>} - The valid token
   */
  async getValidToken(baseURL, username, password) {
    // If we already have a valid token, return it
    if (!this.isTokenExpired()) {
      return this.token;
    }

    // If a refresh is already in progress, wait for it
    if (this.refreshPromise) {
      await this.refreshPromise;
      return this.token;
    }

    // Start a new refresh
    this.refreshPromise = this.login(baseURL, username, password);
    
    try {
      await this.refreshPromise;
      return this.token;
    } finally {
      this.refreshPromise = null;
    }
  }

  /**
   * Make an authenticated request to Frigate
   * @param {Object} options - Axios request options
   * @param {string} baseURL - The Frigate base URL
   * @param {string} username - The username
   * @param {string} password - The password
   * @returns {Promise<Object>} - The full response object
   */
  async authenticatedRequest(options, baseURL, username, password) {
    const token = await this.getValidToken(baseURL, username, password);
    
    const requestOptions = {
      ...options,
      headers: {
        ...options.headers,
        'Cookie': `frigate_token=${token}`
      }
    };

    try {
      const response = await axios(requestOptions);
      return response;
    } catch (error) {
      // If we get a 401, try to refresh token and retry once
      if (error.response?.status === 401) {
        console.verbose('Token expired, refreshing...');
        this.token = null;
        this.tokenExpiry = null;
        
        const newToken = await this.getValidToken(baseURL, username, password);
        requestOptions.headers.Cookie = `frigate_token=${newToken}`;
        
        const retryResponse = await axios(requestOptions);
        return retryResponse;
      }
      
      throw error;
    }
  }

  /**
   * Get current token info
   * @returns {Object} - Token information
   */
  getTokenInfo() {
    return {
      token: this.token,
      expiry: this.tokenExpiry,
      isExpired: this.isTokenExpired(),
      hasToken: !!this.token
    };
  }

  /**
   * Clear stored token
   */
  clearToken() {
    this.token = null;
    this.tokenExpiry = null;
    this.refreshPromise = null;
  }
}

// Create singleton instance
const frigateAuth = new FrigateAuth();

module.exports = frigateAuth; 