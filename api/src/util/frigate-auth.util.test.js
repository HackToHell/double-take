const frigateAuth = require('./frigate-auth.util');

// Mock axios for testing
jest.mock('axios');
const axios = require('axios');

describe('FrigateAuth', () => {
  beforeEach(() => {
    frigateAuth.clearToken();
    jest.clearAllMocks();
  });

  describe('extractTokenFromCookie', () => {
    it('should extract token from Set-Cookie header', () => {
      const setCookieHeader = 'frigate_token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkb3VibGV0YWtlIiwiZXhwIjoxNzYwNzY2NTk4fQ.4IkT0ph1i4ncOk6Xcb3VA2vpk83UKwjj2rnhi8R5sTY; expires=Sat, 26 Apr 2081 11:39:56 GMT; HttpOnly; Path=/; SameSite=lax';
      const token = frigateAuth.extractTokenFromCookie(setCookieHeader);
      expect(token).toBe('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkb3VibGV0YWtlIiwiZXhwIjoxNzYwNzY2NTk4fQ.4IkT0ph1i4ncOk6Xcb3VA2vpk83UKwjj2rnhi8R5sTY');
    });

    it('should return null for invalid cookie header', () => {
      const token = frigateAuth.extractTokenFromCookie('invalid_cookie');
      expect(token).toBeNull();
    });

    it('should return null for empty cookie header', () => {
      const token = frigateAuth.extractTokenFromCookie('');
      expect(token).toBeNull();
    });
  });

  describe('parseExpiryFromCookie', () => {
    it('should parse expiry date from Set-Cookie header', () => {
      const setCookieHeader = 'frigate_token=token; expires=Sat, 26 Apr 2081 11:39:56 GMT; HttpOnly; Path=/; SameSite=lax';
      const expiry = frigateAuth.parseExpiryFromCookie(setCookieHeader);
      expect(expiry).toBeInstanceOf(Date);
      expect(expiry.getFullYear()).toBe(2081);
    });

    it('should return null for cookie without expiry', () => {
      const setCookieHeader = 'frigate_token=token; HttpOnly; Path=/; SameSite=lax';
      const expiry = frigateAuth.parseExpiryFromCookie(setCookieHeader);
      expect(expiry).toBeNull();
    });
  });

  describe('isTokenExpired', () => {
    it('should return true when no token exists', () => {
      expect(frigateAuth.isTokenExpired()).toBe(true);
    });

    it('should return true when token is expired', () => {
      frigateAuth.token = 'test_token';
      frigateAuth.tokenExpiry = new Date(Date.now() - 1000); // Expired 1 second ago
      expect(frigateAuth.isTokenExpired()).toBe(true);
    });

    it('should return false when token is valid', () => {
      frigateAuth.token = 'test_token';
      frigateAuth.tokenExpiry = new Date(Date.now() + 60000); // Expires in 1 minute
      expect(frigateAuth.isTokenExpired()).toBe(false);
    });
  });

  describe('login', () => {
    it('should successfully login and extract token', async () => {
      const mockResponse = {
        headers: {
          'set-cookie': 'frigate_token=test_token; expires=Sat, 26 Apr 2081 11:39:56 GMT; HttpOnly; Path=/; SameSite=lax'
        }
      };
      axios.mockResolvedValue(mockResponse);

      const result = await frigateAuth.login('https://frigate.example.com', 'testuser', 'testpass');

      expect(result.token).toBe('test_token');
      expect(result.expiry).toBeInstanceOf(Date);
      expect(axios).toHaveBeenCalledWith({
        method: 'post',
        url: 'https://frigate.example.com/api/login',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        data: {
          user: 'testuser',
          password: 'testpass'
        },
        timeout: 10000
      });
    });

    it('should throw error for missing credentials', async () => {
      await expect(frigateAuth.login('', '', '')).rejects.toThrow('Base URL, username, and password are required');
    });

    it('should throw error when no Set-Cookie header received', async () => {
      const mockResponse = { headers: {} };
      axios.mockResolvedValue(mockResponse);

      await expect(frigateAuth.login('https://frigate.example.com', 'testuser', 'testpass'))
        .rejects.toThrow('No Set-Cookie header received from Frigate');
    });
  });

  describe('getValidToken', () => {
    it('should return existing token if not expired', async () => {
      frigateAuth.token = 'valid_token';
      frigateAuth.tokenExpiry = new Date(Date.now() + 60000);

      const token = await frigateAuth.getValidToken('https://frigate.example.com', 'testuser', 'testpass');
      expect(token).toBe('valid_token');
    });

    it('should refresh token if expired', async () => {
      const mockResponse = {
        headers: {
          'set-cookie': 'frigate_token=new_token; expires=Sat, 26 Apr 2081 11:39:56 GMT; HttpOnly; Path=/; SameSite=lax'
        }
      };
      axios.mockResolvedValue(mockResponse);

      frigateAuth.token = 'expired_token';
      frigateAuth.tokenExpiry = new Date(Date.now() - 1000);

      const token = await frigateAuth.getValidToken('https://frigate.example.com', 'testuser', 'testpass');
      expect(token).toBe('new_token');
    });
  });

  describe('authenticatedRequest', () => {
    it('should make authenticated request with valid token', async () => {
      const mockResponse = { data: { version: '1.0.0' } };
      axios.mockResolvedValue(mockResponse);

      frigateAuth.token = 'valid_token';
      frigateAuth.tokenExpiry = new Date(Date.now() + 60000);

      const result = await frigateAuth.authenticatedRequest({
        method: 'get',
        url: 'https://frigate.example.com/api/version'
      }, 'https://frigate.example.com', 'testuser', 'testpass');

      expect(result).toEqual({ version: '1.0.0' });
      expect(axios).toHaveBeenCalledWith({
        method: 'get',
        url: 'https://frigate.example.com/api/version',
        headers: {
          'Cookie': 'frigate_token=valid_token'
        }
      });
    });

    it('should retry with new token on 401 error', async () => {
      const mockResponse = { data: { version: '1.0.0' } };
      const mockLoginResponse = {
        headers: {
          'set-cookie': 'frigate_token=new_token; expires=Sat, 26 Apr 2081 11:39:56 GMT; HttpOnly; Path=/; SameSite=lax'
        }
      };

      // First call fails with 401, second succeeds
      axios.mockRejectedValueOnce({ response: { status: 401 } });
      axios.mockResolvedValueOnce(mockLoginResponse); // Login response
      axios.mockResolvedValueOnce(mockResponse); // Retry response

      const result = await frigateAuth.authenticatedRequest({
        method: 'get',
        url: 'https://frigate.example.com/api/version'
      }, 'https://frigate.example.com', 'testuser', 'testpass');

      expect(result).toEqual({ version: '1.0.0' });
    });
  });

  describe('getTokenInfo', () => {
    it('should return token information', () => {
      frigateAuth.token = 'test_token';
      frigateAuth.tokenExpiry = new Date(Date.now() + 60000);

      const info = frigateAuth.getTokenInfo();
      expect(info).toEqual({
        token: 'test_token',
        expiry: frigateAuth.tokenExpiry,
        isExpired: false,
        hasToken: true
      });
    });
  });

  describe('clearToken', () => {
    it('should clear stored token', () => {
      frigateAuth.token = 'test_token';
      frigateAuth.tokenExpiry = new Date();
      frigateAuth.refreshPromise = Promise.resolve();

      frigateAuth.clearToken();

      expect(frigateAuth.token).toBeNull();
      expect(frigateAuth.tokenExpiry).toBeNull();
      expect(frigateAuth.refreshPromise).toBeNull();
    });
  });
}); 