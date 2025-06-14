const axios = require('axios');
const { XMLParser } = require('fast-xml-parser');

class PlexAuthenticator {
  constructor(config, logger) {
    this.config = config;
    this.logger = logger;
    this.xmlParser = new XMLParser({
      ignoreAttributes: false,
      attributeNamePrefix: '@_'
    });
    
    // OAuth client configuration
    this.clientInfo = {
      clientIdentifier: config.app.client_identifier || 'plex-auth-proxy-' + Date.now(),
      product: 'Plex Auth Proxy',
      device: 'Auth Proxy Server',
      version: '1.0.0',
      platform: 'Web'
    };
  }

  async createAuthUrl(redirectUrl) {
    try {
      // Step 1: Request a PIN from Plex
      const pinResponse = await axios.post('https://plex.tv/pins.xml', null, {
        headers: {
          'X-Plex-Client-Identifier': this.clientInfo.clientIdentifier,
          'X-Plex-Product': this.clientInfo.product,
          'X-Plex-Version': this.clientInfo.version,
          'X-Plex-Device': this.clientInfo.device,
          'X-Plex-Device-Name': this.clientInfo.device
        }
      });

      const pinData = this.xmlParser.parse(pinResponse.data);
      const pin = pinData.pin;
      
      if (!pin || !pin['@_id'] || !pin['@_code']) {
        throw new Error('Invalid PIN response from Plex');
      }

      const pinId = pin['@_id'];
      const pinCode = pin['@_code'];
      
      // Step 2: Create the auth URL
      const authUrl = `https://app.plex.tv/auth#!?clientID=${this.clientInfo.clientIdentifier}&code=${pinCode}&forwardUrl=${encodeURIComponent(redirectUrl)}`;
      
      this.logger.info(`Created Plex PIN auth URL - PIN ID: ${pinId}, PIN Code: ${pinCode}`);
      
      return {
        authUrl: authUrl,
        pinId: pinId
      };
    } catch (error) {
      this.logger.error('Failed to create Plex auth URL:', error.message);
      throw new Error('Failed to initiate Plex authentication');
    }
  }

  async checkAuthToken(pinId) {
    try {
      // Check if the PIN has been authorized and get the token
      const response = await axios.get(`https://plex.tv/pins/${pinId}.xml`, {
        headers: {
          'X-Plex-Client-Identifier': this.clientInfo.clientIdentifier,
          'X-Plex-Product': this.clientInfo.product,
          'X-Plex-Version': this.clientInfo.version
        }
      });

      const pinData = this.xmlParser.parse(response.data);
      const pin = pinData.pin;
      
      if (!pin || !pin['@_authToken']) {
        return { success: false, error: 'Authentication not completed' };
      }

      const authToken = pin['@_authToken'];
      
      // Get user info with the token
      const userInfo = await this.getPlexUserInfo(authToken);
      if (!userInfo) {
        return { success: false, error: 'Failed to get user info' };
      }

      // Check server access
      const serverAccess = await this.checkServerAccess(authToken, userInfo);

      return {
        success: true,
        user: {
          id: userInfo.id,
          email: userInfo.email,
          username: userInfo.username,
          title: userInfo.title,
          admin: userInfo.admin === '1',
          token: authToken
        },
        servers: serverAccess
      };

    } catch (error) {
      this.logger.error('Failed to check auth token:', error.message);
      return { success: false, error: 'Authentication failed' };
    }
  }

  async authenticate(username, password) {
    // Legacy method - we'll keep this for backwards compatibility
    // but the main flow should use OAuth
    try {
      const authToken = await this.getPlexToken(username, password);
      if (!authToken) {
        return { success: false, error: 'Invalid credentials' };
      }

      const userInfo = await this.getPlexUserInfo(authToken);
      if (!userInfo) {
        return { success: false, error: 'Failed to get user info' };
      }

      const serverAccess = await this.checkServerAccess(authToken, userInfo);

      return {
        success: true,
        user: {
          id: userInfo.id,
          email: userInfo.email,
          username: userInfo.username,
          title: userInfo.title,
          admin: userInfo.admin === '1',
          token: authToken
        },
        servers: serverAccess
      };

    } catch (error) {
      this.logger.error('Authentication failed:', error);
      return { success: false, error: 'Authentication failed' };
    }
  }

  async getPlexToken(username, password) {
    try {
      const response = await axios.post('https://plex.tv/users/sign_in.xml', null, {
        headers: {
          'X-Plex-Client-Identifier': this.clientInfo.clientIdentifier,
          'X-Plex-Product': this.clientInfo.product,
          'X-Plex-Version': this.clientInfo.version,
          'X-Plex-Device': this.clientInfo.device,
          'X-Plex-Device-Name': 'Authentication Proxy',
          'Authorization': `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`
        },
        timeout: 10000
      });

      const parsed = this.xmlParser.parse(response.data);
      if (parsed.user && parsed.user['@_authToken']) {
        return parsed.user['@_authToken'];
      }
      
      return null;
    } catch (error) {
      this.logger.error('Failed to get Plex token:', error.message);
      return null;
    }
  }

  async getPlexUserInfo(token) {
    try {
      const response = await axios.get('https://plex.tv/users/account.xml', {
        headers: {
          'X-Plex-Token': token,
          'X-Plex-Client-Identifier': this.clientInfo.clientIdentifier,
          'X-Plex-Product': this.clientInfo.product
        },
        timeout: 10000
      });

      const parsed = this.xmlParser.parse(response.data);
      if (parsed.user) {
        return {
          id: parsed.user['@_id'],
          email: parsed.user['@_email'],
          username: parsed.user['@_username'],
          title: parsed.user['@_title'],
          admin: parsed.user['@_admin']
        };
      }
      
      return null;
    } catch (error) {
      this.logger.error('Failed to get user info:', error.message);
      return null;
    }
  }

  async checkServerAccess(token, userInfo) {
    const serverAccess = {};

    for (const [serverId, serverConfig] of Object.entries(this.config.plex_servers)) {
      try {
        const hasAccess = await this.checkUserServerAccess(token, serverConfig, userInfo);
        
        if (hasAccess) {
          serverAccess[serverId] = {
            name: serverConfig.name,
            url: serverConfig.url,
            access_level: hasAccess.level,
